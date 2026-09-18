import type { DB } from "@intx/db";
import type { TenantEnv } from "@intx/hub-api";
import type { CredentialCipher } from "@intx/types";
import { type } from "arktype";
import { Hono, type MiddlewareHandler } from "hono";

import {
  buildAuthorizeUrl,
  startCallbackServer,
  startOAuthLogin,
} from "../index";
import { persistOAuthCredential } from "./credentials";
import { createLoginStore, type LoginState } from "./login-store";
import { callbackTargetFor, type OAuthLoginProviders } from "./registry";

/** An abandoned login holds a fixed loopback port, so it is not held long. */
const DEFAULT_LOGIN_TTL_MS = 5 * 60 * 1000;

const StartLogin = type({
  provider: "string",
  /** The stock `provider` catalog row the credential is filed under. */
  providerId: "string",
  credentialName: "string",
});

const DONE_HTML =
  "<!doctype html><meta charset=utf-8><title>Signed in</title><p>Signed in — you can close this tab and return to your workbench.";

const failedHtml = (reason: string): string =>
  `<!doctype html><meta charset=utf-8><title>Sign-in failed</title><p>Sign-in failed: ${reason.replace(/[<&]/g, "")}`;

export type MountOAuthLoginOpts = {
  readonly db: DB["db"];
  readonly cipher: CredentialCipher;
  /** Providers the host offers; the library never names one itself. */
  readonly providers: OAuthLoginProviders;
  /** The host's stock grant middleware, so authority is checked exactly once, its way. */
  readonly requireGrant: MiddlewareHandler<TenantEnv>;
  readonly loginTtlMs?: number;
  /** Reported when a login fails after the request that started it returned. */
  readonly onError?: (error: unknown, context: { provider: string }) => void;
};

/**
 * Mount browser-driven OAuth login on a tenant router. The browser gets an
 * authorize URL and a login id and nothing else: the PKCE verifier, the
 * loopback listener and the token exchange all stay in this process, and
 * the only thing that crosses back out is the id of the credential the
 * tokens were stored under.
 */
export function mountOAuthLogin(
  app: Hono<TenantEnv>,
  opts: MountOAuthLoginOpts,
): void {
  const logins = createLoginStore();
  const ttlMs = opts.loginTtlMs ?? DEFAULT_LOGIN_TTL_MS;

  const owner = (c: {
    get(key: "tenant" | "principal"): { id: string };
  }): { tenantId: string; principalId: string } => ({
    tenantId: c.get("tenant").id,
    principalId: c.get("principal").id,
  });

  app.get("/oauth-logins/providers", opts.requireGrant, (c) =>
    c.json({ providers: Object.keys(opts.providers) }),
  );

  app.post("/oauth-logins", opts.requireGrant, async (c) => {
    const body = StartLogin(await c.req.json().catch(() => undefined));
    if (body instanceof type.errors) {
      return c.json({ error: body.summary }, 400);
    }
    const provider = opts.providers[body.provider];
    if (provider === undefined) {
      return c.json({ error: `unknown provider "${body.provider}"` }, 404);
    }

    const { tenantId, principalId } = owner(c);
    const target = callbackTargetFor(provider.oauthConfig);
    const abort = new AbortController();

    let handle;
    try {
      handle = await startOAuthLogin(
        { profile: body.credentialName, signal: abort.signal },
        {
          startCallbackServer: (state) =>
            startCallbackServer(state, {
              port: target.port,
              host: target.host,
              path: target.path,
              doneHtml: DONE_HTML,
              failedHtml,
            }),
          buildAuthorizeUrl: (pkce, state) =>
            buildAuthorizeUrl(provider.oauthConfig, pkce, state),
          exchangeCode: (code, verifier, now) =>
            provider.exchange(code, verifier, now),
          // Persistence runs below once the login id exists to report against.
          saveProfile: () => Promise.resolve(),
          // The browser opens the authorize URL; the hub never owns a display.
          openInBrowser: () => undefined,
        },
      );
    } catch (cause) {
      opts.onError?.(cause, { provider: body.provider });
      return c.json(
        { error: cause instanceof Error ? cause.message : String(cause) },
        409,
      );
    }

    const loginId = logins.create({
      tenantId,
      principalId,
      expiresAt: Date.now() + ttlMs,
      abort,
      cancel: handle.cancel,
    });

    // Detached on purpose: the redirect lands minutes after this response.
    void handle.completed.then(
      async (staged) => {
        try {
          const credentialId = await persistOAuthCredential({
            db: opts.db,
            cipher: opts.cipher,
            tenantId,
            principalId,
            providerId: body.providerId,
            provider: body.provider,
            name: body.credentialName,
            scopes: provider.oauthConfig.scopes,
            tokens: staged.profile.tokens,
            metadata: provider.metadata?.(staged.profile.tokens) ?? {},
          });
          logins.settle(loginId, { status: "completed", credentialId });
        } catch (cause) {
          opts.onError?.(cause, { provider: body.provider });
          logins.settle(loginId, {
            status: "failed",
            message: "the tokens could not be stored",
          });
        }
      },
      (cause: unknown) => {
        opts.onError?.(cause, { provider: body.provider });
        logins.settle(loginId, {
          status: "failed",
          message: cause instanceof Error ? cause.message : String(cause),
        });
      },
    );

    return c.json({ loginId, authorizeUrl: handle.authorizeUrl }, 201);
  });

  app.get("/oauth-logins/:loginId", opts.requireGrant, (c) => {
    const state: LoginState | undefined = logins.read(
      c.req.param("loginId"),
      owner(c),
    );
    if (state === undefined) return c.json({ error: "not_found" }, 404);
    return c.json(state);
  });

  app.delete("/oauth-logins/:loginId", opts.requireGrant, (c) =>
    logins.cancel(c.req.param("loginId"), owner(c))
      ? c.body(null, 204)
      : c.json({ error: "not_found" }, 404),
  );
}
