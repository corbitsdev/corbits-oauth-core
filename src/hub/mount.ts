import type { DB } from "@intx/db";
import type { TenantEnv } from "@intx/hub-api";
import type { CredentialCipher } from "@intx/types";
import { type } from "arktype";
import { Hono, type MiddlewareHandler } from "hono";

import {
  buildAuthorizeUrl,
  createLoginRegistry,
  startCallbackServer,
  startOAuthLogin,
  type CallbackFailure,
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

/** Plain stand-ins; a product with a brand passes its own pages instead. */
const FAILURE_TEXT: Record<CallbackFailure["code"], string> = {
  state_mismatch: "This page is no longer the sign-in this hub is waiting for.",
  provider_error: "The provider refused the authorization.",
  no_code: "The provider sent no authorization back.",
};

const failedHtml = (failure: CallbackFailure): string =>
  `<!doctype html><meta charset=utf-8><title>Sign-in failed</title><p>${FAILURE_TEXT[failure.code]}`;

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
  // One live login per provider: its callback server binds the one port the
  // authorization server will redirect to, so a second attempt has nowhere
  // to listen. Resuming is also what keeps the authorize page already open
  // in the operator's browser valid (CL-8857).
  const inFlight = createLoginRegistry();
  const loginIdOf = new Map<string, string>();
  // Cleanup names the login it belongs to, never just its provider. A login
  // leaves the registry the moment it settles, but its credential is still
  // being stored; a newer login for the same provider -- possibly another
  // principal's -- can already be live by then, and must not lose its id.
  const releaseLoginId = (provider: string, loginId: string): void => {
    if (loginIdOf.get(provider) === loginId) loginIdOf.delete(provider);
  };
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

    let started;
    try {
      started = await inFlight.startOrResume(
        body.provider,
        () =>
          startOAuthLogin(
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
          ),
        // A login belongs to the principal who started it: resuming is for
        // them, not for whoever asks next.
        { tag: `${tenantId}:${principalId}` },
      );
    } catch (cause) {
      opts.onError?.(cause, { provider: body.provider });
      return c.json(
        { error: cause instanceof Error ? cause.message : String(cause) },
        409,
      );
    }

    const handle = started.handle;
    if (started.resumed) {
      const loginId = loginIdOf.get(body.provider);
      // Recorded below in the same tick a login is registered, so a live
      // entry always has one; saying so beats inventing a second login.
      if (loginId === undefined) {
        return c.json(
          { error: "a login is in flight but cannot be resumed" },
          409,
        );
      }
      return c.json({ loginId, authorizeUrl: handle.authorizeUrl }, 200);
    }

    const loginId = logins.create({
      tenantId,
      principalId,
      expiresAt: Date.now() + ttlMs,
      abort,
      // This login's own handle, not whatever is live under the provider:
      // the TTL sweep can reach an expired entry after a newer login has
      // taken the port, and cancelling by provider would end that one.
      cancel: () => {
        handle.cancel();
        releaseLoginId(body.provider, loginId);
      },
    });
    loginIdOf.set(body.provider, loginId);

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
          releaseLoginId(body.provider, loginId);
        } catch (cause) {
          opts.onError?.(cause, { provider: body.provider });
          logins.settle(loginId, {
            status: "failed",
            message: "the tokens could not be stored",
          });
          releaseLoginId(body.provider, loginId);
        }
      },
      (cause: unknown) => {
        opts.onError?.(cause, { provider: body.provider });
        logins.settle(loginId, {
          status: "failed",
          message: cause instanceof Error ? cause.message : String(cause),
        });
        releaseLoginId(body.provider, loginId);
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
