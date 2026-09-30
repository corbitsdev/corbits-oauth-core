import type { DB } from "@intx/db";
import type { TenantEnv } from "@intx/hub-api";
import type { CredentialCipher } from "@intx/types";
import { type } from "arktype";
import { Hono, type MiddlewareHandler } from "hono";

import {
  baseTokensFromResponse,
  buildAuthorizeUrl,
  discoverMcpLoginEntry,
  exchangeCode,
  mcpClientConfig,
  OAuthDiscoveryError,
  registerMcpClient,
  startCallbackServer,
  startOAuthLogin,
  type BaseTokens,
  type CallbackServer,
  type FetchLike,
  type OAuthClientConfig,
} from "../index.js";
import {
  checkOAuthCredentialTarget,
  OAUTH_CLIENT_ID_METADATA_KEY,
  OAUTH_RESOURCE_METADATA_KEY,
  OAUTH_TOKEN_URL_METADATA_KEY,
  OAuthCredentialTargetRejectedError,
  persistOAuthCredential,
} from "./credentials.js";
import {
  createLoginStore,
  type LoginState,
  type LoginStore,
} from "./login-store.js";
import { createRouteCallbacks, type RouteCallbacks } from "./route-callback.js";
import {
  callbackTargetFor,
  signedInHtml,
  signInFailedHtml,
  type OAuthLoginProviders,
} from "../provider.js";

/** An abandoned login holds a fixed loopback port, so it is not held long. */
const DEFAULT_LOGIN_TTL_MS = 5 * 60 * 1000;

/** The stock `provider` catalog row the credential is filed under. */
const Target = { providerId: "string", credentialName: "string" } as const;

const StartLogin = type({ provider: "string", ...Target }).or({
  /** An MCP server URL: discovery and dynamic registration supply the rest. */
  resourceUrl: "string",
  ...Target,
});

/** Everything one login needs, however its client was configured. */
type LoginFlow = {
  /** Recorded as the credential's `oauthProvider`. */
  readonly provider: string;
  readonly config: OAuthClientConfig;
  readonly exchange: (
    code: string,
    verifier: string,
    now: number,
  ) => Promise<BaseTokens>;
  readonly metadata: (tokens: BaseTokens) => Record<string, string>;
  readonly startCallbackServer: (state: string) => Promise<CallbackServer>;
};

/**
 * The logins in flight and the state each one awaits a redirect on. The
 * login mount and the callback mount must share one, so the tenant-scoped
 * mount starts a login and the tenant-less callback route completes it.
 */
export type OAuthLoginStore = {
  readonly logins: LoginStore;
  readonly callbacks: RouteCallbacks;
};

export function createOAuthLoginStore(): OAuthLoginStore {
  return { logins: createLoginStore(), callbacks: createRouteCallbacks() };
}

/**
 * Mount the redirect target of resource-URL logins at the hub root, outside
 * any tenant scope. It is unauthenticated on purpose: the browser arrives
 * from the authorization server, the unguessable single-use state binds it
 * to one login (which recorded its tenant when it started), and no token
 * passes through it.
 */
export function mountOAuthCallback(
  app: Hono,
  opts: { readonly store: OAuthLoginStore; readonly path?: string },
): void {
  app.get(opts.path ?? "/oauth/callback", (c) => {
    const { status, html } = opts.store.callbacks.handle({
      state: c.req.query("state"),
      code: c.req.query("code"),
      error: c.req.query("error"),
    });
    return c.html(html, status);
  });
}

export type MountOAuthLoginOpts = {
  readonly db: DB["db"];
  readonly cipher: CredentialCipher;
  /** Providers the host offers; the library never names one itself. */
  readonly providers: OAuthLoginProviders;
  /** The host's stock grant middleware, so authority is checked exactly once, its way. */
  readonly requireGrant: MiddlewareHandler<TenantEnv>;
  /**
   * The absolute public URL of the `mountOAuthCallback` route. A login
   * started from a resource URL registers exactly this as its redirect_uri.
   */
  readonly callbackUrl?: string;
  /** Shared with `mountOAuthCallback`; required for resource-URL logins. */
  readonly store?: OAuthLoginStore;
  /** Outbound fetch for discovery and registration; defaults to `fetch`. */
  readonly fetchImpl?: FetchLike;
  /** The client name shown on a dynamically registered consent screen. */
  readonly clientName?: string;
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
  const { logins, callbacks } = opts.store ?? createOAuthLoginStore();
  const ttlMs = opts.loginTtlMs ?? DEFAULT_LOGIN_TTL_MS;

  const owner = (c: {
    get(key: "tenant" | "principal"): { id: string };
  }): { tenantId: string; principalId: string } => ({
    tenantId: c.get("tenant").id,
    principalId: c.get("principal").id,
  });

  async function resolveFlow(
    body: typeof StartLogin.infer,
  ): Promise<{ flow: LoginFlow } | { error: string; status: 400 | 404 | 502 }> {
    if ("provider" in body) {
      const provider = opts.providers[body.provider];
      if (provider === undefined) {
        return { error: `unknown provider "${body.provider}"`, status: 404 };
      }
      const target = callbackTargetFor(provider.oauthConfig);
      return {
        flow: {
          provider: body.provider,
          config: provider.oauthConfig,
          exchange: provider.exchange,
          metadata: (tokens) => provider.metadata?.(tokens) ?? {},
          startCallbackServer: (state) =>
            startCallbackServer(state, {
              port: target.port,
              host: target.host,
              path: target.path,
              doneHtml: signedInHtml,
              failedHtml: signInFailedHtml,
            }),
        },
      };
    }
    if (opts.callbackUrl === undefined || opts.store === undefined) {
      return {
        error: "resource logins need the mount's callbackUrl and store",
        status: 400,
      };
    }
    const redirectUri = opts.callbackUrl;
    try {
      const entry = await discoverMcpLoginEntry({
        resourceUrl: body.resourceUrl,
        ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
      });
      const registrationEndpoint =
        entry.authorizationServer.registrationEndpoint;
      if (registrationEndpoint === undefined) {
        return {
          error: `${body.resourceUrl} does not support dynamic client registration`,
          status: 502,
        };
      }
      const registration = await registerMcpClient({
        registrationEndpoint,
        redirectUris: [redirectUri],
        clientName: opts.clientName ?? "Corbits",
        ...(entry.authorizationServer.grantTypesSupported !== undefined
          ? {
              grantTypesSupported:
                entry.authorizationServer.grantTypesSupported,
            }
          : {}),
        ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
      });
      const config = mcpClientConfig(entry, {
        clientId: registration.clientId,
        redirectUri,
      });
      return {
        flow: {
          provider: new URL(entry.resourceUrl).origin,
          config,
          exchange: async (code, verifier, now) =>
            baseTokensFromResponse(
              await exchangeCode(config, code, verifier, opts.fetchImpl),
              now,
              undefined,
            ),
          metadata: () => ({
            [OAUTH_CLIENT_ID_METADATA_KEY]: registration.clientId,
            [OAUTH_TOKEN_URL_METADATA_KEY]: config.tokenUrl,
            [OAUTH_RESOURCE_METADATA_KEY]: entry.resourceUrl,
          }),
          startCallbackServer: callbacks.start,
        },
      };
    } catch (cause) {
      if (!(cause instanceof OAuthDiscoveryError)) throw cause;
      opts.onError?.(cause, { provider: body.resourceUrl });
      return { error: cause.message, status: 502 };
    }
  }

  app.get("/oauth-logins/providers", opts.requireGrant, (c) =>
    c.json({ providers: Object.keys(opts.providers) }),
  );

  app.post("/oauth-logins", opts.requireGrant, async (c) => {
    const body = StartLogin(await c.req.json().catch(() => undefined));
    if (body instanceof type.errors) {
      return c.json({ error: body.summary }, 400);
    }
    const { tenantId, principalId } = owner(c);
    const rejected = await checkOAuthCredentialTarget(opts.db, {
      tenantId,
      principalId,
      providerId: body.providerId,
      name: body.credentialName,
    });
    if (rejected !== null) {
      return c.json({ error: rejected.error }, rejected.status);
    }
    const resolved = await resolveFlow(body);
    if ("error" in resolved) {
      return c.json({ error: resolved.error }, resolved.status);
    }
    const { flow } = resolved;
    const abort = new AbortController();

    let handle;
    try {
      handle = await startOAuthLogin(
        { profile: body.credentialName, signal: abort.signal },
        {
          startCallbackServer: flow.startCallbackServer,
          buildAuthorizeUrl: (pkce, state) =>
            buildAuthorizeUrl(flow.config, pkce, state),
          exchangeCode: flow.exchange,
          // Persistence runs below once the login id exists to report against.
          saveProfile: () => Promise.resolve(),
          // The browser opens the authorize URL; the hub never owns a display.
          openInBrowser: () => undefined,
        },
      );
    } catch (cause) {
      opts.onError?.(cause, { provider: flow.provider });
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
            provider: flow.provider,
            name: body.credentialName,
            scopes: flow.config.scopes,
            tokens: staged.profile.tokens,
            metadata: flow.metadata(staged.profile.tokens),
          });
          logins.settle(loginId, { status: "completed", credentialId });
        } catch (cause) {
          opts.onError?.(cause, { provider: flow.provider });
          logins.settle(loginId, {
            status: "failed",
            message:
              cause instanceof OAuthCredentialTargetRejectedError
                ? cause.message
                : "the tokens could not be stored",
          });
        }
      },
      (cause: unknown) => {
        opts.onError?.(cause, { provider: flow.provider });
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
