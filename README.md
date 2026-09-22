# @corbits/oauth-core

PKCE + loopback OAuth for an Interchange host: mint an access token the host injects as `InferenceSource.apiKey`. A loopback callback server, token exchange/refresh, and an expiring-token session that refreshes ahead of expiry and coalesces concurrent refreshes. Endpoints and client id come from the caller, and persistence stays with the host.

## Runtime support

Bun >= 1.2 runs the published TypeScript source. Node >= 24 is an engines floor for tooling; native Node does not load this extensionless TypeScript source as-is.

## Quickstart

```sh
npm add @corbits/oauth-core
pnpm add @corbits/oauth-core
yarn add @corbits/oauth-core
bun add @corbits/oauth-core
```

One flow shape: public client, PKCE S256, fixed-port loopback, no client secret.

A provider is a package the host supplies — `@corbits/xai-provider`,
`@corbits/codex-provider`, or one of its own — pairing an `OAuthClientConfig`
with an `exchange`/`refresh` implementation. This library never names one
itself.

### Hub-hosted browser login

The production path: a tenant router gets browser-driven "Continue with
&lt;provider&gt;" login, and a background ticker keeps issued tokens fresh.
Tokens never leave this process as plaintext — `mountOAuthLogin` writes them
through the host's `CredentialCipher` into a stock `oauth_token` credential,
and `createOAuthTokenRefresher` reads them back the same way.

```ts
import {
  createOAuthTokenRefresher,
  mountOAuthLogin,
  type OAuthLoginProviders,
  type OAuthTokenRefresher,
} from "@corbits/oauth-core/hub";
import type { DB } from "@intx/db";
import type { TenantEnv } from "@intx/hub-api";
import type { CredentialCipher } from "@intx/types";
import { Hono, type MiddlewareHandler } from "hono";

export function installOAuthLogin(
  app: Hono<TenantEnv>,
  opts: {
    db: DB["db"];
    cipher: CredentialCipher;
    // The host's own grant middleware, e.g. from `createRequireGrant` —
    // checked once, the host's way, before a login can start.
    requireGrant: MiddlewareHandler<TenantEnv>;
    // Provider packages the host has installed, e.g. `@corbits/xai-provider`.
    providers: OAuthLoginProviders;
    // Required: a refresh only reaches the DB. A sidecar already running
    // with the old token keeps using it until something tells it to reload,
    // so the host must push or notify its running consumers here — see
    // "Keeping running consumers in sync" below.
    onRefreshed: (context: { tenantId: string; credentialId: string }) => void;
    onError: (error: unknown) => void;
  },
): OAuthTokenRefresher {
  const oauthLoginApi = new Hono<TenantEnv>();

  mountOAuthLogin(oauthLoginApi, {
    db: opts.db,
    cipher: opts.cipher,
    requireGrant: opts.requireGrant,
    providers: opts.providers,
    onError: (error) => opts.onError(error),
  });
  app.route("/api/tenants/:tenantId", oauthLoginApi);

  const refresher = createOAuthTokenRefresher({
    db: opts.db,
    cipher: opts.cipher,
    providers: opts.providers,
    intervalMs: 60_000,
    onRefreshed: (context) => opts.onRefreshed(context),
    onError: (error) => opts.onError(error),
  });
  refresher.start();
  return refresher; // host calls .stop() on shutdown
}
```

`mountOAuthLogin` adds `POST /oauth-logins` (starts a login and returns an
authorize URL and a login id — the PKCE verifier and the loopback callback
listener never leave this process), `GET /oauth-logins/:loginId` (poll for
completion), and `DELETE /oauth-logins/:loginId` (cancel). The browser only
ever learns the id of the credential the tokens landed in.

#### Keeping running consumers in sync

`createOAuthTokenRefresher` only writes the renewed token to the credential
row; it does not know what, if anything, is holding a live copy of the old
one. A host that runs long-lived processes against a credential — sidecars,
workers, anything that loaded the token into memory rather than re-reading it
per call — has to push or notify those processes itself from `onRefreshed`,
or they keep using the stale token until they happen to restart or redeploy,
even though the database already has the fresh one. That is why `onRefreshed`
is a required callback here rather than an optional log hook.

### Lower-level: a CLI/desktop login

Outside a hub — a bare CLI or desktop host with its own credential store —
compose the same building blocks `mountOAuthLogin` composes, directly:

```ts
import {
  baseTokensFromResponse,
  buildAuthorizeUrl,
  createTokenSession,
  exchangeCode,
  refreshTokenRequest,
  startCallbackServer,
  startOAuthLogin,
  type BaseTokens,
  type OAuthClientConfig,
  type OAuthLoginDeps,
  type TokenSessionDeps,
} from "@corbits/oauth-core";

// Host-owned persistence — an OS keychain, an encrypted file, whatever this
// particular host already uses to hold secrets at rest. The field types
// come straight from the library's own dependency types, so a store that
// satisfies this shape also satisfies `startOAuthLogin` and
// `createTokenSession` directly.
type ProfileStore = {
  persist: OAuthLoginDeps<BaseTokens>["saveProfile"];
  load: TokenSessionDeps<BaseTokens, string>["loadProfile"];
  update: TokenSessionDeps<BaseTokens, string>["updateTokens"];
};

export async function loginAndGetToken(
  config: OAuthClientConfig,
  store: ProfileStore,
): Promise<string> {
  // The callback server binds exactly what `redirectUri` names.
  const redirect = new URL(config.redirectUri);
  const handle = await startOAuthLogin(
    { profile: "default", signal: new AbortController().signal },
    {
      startCallbackServer: (state) =>
        startCallbackServer(state, {
          port: Number(redirect.port),
          host: redirect.hostname,
          path: redirect.pathname,
          doneHtml:
            "<html><body>Signed in — you can close this tab.</body></html>",
          failedHtml: (reason) =>
            `<html><body>Sign-in failed: ${reason}</body></html>`,
        }),
      buildAuthorizeUrl: (pkce, state) =>
        buildAuthorizeUrl(config, pkce, state),
      exchangeCode: async (code, verifier, now) =>
        baseTokensFromResponse(
          await exchangeCode(config, code, verifier),
          now,
          undefined,
        ),
      saveProfile: store.persist,
    },
  );

  const staged = await handle.completed;
  await staged.commit();

  const session = createTokenSession<BaseTokens, string>({
    skewMs: 30_000,
    loadProfile: store.load,
    updateTokens: store.update,
    refreshTokens: async (refreshToken, now) =>
      baseTokensFromResponse(
        await refreshTokenRequest(config, refreshToken),
        now,
        refreshToken,
      ),
    toAccess: (tokens) => tokens.access,
  });

  return session.getValidToken("default");
}
```

Hand the returned token to `InferenceSource.apiKey` — that injection is the
host's job.

## How it works

Nothing here names a provider — config and callback HTML are caller-supplied;
persistence is a host callback (`mountOAuthLogin`'s `db`/`cipher`, or a CLI
host's own `persist`/`load`/`update`). `startOAuthLogin` stages the exchanged
profile behind `commit()`. Callback binds are loopback only (`127.0.0.0/8` or
`::1`); the redirect carrying the code is cleartext HTTP. The token session
coalesces concurrent refreshes for the same profile. The hub subpath runs
that same login loop in-process behind `mountOAuthLogin` and writes a stock
`oauth_token` credential, encrypted under the host's `CredentialCipher`;
`createOAuthTokenRefresher` walks those credentials ahead of expiry and
refreshes them under a row lock (`FOR UPDATE SKIP LOCKED`), so two hubs
ticking at once never both refresh the same credential.

`PRODUCT.md`, `ARCHITECTURE.md`, and `IMPLEMENTATION.md` describe the PKCE loopback product, structure, and wire format.

## Development

```sh
git clone https://github.com/corbitsdev/corbits-oauth-core.git
cd corbits-oauth-core
bun install
bun run typecheck
bun run lint
bun run format:check
bun run test
bun run check
```

`bun run format` rewrites the tree. `bun run check` is typecheck + lint + format:check + test.

## License

LGPL-2.1-only.
