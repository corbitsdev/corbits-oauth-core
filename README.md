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
} from "@corbits/oauth-core/hub";
import type { DB } from "@intx/db";
import type { TenantEnv } from "@intx/hub-api";
import type { CredentialCipher } from "@intx/types";
import { Hono, type MiddlewareHandler } from "hono";

declare const db: DB["db"];
declare const cipher: CredentialCipher;
// The host's own grant middleware, e.g. from `createRequireGrant` — checked
// once, the host's way, before a login can start.
declare const requireGrant: MiddlewareHandler<TenantEnv>;
// Provider packages the host has installed, e.g. `@corbits/xai-provider`.
declare const providers: OAuthLoginProviders;
// The host's tenant-scoped router, mounted under its own tenant prefix.
declare const app: Hono<TenantEnv>;

const oauthLoginApi = new Hono<TenantEnv>();

mountOAuthLogin(oauthLoginApi, {
  db,
  cipher,
  requireGrant,
  providers,
  onError: (error, { provider }) => {
    console.error(`oauth login failed for ${provider}`, error);
  },
});

app.route("/api/tenants/:tenantId", oauthLoginApi);

const refresher = createOAuthTokenRefresher({
  db,
  cipher,
  providers,
  intervalMs: 60_000,
  onRefreshed: ({ tenantId, credentialId }) => {
    // Push the renewed credential to whatever holds a live copy.
  },
  onError: (error, { provider, credentialId }) => {
    console.error(`oauth refresh failed`, { provider, credentialId, error });
  },
});
refresher.start();
```

`mountOAuthLogin` adds `POST /oauth-logins` (starts a login and returns an
authorize URL and a login id — the PKCE verifier and the loopback callback
listener never leave this process), `GET /oauth-logins/:loginId` (poll for
completion), and `DELETE /oauth-logins/:loginId` (cancel). The browser only
ever learns the id of the credential the tokens landed in.

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
} from "@corbits/oauth-core";

const config: OAuthClientConfig = {
  clientId: "my-client-id",
  authorizeUrl: "https://provider.example.com/oauth/authorize",
  tokenUrl: "https://provider.example.com/oauth/token",
  redirectUri: "http://127.0.0.1:8765/callback",
  scopes: ["profile"],
  tokenTimeoutMs: 10_000,
};

// Host-owned persistence — an OS keychain, an encrypted file, whatever this
// particular host already uses to hold secrets at rest.
declare function persist(profile: {
  name: string;
  tokens: BaseTokens;
  createdAt: number;
}): Promise<void>;
declare function load(
  name: string,
): Promise<{ tokens: BaseTokens } | undefined>;
declare function update(name: string, tokens: BaseTokens): Promise<void>;

const handle = await startOAuthLogin(
  { profile: "default", signal: new AbortController().signal },
  {
    startCallbackServer: (state) =>
      startCallbackServer(state, {
        port: 8765,
        host: "127.0.0.1",
        path: "/callback",
        doneHtml:
          "<html><body>Signed in — you can close this tab.</body></html>",
        failedHtml: (reason) =>
          `<html><body>Sign-in failed: ${reason}</body></html>`,
      }),
    buildAuthorizeUrl: (pkce, state) => buildAuthorizeUrl(config, pkce, state),
    exchangeCode: async (code, verifier, now) =>
      baseTokensFromResponse(
        await exchangeCode(config, code, verifier),
        now,
        undefined,
      ),
    saveProfile: persist,
  },
);

const staged = await handle.completed;
await staged.commit();

const session = createTokenSession<BaseTokens, string>({
  skewMs: 30_000,
  loadProfile: load,
  updateTokens: update,
  refreshTokens: async (refreshToken, now) =>
    baseTokensFromResponse(
      await refreshTokenRequest(config, refreshToken),
      now,
      refreshToken,
    ),
  toAccess: (tokens) => tokens.access,
});

const accessToken = await session.getValidToken("default");
```

Hand `accessToken` to `InferenceSource.apiKey` — that injection is the
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
