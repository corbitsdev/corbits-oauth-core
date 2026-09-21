# @corbits/oauth-core

PKCE + loopback OAuth for an Interchange host: mint an access token the harness injects as `InferenceSource.apiKey`. A loopback callback server, token exchange/refresh, and an expiring-token session that refreshes ahead of expiry and coalesces concurrent refreshes. It is not a vault and not a client for any particular issuer — endpoints and client id come from the caller.

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

```ts
import {
  buildAuthorizeUrl,
  exchangeCode,
  startCallbackServer,
  startOAuthLogin,
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

void buildAuthorizeUrl;
void exchangeCode;
void startCallbackServer;
void startOAuthLogin;
void config;
```

Typical callers: `@corbits/xai-provider`, `@corbits/codex-provider`.

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
void accessToken;
```

A hub that wants a browser-driven login mounts `@corbits/oauth-core/hub`:

```ts
import { mountOAuthLogin } from "@corbits/oauth-core/hub";

mountOAuthLogin(api, {
  db,
  cipher: credentialCipher,
  requireGrant: requireGrant("credential:*", "create"),
  providers: {
    someProvider: {
      oauthConfig,
      exchange: (code, verifier, now) => exchangeSomeCode(code, verifier, now),
    },
  },
});
```

## How it works

Nothing here names a provider — config and callback HTML are caller-supplied; persistence is a host callback. `startOAuthLogin` stages the exchanged profile behind `commit()`. Callback binds are loopback only (`127.0.0.0/8` or `::1`); the redirect carrying the code is cleartext HTTP. The token session coalesces concurrent refreshes for the same profile. The hub subpath runs that loop in-process and writes a stock `oauth_token` credential; `createOAuthTokenRefresher` walks those credentials ahead of expiry.

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
