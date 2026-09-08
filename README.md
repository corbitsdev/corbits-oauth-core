# @corbits/oauth-core

PKCE + loopback OAuth for an Interchange host: mint an access token the
harness injects as `InferenceSource.apiKey`. A loopback callback server,
token exchange/refresh, and an expiring-token session that refreshes ahead
of expiry and coalesces concurrent refreshes. It is not a credential vault
and it is not a client for any particular issuer — endpoints and client id
come from the caller (typically `@corbits/xai-provider` or
`@corbits/codex-provider`). One flow shape: public client, PKCE S256,
fixed-port loopback, no client secret.

## Install

```sh
bun add github:corbitsdev/corbits-oauth-core
```

The package ships TypeScript source and needs no build step; Bun consumes it
directly.

## Usage

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

// `persist`, `load`, and `update` below are the host's storage layer — write
// an Interchange `oauth_token` credential or use the OS vault. This package
// never stores.
const handle = await startOAuthLogin(
  { profile: "default", signal: new AbortController().signal },
  {
    startCallbackServer: (state) =>
      startCallbackServer(state, {
        port: 8765,
        // Optional; defaults to 127.0.0.1.
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
    // Host: Interchange `oauth_token` or the OS vault. This package does not store.
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
// Host: put `accessToken` on InferenceSource.apiKey. The harness injects it at send.
```

See `src/index.ts` for the full export surface.

## Design notes

- Nothing here names a provider, product, or default client id — config and
  callback HTML are caller-supplied. Persistence is the host's callback.
- `expiresAt` on `BaseTokens` is optional: RFC 6749 §5.1 makes `expires_in`
  RECOMMENDED, not required, and this package never guesses a lifetime the
  server didn't send.
- `startOAuthLogin` stages the exchanged profile behind a `commit()` the
  caller controls, so persistence can be gated on the host's own setup
  succeeding first.
- Callback hostnames are resolved once before binding. Every returned address
  must be loopback (`127.0.0.0/8` or `::1`), and the validated address is bound
  directly; wildcard and routable hosts are rejected. This is a cleartext
  safeguard: the redirect carrying the authorization code travels as plain
  HTTP, so a routable or wildcard bind would expose it on the network where
  passive capture defeats the state check.
- The token session coalesces concurrent refreshes for the same profile
  into one in-flight request, since a provider that rotates refresh tokens
  would otherwise invalidate a racing second attempt. Interchange's harness
  injects `apiKey` at send; it does not refresh provider tokens.
- `fetch`, `now`, and refresh skew are all injectable, so login and refresh
  paths are testable without patching globals.

## Not supported

- No credential persistence — the host writes an Interchange `oauth_token`
  or the OS vault.
- No device-code flow — loopback redirect only.
- No confidential client / client secret support — public clients (PKCE)
  only.
- No token revocation endpoint call.
- Fixed-port loopback only, no dynamic port selection: authorization
  servers only accept the registered `redirect_uri` for the client, so a
  randomly chosen port would be rejected.

## License

LGPL-2.1-or-later.
