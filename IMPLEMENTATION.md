# @corbits/oauth-core — Implementation

## Package

- Name: `@corbits/oauth-core` `0.1.0`
- License: LGPL-2.1-only
- Published as TypeScript source. `exports` point at `src/index.ts` and
  `src/hub/index.ts`; there is no build step and no `dist/`.
- Runtime that loads this source as-is: Bun >= 1.2. Node >= 24 is the
  engines floor for tooling; native Node does not load extensionless
  TypeScript.
- These design docs live at the repository root. The npm tarball currently
  ships `src/` (tests excluded), `README.md`, and `LICENSE`.

## Public exports

Root (`@corbits/oauth-core`):

- `generatePkce`, `generateState`
- `openInBrowser`
- `startCallbackServer`, `OAuthCallbackError`,
  `OAuthCallbackPortInUseError`, `OAuthCallbackAddressUnavailableError`
- `buildAuthorizeUrl`, `baseTokensFromResponse`, `exchangeCode`,
  `refreshTokenRequest`, `OAuthTokenEndpointError`,
  `OAuthTokenResponseSchemaError`, `OAuthMissingRefreshTokenError`
- `startOAuthLogin`
- `createTokenSession`, `isTokenExpired`, `OAuthProfileNotFoundError`,
  `OAuthRefreshFailedError`
- Types: `Pkce`, `CallbackServer`, `CallbackServerConfig`, `AuthProfile`,
  `BaseTokens`, `OAuthClientConfig`, `TokenResponse`, `FetchLike`,
  `OAuthLoginDeps`, `OAuthLoginHandle`, `StagedOAuthProfile`,
  `StartOAuthLoginOptions`, `TokenSession`, `TokenSessionDeps`

Hub (`@corbits/oauth-core/hub`):

- `mountOAuthLogin`
- `callbackTargetFor`, `persistOAuthCredential`,
  `OAUTH_PROVIDER_METADATA_KEY`
- `createOAuthRefreshStore`, `createOAuthTokenRefresher`,
  `createRefreshTicker`

## Protocols and wire format

PKCE (RFC 7636), S256 only:

- Verifier: 32 random bytes, base64url (43 characters, inside the 43–128
  range).
- Challenge: SHA-256 of the verifier, base64url.
- Authorize query includes `code_challenge` and `code_challenge_method=S256`.
- Token exchange includes `code_verifier`.

OAuth 2.0 (RFC 6749) grants used:

- Authorize: `response_type=code`, `client_id`, `redirect_uri`,
  space-joined `scope`, `state`, optional `extraAuthorizeParams`.
- Token POST: `application/x-www-form-urlencoded`, `accept: application/json`.
  - Exchange: `grant_type=authorization_code` plus `code`, `client_id`,
    `redirect_uri`, `code_verifier`.
  - Refresh: `grant_type=refresh_token` plus `refresh_token`, `client_id`.
- No client secret. Public client only.

Token JSON is parsed with arktype:

```
access_token: string
refresh_token?: string
expires_in?: number
id_token?: string
```

`expires_in` must be a number when present. `baseTokensFromResponse`
computes `expiresAt = now + expires_in * 1000` or omits `expiresAt`. A
refresh response that omits `refresh_token` carries the previous one
forward; if neither exists, throw `OAuthMissingRefreshTokenError`.

Token HTTP uses injectable `fetch` (defaults to global `fetch` only at
`exchangeCode` / `refreshTokenRequest`). Every token request is bounded by
`AbortSignal.timeout(config.tokenTimeoutMs)`.

## Callback server

- `node:http` `createServer`, listen on a resolved loopback address.
- Default host `127.0.0.1`. Hostnames are `dns.promises.lookup`'d; any
  non-loopback result is rejected.
- `CallbackServerConfig`: `{ port, host?, path, doneHtml, failedHtml }`.
- Success: HTTP 200, `text/html; charset=utf-8`, caller `doneHtml`.
- State / error / missing code: HTTP 400 and `failedHtml(reason)`.
- Wrong path: HTTP 404 `"Not found"`.
- `EADDRINUSE` → `OAuthCallbackPortInUseError`; `EADDRNOTAVAIL` →
  `OAuthCallbackAddressUnavailableError`.

## Browser open

Best-effort, never throws. `spawn` with `stdio: "ignore"`, `detached: true`,
`unref`. Darwin `open`, POSIX `xdg-open`, Windows
`rundll32 url.dll,FileProtocolHandler` (argv, not `cmd /c start`, so `&` in
query strings cannot split into a second command).

## Hub specifics

Dependencies only on the hub subpath: `hono`, `drizzle-orm`, `@intx/db`,
`@intx/hub-api`, `@intx/hub-common`, `@intx/types`. Arktype is used on both
entry points.

- Routes (under the host's `requireGrant`):
  - `GET /oauth-logins/providers`
  - `POST /oauth-logins` → 201 `{ loginId, authorizeUrl }`
  - `GET /oauth-logins/:loginId` → login state, never tokens
  - `DELETE /oauth-logins/:loginId` → 204 or 404
- Default login TTL: 5 minutes. Default refresh interval: 60s. Default
  refresh margin: 10 minutes.
- Credential type `oauth_token`; secrets sealed with `credentialAad(id,
  "secret" | "refreshSecret")`. Metadata key `oauthProvider` names the
  registry entry the refresher matches.
- Refresh claim: `FOR UPDATE SKIP LOCKED` in the same transaction that
  writes new material.
- `OAuthTokenEndpointError` on refresh ⇒ reauth; other failures retry.

`redirect_uri` must include an explicit loopback port;
`callbackTargetFor` throws if the URL has no integer port.

## `OAuthClientConfig`

| Field | Meaning |
| --- | --- |
| `clientId` | Public client id. |
| `authorizeUrl` | Authorization endpoint. |
| `tokenUrl` | Token endpoint. |
| `redirectUri` | Registered loopback URI (`http://127.0.0.1:<port>/…`). |
| `scopes` | Sent space-joined. |
| `extraAuthorizeParams?` | Extra authorize query pairs a provider requires. |
| `tokenTimeoutMs` | Abort bound for token HTTP. |

## Tooling

```sh
bun install
bun run typecheck
bun run lint
bun run format:check
bun run test
bun run check   # all of the above
```

Tests sit next to the module they cover and exist only for a named
load-bearing risk. `exactOptionalPropertyTypes` is on: omit optional keys,
never assign `undefined` to them. Trust boundaries are parsed with arktype;
no `as T` on untrusted input.
