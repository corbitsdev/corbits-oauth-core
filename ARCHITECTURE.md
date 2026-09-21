# @corbits/oauth-core — Architecture

## Overview

Two entry points share one login kernel.

- `@corbits/oauth-core` — library used by a local host: generate PKCE and
  state, bind a loopback callback, build the authorize URL, exchange the
  code, stage a profile, refresh a session.
- `@corbits/oauth-core/hub` — the same kernel, in-process on a tenant
  router. The browser never sees the verifier or the tokens.

Issuer identity stays outside the package. `OAuthClientConfig` is the only
place endpoints, client id, redirect URI, and scopes are named, and the
caller fills it.

MCP resource discovery and dynamic registration are out of scope here.
They are a separate product surface, not a layer on this loopback flow.

## Components

```
Caller config (endpoints, client id, redirect_uri, scopes, HTML)
        │
        ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ pkce / state    │────▶│ authorize URL    │────▶│ user browser    │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
        │                                                 │
        │                                                 │ redirect
        ▼                                                 ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ login orchestr. │◀───▶│ loopback server  │◀────│ 127.0.0.0/8 or  │
│ startOAuthLogin │     │ startCallback…   │     │ ::1 only        │
└────────┬────────┘     └──────────────────┘     └─────────────────┘
         │ code + verifier
         ▼
┌─────────────────┐     ┌──────────────────┐
│ token client    │────▶│ staged profile   │──commit()──▶ host store
│ exchange/refresh│     │ (not persisted)  │
└─────────────────┘     └──────────────────┘
         ▲
         │ refresh_token
┌────────┴────────┐
│ token session   │  coalesced refresh-ahead per profile name
└─────────────────┘
```

| Piece | Role |
| --- | --- |
| PKCE + state | One-attempt verifier/challenge (S256) and CSRF nonce. |
| Authorize URL builder | `response_type=code` plus challenge, state, caller scopes. |
| Loopback callback server | Fixed-port HTTP listener; state-checked before the code is trusted. |
| Token client | Authorization-code exchange and refresh-token grant. Maps the response onto `BaseTokens` without guessing a lifetime. |
| Login orchestrator | Starts the server, opens the browser, waits, exchanges, returns a staged profile. Closes the server on success, failure, or abort. |
| Token session | Loads a named profile, refreshes within skew of expiry, coalesces concurrent callers. |
| Hub mount | In-process login store, stock `oauth_token` write, due-credential refresher. |

Persistence is a port (`saveProfile` / `loadProfile` / `updateTokens`), not
a module in this package.

## Login control flow

1. Generate PKCE and state.
2. Bind the callback server **before** listen with `expectedState` already
   set, so a redirect that arrives the instant the socket opens is still
   CSRF-checked.
3. Build the authorize URL; open it (best-effort). The copyable URL is the
   fallback if no browser is available.
4. `completed` is lazy: waiting and exchange start when the caller first
   observes the promise, so a rejection cannot land unhandled.
5. On a matching redirect, exchange the code with the verifier. Return
   `{ profile, commit }`. `commit` is the first write; a second call shares
   the in-flight write. The host can abandon the staged profile without
   persisting.
6. The callback server closes when that work finishes, fails, or is aborted.

Hub login uses the same steps with `openInBrowser` as a no-op: the HTTP
response returns `{ loginId, authorizeUrl }` and the process waits on
`completed`, then writes the credential itself.

## Loopback callback

The authorization server only accepts the **registered** `redirect_uri`, so
the port is fixed. A bind failure (`EADDRINUSE`, `EADDRNOTAVAIL`) is not a
cue to pick another port.

The redirect that carries the authorization code is cleartext HTTP.
Routable and wildcard binds are rejected: the host must resolve to
loopback-only addresses (`127.0.0.0/8` or `::1`). IPv4 is preferred when
both families resolve so `localhost` matches the default callback host.

Outcomes are buffered. No Promise exists until `waitForCode`, so an early
failed redirect cannot become an unhandled rejection. Path mismatch is 404
and ignored; state mismatch, missing code, or `error=` fail the login.

## Tokens and session

`BaseTokens` is `{ access, refresh, expiresAt? }`. `expiresAt` is absent
when the token endpoint omitted `expires_in` (recommended, not required).
The package will not invent a lifetime. A token of unknown age is treated
as not expired and used until the server rejects it — eager refresh on
every call would rotate a single-use refresh token.

`createTokenSession` re-checks expiry after load (another caller may have
already refreshed), coalesces in-flight refresh per profile name, and
clears the in-flight slot on both success and failure so a later call can
retry. `mergeRefreshed` is optional for fields a refresh response omits.

## Hub

The root export stays free of HTTP-framework and hub-database types so a
browser bundle never reaches them. The hub subpath:

- Lists host-supplied providers; the library never names one.
- Starts a login under the host's grant middleware. PKCE, loopback, and
  exchange stay in this process.
- Polls and cancel are owner-scoped (tenant + principal). Tokens never
  appear in login state — only `pending` / `completed` (credential id) /
  `failed` / `cancelled`.
- Logins are in-process and TTL-bounded (default five minutes) so an
  abandoned attempt releases its fixed callback port.
- Persists through the same `oauth_token` row shape and AAD-bound secrets
  as a hand-entered credential. Re-login under the same name replaces
  secrets in place.
- A refresher lists due `oauth_token` rows, claims with row locks so two
  hubs do not both refresh one credential, and treats a token-endpoint
  rejection as "reauth" (the refresh token is dead) while other errors
  retry on the next pass.

## Failure modes

| Condition | Behavior |
| --- | --- |
| Callback host is not loopback | Refuse to bind. |
| Port in use / address unavailable | Typed bind errors; do not scan for another port. |
| State mismatch | HTML failure page; abort as CSRF. |
| `error=` or empty code | HTML failure page; abort. |
| Abort signal | Callback wait fails; server closes. |
| Token endpoint non-2xx | `OAuthTokenEndpointError` (hub refresh: reauth). |
| 2xx payload fails validation | `OAuthTokenResponseSchemaError` (malformed `expires_in` must not become a never-expiring token). |
| No refresh token in response or store | `OAuthMissingRefreshTokenError`. |
| Named profile missing | `OAuthProfileNotFoundError`. |
| Refresh throws | `OAuthRefreshFailedError` with cause; in-flight slot cleared. |
| Hub login TTL elapsed | Cancel, abort, mark failed, drop the entry. |
| Provider has no `refresh` | Leave the credential for a fresh sign-in. |

## Out of scope

- RFC 9728 protected-resource metadata
- RFC 8414 authorization-server metadata
- RFC 7591 dynamic client registration
- Any issuer-specific authorize or token URL
- Credential storage implementations other than the hub's stock
  `oauth_token` write (the library path is host-supplied)
