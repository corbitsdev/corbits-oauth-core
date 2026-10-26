# @corbits/oauth-core

OAuth 2.0 authorization-code login with PKCE and a loopback callback, in the Corbits auth & credentials bucket: it mints the tokens an Interchange hub (the multi-tenant control plane that holds tenants, principals and credentials) stores as `oauth_token` credentials. It also works standalone in any CLI or desktop host, with token refresh and MCP server discovery.

## Why @corbits/oauth-core?

1. **Provider-agnostic.** A provider is a config plus an `exchange` function the host supplies. The package never names or depends on one.
2. **One call to sign in.** `loginWithProvider` binds the provider's registered redirect URI, opens the browser, exchanges the code, and saves the profile.
3. **Tokens stay fresh.** The token session refreshes ahead of expiry and coalesces concurrent refreshes; on a hub, a background refresher renews stored credentials under a row lock.
4. **Hub-ready.** The `/hub` entry mounts login routes on a hub tenant router, gated by the host's grants (a principal's permission on a resource), and writes tokens through the host's `CredentialCipher`.

## Install

```sh
bun add @corbits/oauth-core@0.3.3
```

This release is `@corbits/oauth-core@0.3.3`. MCP pairing is [`@corbits/mcp@0.4.0`](https://github.com/corbitsdev/corbits-mcp), which calls this package for the login.

This installs `@intx/db`, `@intx/hub-api`, `@intx/hub-common`, `@intx/types`, `drizzle-orm` and `hono` as dependencies. Only the `@corbits/oauth-core/hub` entry imports them, so browser and CLI bundles built from the root entry do not include them.

## Quickstart

```ts
import {
  baseTokensFromResponse,
  exchangeCode,
  loginWithProvider,
  openInBrowser,
} from "@corbits/oauth-core";

const oauthConfig = {
  clientId: "my-cli",
  authorizeUrl: "https://auth.example.com/authorize",
  tokenUrl: "https://auth.example.com/token",
  redirectUri: "http://127.0.0.1:1455/callback",
  scopes: ["openid", "offline_access"],
  tokenTimeoutMs: 10_000,
};

const profile = await loginWithProvider(
  {
    oauthConfig,
    exchange: async (code, verifier, now) =>
      baseTokensFromResponse(
        await exchangeCode(oauthConfig, code, verifier),
        now,
        undefined,
      ),
  },
  {
    profile: "default",
    signal: AbortSignal.timeout(120_000),
    openInBrowser,
    save: async (saved) => console.log(`saved ${saved.name}`),
  },
);
console.log(profile.tokens.expiresAt);
```

The callback server binds only loopback addresses (`127.0.0.0/8` or `::1`) on the port in `redirectUri`, which must match the client registration exactly.

## Where it fits

- **CLI or desktop host:** the root entry. The host keeps profiles in its own store (an OS keychain, an encrypted file).
- **Interchange hub** (`@intx/hub-api`, `@intx/db`, `@intx/types`): the `/hub` entry mounts login routes and refreshes `oauth_token` credentials that an `InferenceSource` names by `credentialId`.
- **Providers:** a provider package or the host itself supplies an `OAuthLoginProvider`.
- **MCP servers:** pairs with [`@corbits/mcp@0.4.0`](https://github.com/corbitsdev/corbits-mcp). `discoverMcpLoginEntry` builds the `OAuthClientConfig` for servers that publish their authorization server instead of a fixed client.

## Reference

### Root entry (`@corbits/oauth-core`)

| Export                                                                               | Purpose                                                                                                            |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `loginWithProvider(provider, opts)`                                                  | Sign in with a provider and save the profile.                                                                      |
| `startOAuthLogin(opts, deps)`                                                        | Lower-level login; returns the authorize URL and a staged profile to `commit()`. Use it for custom callback pages. |
| `createTokenSession(deps)`                                                           | `getValidToken(profile)` refreshes ahead of expiry and coalesces concurrent refreshes.                             |
| `startCallbackServer(state, config)`                                                 | The loopback callback listener.                                                                                    |
| `buildAuthorizeUrl`, `exchangeCode`, `refreshTokenRequest`, `baseTokensFromResponse` | Token endpoint helpers.                                                                                            |
| `callbackTargetFor(config)`                                                          | The host, port and path a `redirectUri` binds.                                                                     |
| `discoverMcpLoginEntry`, `registerMcpClient`, `mcpClientConfig`, `selectMcpScopes`   | MCP authorization discovery and dynamic client registration.                                                       |
| `generatePkce`, `generateState`, `openInBrowser`                                     | Primitives.                                                                                                        |

### Hub entry (`@corbits/oauth-core/hub`)

| Export                            | Purpose                                                   |
| --------------------------------- | --------------------------------------------------------- |
| `mountOAuthLogin(app, opts)`      | Adds the login routes below to a tenant router.           |
| `createOAuthTokenRefresher(opts)` | Background refresher with `start()` and `stop()`.         |
| `persistOAuthCredential`          | Writes tokens into an encrypted `oauth_token` credential. |

| Route                           |                                                                                                                                        |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /oauth-logins/providers`   | Provider names the host offers.                                                                                                        |
| `POST /oauth-logins`            | Start a login from `provider` or an MCP `resourceUrl` (plus `providerId`, `credentialName`); returns the authorize URL and a login id. |
| `GET /oauth/callback`           | The redirect target of resource-URL logins (`${baseUrl}/oauth/callback`); needs no grant.                                              |
| `GET /oauth-logins/:loginId`    | Poll for completion; returns the credential id when done.                                                                              |
| `DELETE /oauth-logins/:loginId` | Cancel.                                                                                                                                |

A resource-URL login discovers the server's authorization server and obtains a client id from a pre-registered `clientId`, a Client ID Metadata Document URL (`clientMetadataUrl`, only when the server advertises it), or dynamic client registration. It stores that client id, the token URL and the resource on the credential, so the refresher renews a credential that has a refresh token without a registry entry. An access token issued with no refresh token is stored without one; the refresher skips that row, and a new login is required when it expires. It needs the mount's `callbackUrl` and `store` options (below). The PKCE verifier never leaves the hub process.

What the callback route relies on: PKCE S256 is required of the server (discovery refuses one that does not advertise it); the `state` is 32 random bytes, single-use and bound to the tenant and principal that started the login; the RFC 8707 `resource` goes on the authorize, exchange and refresh requests; the discovered issuer is recorded with that state, a present `iss` must match it, and a missing `iss` is refused only when the server advertises RFC 9207; caller authorize extras cannot replace PKCE, state, or the other protected fields; token requests do not follow redirects and do not put response bodies in errors; the page is served `no-store` / `no-referrer`; and `callbackUrl` must be `https` unless it is loopback (`localhost`, `127.x`, `::1`), which is what local development uses.

In 0.3.3, authorization and token endpoint origins must match the issuer that was fetched. A document that points the token endpoint at a different origin is rejected before the code and PKCE verifier are posted. A blank or whitespace refresh token is treated as absent. The refresher does not call the token endpoint for it. A long `invalid_grant` body still retires the credential (the row is marked `error`). The `error_description` is not copied into the public error. Client ID Metadata URLs are stored as one canonical URL. Backslash dot-segments are rejected.

The loopback callback from `startCallbackServer` still does not check `iss`, because that path has no discovered issuer. The hub callback does.

## Using with Interchange

Mount the routes under the tenant prefix, gate them with the host's grant middleware (a grant is a principal's permission on a resource), and run the refresher:

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
    requireGrant: MiddlewareHandler<TenantEnv>;
    providers: OAuthLoginProviders;
    onRefreshed: (context: { tenantId: string; credentialId: string }) => void;
  },
): OAuthTokenRefresher {
  const oauthLoginApi = new Hono<TenantEnv>();
  mountOAuthLogin(oauthLoginApi, {
    db: opts.db,
    cipher: opts.cipher,
    requireGrant: opts.requireGrant,
    providers: opts.providers,
  });
  app.route("/api/tenants/:tenantId", oauthLoginApi);

  const refresher = createOAuthTokenRefresher({
    db: opts.db,
    cipher: opts.cipher,
    providers: opts.providers,
    onRefreshed: opts.onRefreshed,
  });
  refresher.start();
  return refresher;
}
```

The refresher only updates the credential row. A process that loaded the old token into memory, such as a running sidecar (the agent runtime), keeps it until told to reload, so notify those processes from `onRefreshed`.

The hub entry will move to a separate `@corbits/oauth-hub` package in a later release.

### Resource-URL logins

The redirect lands on a hub-root route outside any tenant, so mount it beside the tenant router and share one store:

```ts
const store = createOAuthLoginStore();
mountOAuthCallback(app, { store, path: "/api/oauth/callback" }); // unauthenticated
mountOAuthLogin(oauthLoginApi, {
  // ...db, cipher, requireGrant, providers
  store,
  callbackUrl: "https://hub.example.com/api/oauth/callback",
});
```

`callbackUrl` is the absolute public URL of that route; it is registered verbatim as the redirect_uri.

A refused redirect is reported as a code — `state_mismatch`, `provider_error`
(carrying the authorization server's own `error`), `no_code` — not as prose.
What to tell the person differs by product and brand; what the redirect was
does not.

#### Retrying a sign-in

The authorization server accepts one registered redirect_uri per client, so
every attempt for a provider contends for the same loopback port, and the
authorize page already open in the browser is bound to the state and PKCE
verifier of the attempt that opened it. A second attempt should therefore
resume the first, not replace it. `createLoginRegistry` holds one live login
per key and does that:

```ts
import { createLoginRegistry } from "@corbits/oauth-core";

const logins = createLoginRegistry();

const { handle, resumed } = await logins.startOrResume(
  "codex",
  () => startOAuthLogin({ profile: "default", signal }, deps),
  // Only the principal who started a login resumes it.
  { tag: `${tenantId}:${principalId}` },
);
```

An entry is released when its login settles, so the next attempt after a
completed, failed or cancelled one starts clean. `logins.cancel(key)` ends
the login in flight and frees the port. `mountOAuthLogin` uses this already:
a start that collides with a pending login answers `200` with that login's
id rather than `409`.

## Upgrading from 0.1

- `OAuthLoginProvider` and `callbackTargetFor` import from `@corbits/oauth-core`, not `@corbits/oauth-core/hub`.
- `CallbackServer.port` is required. A custom `startCallbackServer` must return the bound port.
- Stored profiles and `oauth_token` credentials are unchanged and keep working.

## License

LGPL-2.1-only.
