# @corbits/oauth-core

PKCE + loopback OAuth for an Interchange host: mint an OAuth token the host stores as a credential, which an `InferenceSource` names by `credentialId` (the harness reads the current secret at send time). A loopback callback server, token exchange/refresh, and an expiring-token session that refreshes ahead of expiry and coalesces concurrent refreshes. Endpoints and client id come from the caller, and persistence stays with the host.

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

Outside a hub, a CLI or desktop app drives `startOAuthLogin` itself. Each
dependency is where that host plugs in its own piece: its callback page, the
provider package's code exchange, and its own credential store.

```ts
import {
  createTokenSession,
  buildAuthorizeUrl,
  startCallbackServer,
  startOAuthLogin,
  type BaseTokens,
  type CallbackServer,
  type OAuthLoginDeps,
  type TokenSessionDeps,
} from "@corbits/oauth-core";
import type { OAuthLoginProvider } from "@corbits/oauth-core/hub";

// The host's own callback page, served on the provider's fixed redirect_uri.
function startBrandedCallbackServer(
  provider: OAuthLoginProvider,
  expectedState: string,
): Promise<CallbackServer> {
  const redirect = new URL(provider.oauthConfig.redirectUri);
  return startCallbackServer(expectedState, {
    host: redirect.hostname,
    port: Number(redirect.port),
    path: redirect.pathname,
    doneHtml: "<p>Signed in. You can close this tab.</p>",
    failedHtml: ({ code }) => `<p>Sign-in failed: ${code}</p>`,
  });
}

// Where this host keeps secrets at rest: an OS keychain, an encrypted file.
export type ProfileStore = {
  save: OAuthLoginDeps<BaseTokens>["saveProfile"];
  load: TokenSessionDeps<BaseTokens, string>["loadProfile"];
  update: TokenSessionDeps<BaseTokens, string>["updateTokens"];
};

// `provider` comes from a provider package, e.g. `@corbits/xai-provider`,
// which supplies the OAuth config, code exchange and refresh.
export async function signIn(
  provider: OAuthLoginProvider,
  store: ProfileStore,
  signal: AbortSignal,
): Promise<string> {
  const login = await startOAuthLogin(
    { profile: "default", signal },
    {
      startCallbackServer: (state) =>
        startBrandedCallbackServer(provider, state),
      buildAuthorizeUrl: (pkce, state) =>
        buildAuthorizeUrl(provider.oauthConfig, pkce, state),
      exchangeCode: provider.exchange,
      saveProfile: store.save,
    },
  );
  const staged = await login.completed;
  await staged.commit();

  const refresh = provider.refresh;
  if (refresh === undefined) {
    return staged.profile.tokens.access;
  }
  const session = createTokenSession<BaseTokens, string>({
    skewMs: 30_000,
    loadProfile: store.load,
    updateTokens: store.update,
    refreshTokens: (refreshToken, now) => refresh(refreshToken, now),
    toAccess: (tokens) => tokens.access,
  });
  return session.getValidToken("default");
}
```

`startOAuthLogin` opens the browser, waits for the callback, exchanges the
code, and stages the profile; `commit()` saves it. The token session then
refreshes ahead of expiry and coalesces concurrent refreshes.

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

### Lower-level: an MCP server with no fixed client

An MCP server such as Linear's publishes its authorization server instead of
a fixed client id. Discover it, register a public client, and build the same
`OAuthClientConfig` the flows above take:

```ts
import {
  discoverMcpLoginEntry,
  mcpClientConfig,
  registerMcpClient,
  type OAuthClientConfig,
} from "@corbits/oauth-core";

export async function mcpOAuthConfig(
  resourceUrl: string,
  redirectUri: string,
  clientName: string,
): Promise<{ config: OAuthClientConfig; clientId: string }> {
  const entry = await discoverMcpLoginEntry({ resourceUrl });
  const { registrationEndpoint } = entry.authorizationServer;
  if (registrationEndpoint === undefined) {
    throw new Error(`${resourceUrl} offers no dynamic client registration`);
  }
  const { clientId } = await registerMcpClient({
    registrationEndpoint,
    redirectUris: [redirectUri],
    clientName,
  });
  return {
    config: mcpClientConfig(entry, { clientId, redirectUri }),
    clientId,
  };
}
```

Store `clientId` with the credential: refresh needs the same client that
signed in. `registerMcpClient` also returns the `grantTypes` and `scope` the
server actually granted, which can be narrower than what was asked for.
Discovery refuses a server without PKCE S256 or public-client support, and
`mcpClientConfig` picks scopes the way the MCP spec orders them, adding
`offline_access` when the server offers it (pass `scopes` to override). The config carries the RFC 8707 `resource` parameter, so the token
is bound to that one MCP server.

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
