// Server-only entry point: the hub-hosted login mount. The root export
// stays free of `hono` and `@intx/*` so browser bundles never reach them.
export { mountOAuthLogin, type MountOAuthLoginOpts } from "./mount";
export {
  callbackTargetFor,
  type OAuthLoginProvider,
  type OAuthLoginProviders,
} from "./registry";
export {
  persistOAuthCredential,
  OAUTH_PROVIDER_METADATA_KEY,
} from "./credentials";
export {
  createOAuthRefreshStore,
  createOAuthTokenRefresher,
  createRefreshTicker,
  type ClaimedCredential,
  type DueCredential,
  type OAuthRefreshStore,
  type OAuthTokenRefresher,
  type OAuthTokenRefresherOpts,
} from "./refresh";
export { createLoginStore, type LoginState } from "./login-store";
