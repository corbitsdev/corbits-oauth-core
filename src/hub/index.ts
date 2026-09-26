// Server-only entry point: the hub-hosted login mount. The root export
// stays free of `hono` and `@intx/*` so browser bundles never reach them.
export { mountOAuthLogin, type MountOAuthLoginOpts } from "./mount.js";
export type { OAuthLoginProviders } from "../provider.js";
export {
  persistOAuthCredential,
  OAUTH_PROVIDER_METADATA_KEY,
} from "./credentials.js";
export {
  createOAuthRefreshStore,
  createOAuthTokenRefresher,
  createRefreshTicker,
  type ClaimedCredential,
  type DueCredential,
  type OAuthRefreshStore,
  type OAuthTokenRefresher,
  type OAuthTokenRefresherOpts,
} from "./refresh.js";
export { createLoginStore, type LoginState } from "./login-store.js";
