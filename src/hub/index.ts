// Server-only entry point: the hub-hosted login mount. The root export
// stays free of `hono` and `@intx/*` so browser bundles never reach them.
export { mountOAuthLogin, type MountOAuthLoginOpts } from "./mount";
export {
  callbackTargetFor,
  type OAuthLoginProvider,
  type OAuthLoginProviders,
} from "./registry";
export { persistOAuthCredential } from "./credentials";
export type { LoginState } from "./login-store";
