export { generatePkce, generateState, type Pkce } from "./pkce.js";

export { openInBrowser } from "./browser.js";

export {
  startCallbackServer,
  OAuthCallbackError,
  OAuthCallbackPortInUseError,
  OAuthCallbackAddressUnavailableError,
  type CallbackServer,
  type CallbackServerConfig,
} from "./callback-server.js";

export type { AuthProfile, BaseTokens } from "./tokens.js";
export {
  buildAuthorizeUrl,
  baseTokensFromResponse,
  exchangeCode,
  refreshTokenRequest,
  OAuthTokenEndpointError,
  OAuthTokenResponseSchemaError,
  OAuthMissingRefreshTokenError,
  type FetchLike,
  type OAuthClientConfig,
  type TokenResponse,
} from "./client.js";

export {
  startOAuthLogin,
  type OAuthLoginDeps,
  type OAuthLoginHandle,
  type StagedOAuthProfile,
  type StartOAuthLoginOptions,
} from "./login.js";

export {
  callbackTargetFor,
  loginWithProvider,
  type LoginWithProviderOptions,
  type OAuthLoginProvider,
} from "./provider.js";

export {
  createTokenSession,
  isTokenExpired,
  OAuthProfileNotFoundError,
  OAuthRefreshFailedError,
  type TokenSession,
  type TokenSessionDeps,
} from "./session.js";

export {
  discoverMcpLoginEntry,
  registerMcpClient,
  mcpClientConfig,
  selectMcpScopes,
  OAuthDiscoveryError,
  type DiscoverMcpLoginEntryOptions,
  type McpAuthorizationServer,
  type McpClientConfigOptions,
  type McpClientRegistration,
  type McpLoginEntry,
  type RegisterMcpClientOptions,
  type SelectMcpScopesOptions,
} from "./discovery.js";
