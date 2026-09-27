import { startCallbackServer } from "./callback-server.js";
import { buildAuthorizeUrl, type OAuthClientConfig } from "./client.js";
import { startOAuthLogin, type OAuthLoginDeps } from "./login.js";
import type { AuthProfile, BaseTokens } from "./tokens.js";

/**
 * One OAuth provider a host offers for login. The host owns the provider
 * packages, so this library never depends on any of them: it only sees an
 * OAuth config and a code exchange.
 */
export type OAuthLoginProvider = {
  /** Supplies the authorize URL and the fixed loopback redirect_uri. */
  readonly oauthConfig: OAuthClientConfig;
  /** Redeems the authorization code for tokens. */
  readonly exchange: (
    code: string,
    verifier: string,
    now: number,
  ) => Promise<BaseTokens>;
  /**
   * Redeems a stored refresh token for a fresh access token, ahead of
   * expiry. Absent when the provider issues no refreshable token: its
   * credentials are then left for the person to sign in again.
   */
  readonly refresh?: (
    refreshSecret: string,
    now: number,
  ) => Promise<BaseTokens>;
  /**
   * Credential metadata derived from the freshly-minted tokens — an account
   * id a provider needs on every inference request, say. Never the raw
   * id_token: the credential row is not a place to park a bearer assertion.
   */
  readonly metadata?: (tokens: BaseTokens) => Record<string, string>;
};

export type OAuthLoginProviders = Readonly<Record<string, OAuthLoginProvider>>;

/**
 * Splits a provider's registered redirect_uri into the host, port and path
 * the loopback callback server must bind. The port is fixed by the
 * authorization server's client registration, so it is read from the
 * provider rather than chosen here.
 */
export function callbackTargetFor(config: OAuthClientConfig): {
  host: string;
  port: number;
  path: string;
} {
  const url = new URL(config.redirectUri);
  const port = Number(url.port);
  if (!Number.isInteger(port) || port <= 0) {
    throw new Error(
      `OAuth redirect_uri must name an explicit loopback port; received ${config.redirectUri}.`,
    );
  }
  return { host: url.hostname, port, path: url.pathname };
}

export const signedInHtml =
  "<!doctype html><meta charset=utf-8><title>Signed in</title><p>Signed in. You can close this tab.";

// `reason` echoes the redirect's `error` parameter, which anyone can set.
export const signInFailedHtml = (reason: string): string =>
  `<!doctype html><meta charset=utf-8><title>Sign-in failed</title><p>Sign-in failed: ${reason.replace(/[<&]/g, "")}`;

export type LoginWithProviderOptions = {
  save: OAuthLoginDeps<BaseTokens>["saveProfile"];
  profile: string;
  signal: AbortSignal;
  openInBrowser: (url: string) => void;
};

/**
 * Run the loopback PKCE login against `provider`'s fixed redirect_uri, save
 * the exchanged profile, and return it. Hosts that need their own callback
 * pages, or to show the staged profile before committing it, use
 * `startOAuthLogin`. `provider.metadata` is not applied: the profile holds
 * tokens only, and the host derives any metadata from them when it stores
 * the credential.
 */
export async function loginWithProvider(
  provider: OAuthLoginProvider,
  opts: LoginWithProviderOptions,
): Promise<AuthProfile<BaseTokens>> {
  const target = callbackTargetFor(provider.oauthConfig);
  const login = await startOAuthLogin(
    {
      profile: opts.profile,
      signal: opts.signal,
    },
    {
      startCallbackServer: (state) =>
        startCallbackServer(state, {
          host: target.host,
          port: target.port,
          path: target.path,
          doneHtml: signedInHtml,
          failedHtml: signInFailedHtml,
        }),
      buildAuthorizeUrl: (pkce, state) =>
        buildAuthorizeUrl(provider.oauthConfig, pkce, state),
      exchangeCode: provider.exchange,
      saveProfile: opts.save,
      openInBrowser: opts.openInBrowser,
    },
  );
  const staged = await login.completed;
  await staged.commit();
  return staged.profile;
}
