import type { BaseTokens, OAuthClientConfig } from "../index.js";

/**
 * One provider a host offers for hub-hosted login. The host owns the
 * provider packages, so this library never depends on any of them: it only
 * sees an OAuth config and a code exchange.
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
