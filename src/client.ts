import { type } from "arktype";

import type { Pkce } from "./pkce";
import type { BaseTokens } from "./tokens";

// Provider-agnostic OAuth client config. Endpoints, client id, scopes, and
// timeouts are supplied by the caller; this module owns only the shared
// request shape.
export type OAuthClientConfig = {
  clientId: string;
  authorizeUrl: string;
  tokenUrl: string;
  redirectUri: string;
  scopes: readonly string[];
  // Extra authorize-request params a provider requires.
  extraAuthorizeParams?: Record<string, string>;
  tokenTimeoutMs: number;
};

/**
 * Build the authorization URL the user opens to grant access. The challenge
 * binds this request to the PKCE verifier held locally; `state` is the CSRF
 * nonce the redirect must echo back unchanged.
 */
export function buildAuthorizeUrl(
  config: OAuthClientConfig,
  pkce: Pkce,
  state: string,
): string {
  const url = new URL(config.authorizeUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("scope", config.scopes.join(" "));
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", pkce.method);
  url.searchParams.set("state", state);
  if (config.extraAuthorizeParams !== undefined) {
    for (const [key, value] of Object.entries(config.extraAuthorizeParams)) {
      url.searchParams.set(key, value);
    }
  }
  return url.toString();
}

// Validate the whole token response, not just access_token: a malformed
// expires_in (e.g. the string "soon") would otherwise survive and compute a
// NaN expiry, which never compares as expired, so the token would never
// refresh.
const TokenResponse = type({
  access_token: "string",
  "refresh_token?": "string",
  "expires_in?": "number",
  "id_token?": "string",
});
export type TokenResponse = typeof TokenResponse.infer;

// The token endpoint responded with a non-2xx status.
export class OAuthTokenEndpointError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(
      `OAuth token endpoint returned ${String(status)}${detail ? `: ${detail}` : ""}`,
    );
    this.name = "OAuthTokenEndpointError";
    this.status = status;
    this.detail = detail;
  }
}

// The token endpoint responded 2xx with a payload that failed validation.
export class OAuthTokenResponseSchemaError extends Error {
  constructor(summary: string) {
    super(`OAuth token endpoint returned an unexpected payload: ${summary}`);
    this.name = "OAuthTokenResponseSchemaError";
  }
}

// No refresh token was present in the response or carried forward from a prior one.
export class OAuthMissingRefreshTokenError extends Error {
  constructor() {
    super(
      "OAuth token response carried no refresh_token and none was previously stored.",
    );
    this.name = "OAuthMissingRefreshTokenError";
  }
}

/**
 * Convert a token response to the shared base token fields. `now` is
 * injectable so callers (and tests) control the expiry baseline;
 * `previousRefresh` is carried forward when a refresh response omits a new
 * refresh_token (servers may rotate or not).
 *
 * `expires_in` is RECOMMENDED, not required, on a token response (RFC 6749
 * §5.1). When a server omits it there is no spec-defined lifetime to fall
 * back to, so `expiresAt` is left absent rather than guessed — a caller that
 * needs a concrete expiry for such a token must supply its own policy.
 */
export function baseTokensFromResponse(
  response: TokenResponse,
  now: number,
  previousRefresh: string | undefined,
): BaseTokens {
  const refresh = response.refresh_token ?? previousRefresh;
  if (refresh === undefined) throw new OAuthMissingRefreshTokenError();
  return {
    access: response.access_token,
    refresh,
    ...(response.expires_in !== undefined
      ? { expiresAt: now + response.expires_in * 1000 }
      : {}),
  };
}

// `fetch` implementation to use for token requests; injectable for tests.
export type FetchLike = typeof fetch;

// `fetchImpl` is a required parameter here, not defaulted to the global —
// only the exported entry points (exchangeCode, refreshTokenRequest) default
// to the real `fetch`; an internal helper reaching for the global itself
// would make that default impossible to override consistently from one place.
async function postToken(
  config: OAuthClientConfig,
  body: URLSearchParams,
  fetchImpl: FetchLike,
): Promise<TokenResponse> {
  // Refresh can run on a hot path outside any surrounding timer, so the
  // token request must abort within the bounded timeout rather than hang
  // the caller forever when the endpoint stalls.
  const res = await fetchImpl(config.tokenUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: body.toString(),
    signal: AbortSignal.timeout(config.tokenTimeoutMs),
  });
  if (!res.ok) {
    let detail = "";
    try {
      detail = await res.text();
    } catch {
      // Non-2xx is the error; the body is optional detail.
    }
    throw new OAuthTokenEndpointError(res.status, detail);
  }
  const json = TokenResponse(await res.json());
  if (json instanceof type.errors)
    throw new OAuthTokenResponseSchemaError(json.summary);
  return json;
}

/**
 * Exchange an authorization code for a raw token response. Callers map the
 * response onto their stored token shape (account id, id_token, ...).
 */
export async function exchangeCode(
  config: OAuthClientConfig,
  code: string,
  verifier: string,
  fetchImpl: FetchLike = fetch,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code_verifier: verifier,
  });
  return postToken(config, body, fetchImpl);
}

/**
 * Mint a fresh access token from a refresh token. Returns the raw response;
 * callers map it and carry the prior refresh token forward when omitted.
 */
export async function refreshTokenRequest(
  config: OAuthClientConfig,
  refreshToken: string,
  fetchImpl: FetchLike = fetch,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: config.clientId,
  });
  return postToken(config, body, fetchImpl);
}
