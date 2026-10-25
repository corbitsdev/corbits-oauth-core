import { type } from "arktype";

import type { Pkce } from "./pkce.js";
import { presentRefreshToken, type BaseTokens } from "./tokens.js";

// Provider-agnostic OAuth client config. Endpoints, client id, scopes, and
// timeouts are supplied by the caller; this module owns only the shared
// request shape.
export type OAuthClientConfig = {
  clientId: string;
  authorizeUrl: string;
  tokenUrl: string;
  redirectUri: string;
  scopes: readonly string[];
  // RFC 8707 resource indicator, sent on the authorize request and on every
  // token request so the issued token is audience-bound to that resource.
  resource?: string;
  // Extra authorize-request params a provider requires.
  extraAuthorizeParams?: Record<string, string>;
  tokenTimeoutMs: number;
};

// What a token request needs: a refresh does not repeat the authorize-time
// fields, so a host holding only a stored client id and token URL can refresh.
export type TokenEndpointConfig = Pick<
  OAuthClientConfig,
  "clientId" | "tokenUrl" | "tokenTimeoutMs" | "resource"
>;

const PROTECTED_AUTHORIZE_PARAMS = new Set([
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "code_challenge",
  "code_challenge_method",
  "state",
  "resource",
]);

/**
 * Build the authorization URL the user opens to grant access. The challenge
 * binds this request to the PKCE verifier held locally; `state` is the CSRF
 * nonce the redirect must echo back unchanged.
 *
 * Caller `extraAuthorizeParams` are applied first and cannot replace the
 * protected fields this function sets (PKCE, state, client, redirect, scope,
 * resource, response type). An empty scope list omits `scope` rather than
 * sending an empty value that would override the server default.
 */
export function buildAuthorizeUrl(
  config: OAuthClientConfig,
  pkce: Pkce,
  state: string,
): string {
  const url = new URL(config.authorizeUrl);
  if (config.extraAuthorizeParams !== undefined) {
    for (const [key, value] of Object.entries(config.extraAuthorizeParams)) {
      if (PROTECTED_AUTHORIZE_PARAMS.has(key)) continue;
      url.searchParams.set(key, value);
    }
  }
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  const scope = config.scopes.filter((item) => item.length > 0).join(" ");
  if (scope.length > 0) url.searchParams.set("scope", scope);
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", pkce.method);
  url.searchParams.set("state", state);
  if (config.resource !== undefined) {
    url.searchParams.set("resource", config.resource);
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

// No refresh token was present where a refresh was required.
export class OAuthMissingRefreshTokenError extends Error {
  constructor() {
    super("OAuth grant has no refresh token; a new authorization is required.");
    this.name = "OAuthMissingRefreshTokenError";
  }
}

/**
 * Convert a token response to the shared base token fields. `now` is
 * injectable so callers (and tests) control the expiry baseline;
 * `previousRefresh` is carried forward when a refresh response omits a new
 * refresh_token (servers may rotate or not). A blank refresh token is absent,
 * the same as an omitted one. When neither the response nor the previous
 * grant has a usable refresh token, the result simply has no `refresh`.
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
  const refresh =
    presentRefreshToken(response.refresh_token) ??
    presentRefreshToken(previousRefresh);
  return {
    access: response.access_token,
    ...(refresh !== undefined ? { refresh } : {}),
    ...(response.expires_in !== undefined
      ? { expiresAt: now + response.expires_in * 1000 }
      : {}),
  };
}

// `fetch` implementation to use for token requests; injectable for tests.
export type FetchLike = typeof fetch;

// OAuth error codes are a small token (RFC 6749 §5.2). Anything else in a
// token response body can be a secret and must not be copied into an Error.
const OAUTH_ERROR_CODE = /^[a-z0-9_]{1,64}$/;

function oauthErrorCode(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      "error" in parsed &&
      typeof parsed.error === "string" &&
      OAUTH_ERROR_CODE.test(parsed.error)
    ) {
      return parsed.error;
    }
  } catch {
    // Non-JSON bodies contribute no public detail.
  }
  return "";
}

function isRedirectResponse(res: Response): boolean {
  return (
    res.type === "opaqueredirect" ||
    res.redirected ||
    (res.status >= 300 && res.status < 400)
  );
}

// `fetchImpl` is a required parameter here, not defaulted to the global —
// only the exported entry points (exchangeCode, refreshTokenRequest) default
// to the real `fetch`; an internal helper reaching for the global itself
// would make that default impossible to override consistently from one place.
async function postToken(
  config: TokenEndpointConfig,
  body: URLSearchParams,
  fetchImpl: FetchLike,
): Promise<TokenResponse> {
  // Refresh can run on a hot path outside any surrounding timer, so the
  // token request must abort within the bounded timeout rather than hang
  // the caller forever when the endpoint stalls.
  //
  // `redirect: "manual"` is load-bearing: the body carries an authorization
  // code or refresh token, and the default follow mode would replay it at
  // the Location (RFC 9700). A 3xx is a failure and its body is not read.
  const res = await fetchImpl(config.tokenUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: body.toString(),
    redirect: "manual",
    signal: AbortSignal.timeout(config.tokenTimeoutMs),
  });
  if (isRedirectResponse(res)) {
    throw new OAuthTokenEndpointError(res.status, "redirect_refused");
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = oauthErrorCode((await res.text()).slice(0, 4096));
    } catch {
      // Non-2xx is the error; the body is not public detail.
    }
    throw new OAuthTokenEndpointError(res.status, detail);
  }
  let payload: unknown;
  try {
    payload = await res.json();
  } catch {
    throw new OAuthTokenResponseSchemaError("invalid JSON");
  }
  const json = TokenResponse(payload);
  if (json instanceof type.errors)
    throw new OAuthTokenResponseSchemaError(json.summary);
  return omitBlankRefresh(json);
}

// `refresh_token: ""` parses as a string, but it is not a credential. Drop it
// at the boundary so later stages see the same shape as an omitted field.
function omitBlankRefresh(response: TokenResponse): TokenResponse {
  if (presentRefreshToken(response.refresh_token) !== undefined)
    return response;
  if (response.refresh_token === undefined) return response;
  const { refresh_token: _blank, ...rest } = response;
  return rest;
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
  if (config.resource !== undefined) body.set("resource", config.resource);
  return postToken(config, body, fetchImpl);
}

/**
 * Mint a fresh access token from a refresh token. Returns the raw response;
 * callers map it and carry the prior refresh token forward when omitted.
 */
export async function refreshTokenRequest(
  config: TokenEndpointConfig,
  refreshToken: string,
  fetchImpl: FetchLike = fetch,
): Promise<TokenResponse> {
  if (presentRefreshToken(refreshToken) === undefined)
    throw new OAuthMissingRefreshTokenError();
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: config.clientId,
  });
  if (config.resource !== undefined) body.set("resource", config.resource);
  return postToken(config, body, fetchImpl);
}
