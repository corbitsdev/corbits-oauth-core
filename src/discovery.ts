import { type } from "arktype";

import type { FetchLike, OAuthClientConfig } from "./client";

// Generic MCP-OAuth discovery (RFC 9728 protected-resource metadata, RFC 8414
// authorization-server metadata) plus RFC 7591 dynamic client registration.
// Nothing here names a provider: the caller supplies the MCP server's resource
// URL and gets back the endpoints plus a registered client id it can feed to
// buildAuthorizeUrl/exchangeCode. Hosts persist the client id alongside the
// tokens (see OAUTH_CLIENT_ID_METADATA_KEY in ./hub/credentials) so refresh
// keeps working after the login completes.
//
// Grant types, scopes, and the PKCE code-challenge method are negotiated from
// server metadata rather than hard-coded, per the MCP authorization spec
// (https://modelcontextprotocol.io/specification/latest/basic/authorization)
// and its "Client Registration" and "Security Considerations" sub-pages.

// Discovery failed: metadata missing, unreachable, malformed, or the server
// does not support dynamic registration.
export class OAuthDiscoveryError extends Error {
  constructor(detail: string) {
    super(`OAuth discovery failed: ${detail}`);
    this.name = "OAuthDiscoveryError";
  }
}

// RFC 9728 §2 — protected-resource metadata. Only the fields discovery needs
// are validated; anything else the server sends is ignored.
const ProtectedResourceMetadata = type({
  resource: "string",
  "authorization_servers?": "string[]",
  "scopes_supported?": "string[]",
});

// RFC 8414 §2 — authorization-server metadata, narrowed to the endpoints and
// capabilities a loopback PKCE login needs. `registration_endpoint` is
// optional: its absence means the server does not support dynamic
// registration.
const AuthorizationServerMetadata = type({
  issuer: "string",
  authorization_endpoint: "string",
  token_endpoint: "string",
  "registration_endpoint?": "string",
  "grant_types_supported?": "string[]",
  "scopes_supported?": "string[]",
  "token_endpoint_auth_methods_supported?": "string[]",
  "code_challenge_methods_supported?": "string[]",
});

// RFC 7591 §3.2.1 — registration response, narrowed to the assigned client id
// plus what the server echoes back as actually granted. A server MAY narrow
// the request (e.g. drop refresh_token, trim scope); callers that need to
// persist what was granted read these instead of assuming the request stuck.
const ClientRegistrationResponse = type({
  client_id: "string",
  "grant_types?": "string[]",
  "scope?": "string",
});

// The authorization server a protected resource points at.
export type McpAuthorizationServer = {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
  grantTypesSupported?: readonly string[];
  scopesSupported?: readonly string[];
  tokenEndpointAuthMethodsSupported?: readonly string[];
  codeChallengeMethodsSupported?: readonly string[];
};

// A login entry derived from a resource URL: everything the host needs to
// register a client and build an authorize URL, before any provider-specific
// state exists.
export type McpLoginEntry = {
  resourceUrl: string;
  authorizationServer: McpAuthorizationServer;
  // The protected resource's own `scopes_supported` (RFC 9728 §2), if it
  // published one. Distinct from the authorization server's scopes_supported.
  resourceScopesSupported?: readonly string[];
};

export type DiscoverMcpLoginEntryOptions = {
  resourceUrl: string;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
};

export type RegisterMcpClientOptions = {
  registrationEndpoint: string;
  redirectUris: readonly string[];
  clientName: string;
  // The authorization server's advertised grant_types_supported (RFC 8414
  // §2), used to decide whether to request refresh_token. Omit when unknown.
  grantTypesSupported?: readonly string[];
  scope?: string;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
};

// What the authorization server actually granted the registered client,
// falling back to what was requested when the response doesn't echo it back.
export type McpClientRegistration = {
  clientId: string;
  grantTypes: string[];
  scope?: string;
};

export type McpClientConfigOptions = {
  clientId: string;
  redirectUri: string;
  // Explicit override; bypasses selectMcpScopes entirely.
  scopes?: readonly string[];
  // The `scope` parameter from a 401 WWW-Authenticate challenge, if the host
  // has one. Only consulted when `scopes` is omitted.
  challengeScope?: string;
  // Add `offline_access` (when the authorization server supports it) so the
  // token response includes a refresh token. Only consulted when `scopes` is
  // omitted. Defaults to true — registerMcpClient already requests
  // refresh_token by default, so scope selection wants offline_access by
  // default too; pass false to opt out.
  wantRefresh?: boolean;
  extraAuthorizeParams?: Record<string, string>;
  tokenTimeoutMs?: number;
};

export type SelectMcpScopesOptions = {
  entry: McpLoginEntry;
  challengeScope?: string;
  // Defaults to true, matching registerMcpClient's default refresh_token
  // request; pass false to opt out of adding offline_access.
  wantRefresh?: boolean;
};

const DEFAULT_TIMEOUT_MS = 10_000;

// Build a well-known URI by inserting `/.well-known/<suffix>` before the
// URL's path (RFC 8414 §3.1, RFC 9728 §3.1): for a bare origin the well-known
// path stands alone, for `https://host/mcp` it becomes
// `https://host/.well-known/<suffix>/mcp`.
function wellKnownUrl(raw: string, suffix: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new OAuthDiscoveryError(`not a valid URL: ${raw}`);
  }
  const path =
    parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/$/, "");
  parsed.pathname = `/.well-known/${suffix}${path}`;
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString();
}

async function getJson(
  url: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
): Promise<Response> {
  let res: Response;
  try {
    res = await fetchImpl(url, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    throw new OAuthDiscoveryError(
      `request to ${url} failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return res;
}

async function readJson(res: Response, url: string): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    throw new OAuthDiscoveryError(`endpoint ${url} returned invalid JSON.`);
  }
}

function badStatus(url: string, status: number): OAuthDiscoveryError {
  return new OAuthDiscoveryError(
    `endpoint ${url} returned status ${String(status)}.`,
  );
}

// MCP authorization spec, "Security Considerations" → "Authorization Code
// Protection": if `code_challenge_methods_supported` is absent, or present
// without S256, the client MUST refuse to proceed rather than fall back to a
// weaker challenge method.
function assertSupportsS256(
  asMetadataUrl: string,
  codeChallengeMethodsSupported: readonly string[] | undefined,
): void {
  if (
    codeChallengeMethodsSupported === undefined ||
    !codeChallengeMethodsSupported.includes("S256")
  )
    throw new OAuthDiscoveryError(
      `authorization server at ${asMetadataUrl} does not advertise PKCE S256 support (code_challenge_methods_supported).`,
    );
}

// This package only ever registers a public loopback client
// (token_endpoint_auth_method: "none"). If the server advertises auth
// methods but excludes "none", it cannot accept this client at all.
function assertSupportsPublicClients(
  asMetadataUrl: string,
  tokenEndpointAuthMethodsSupported: readonly string[] | undefined,
): void {
  if (
    tokenEndpointAuthMethodsSupported !== undefined &&
    !tokenEndpointAuthMethodsSupported.includes("none")
  )
    throw new OAuthDiscoveryError(
      `authorization server at ${asMetadataUrl} does not accept public clients (token_endpoint_auth_methods_supported omits "none").`,
    );
}

// Resolve the authorization server for a resource URL: protected-resource
// metadata first (RFC 9728), falling back to authorization-server metadata
// served directly at the resource (RFC 8414 §3.1) for servers that skip the
// protected-resource document.
export async function discoverMcpLoginEntry(
  opts: DiscoverMcpLoginEntryOptions,
): Promise<McpLoginEntry> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const resourceUrl = opts.resourceUrl;
  try {
    new URL(resourceUrl);
  } catch {
    throw new OAuthDiscoveryError(`not a valid URL: ${resourceUrl}`);
  }

  let issuer: string | undefined;
  let resourceScopesSupported: readonly string[] | undefined;
  const resourceMetadataUrl = wellKnownUrl(
    resourceUrl,
    "oauth-protected-resource",
  );
  const resourceRes = await getJson(resourceMetadataUrl, fetchImpl, timeoutMs);
  if (resourceRes.ok) {
    const payload = ProtectedResourceMetadata(
      await readJson(resourceRes, resourceMetadataUrl),
    );
    if (payload instanceof type.errors)
      throw new OAuthDiscoveryError(
        `protected-resource metadata at ${resourceMetadataUrl} is malformed: ${payload.summary}`,
      );
    if (payload.resource !== resourceUrl)
      throw new OAuthDiscoveryError(
        `protected-resource metadata resource mismatch: expected ${resourceUrl}, got ${payload.resource}.`,
      );
    issuer = payload.authorization_servers?.[0];
    if (issuer === undefined)
      throw new OAuthDiscoveryError(
        `protected-resource metadata at ${resourceMetadataUrl} names no authorization server.`,
      );
    resourceScopesSupported = payload.scopes_supported;
  } else if (resourceRes.status !== 404) {
    throw badStatus(resourceMetadataUrl, resourceRes.status);
  }

  // No protected-resource document: the resource itself may serve
  // authorization-server metadata (some MCP servers do).
  const asMetadataUrl =
    issuer === undefined
      ? wellKnownUrl(resourceUrl, "oauth-authorization-server")
      : wellKnownUrl(issuer, "oauth-authorization-server");
  const asRes = await getJson(asMetadataUrl, fetchImpl, timeoutMs);
  if (!asRes.ok) throw badStatus(asMetadataUrl, asRes.status);
  const metadata = AuthorizationServerMetadata(
    await readJson(asRes, asMetadataUrl),
  );
  if (metadata instanceof type.errors)
    throw new OAuthDiscoveryError(
      `authorization-server metadata at ${asMetadataUrl} is malformed: ${metadata.summary}`,
    );

  assertSupportsS256(asMetadataUrl, metadata.code_challenge_methods_supported);
  assertSupportsPublicClients(
    asMetadataUrl,
    metadata.token_endpoint_auth_methods_supported,
  );

  return {
    resourceUrl,
    authorizationServer: {
      issuer: metadata.issuer,
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      ...(metadata.registration_endpoint !== undefined
        ? { registrationEndpoint: metadata.registration_endpoint }
        : {}),
      ...(metadata.grant_types_supported !== undefined
        ? { grantTypesSupported: metadata.grant_types_supported }
        : {}),
      ...(metadata.scopes_supported !== undefined
        ? { scopesSupported: metadata.scopes_supported }
        : {}),
      ...(metadata.token_endpoint_auth_methods_supported !== undefined
        ? {
            tokenEndpointAuthMethodsSupported:
              metadata.token_endpoint_auth_methods_supported,
          }
        : {}),
      ...(metadata.code_challenge_methods_supported !== undefined
        ? {
            codeChallengeMethodsSupported:
              metadata.code_challenge_methods_supported,
          }
        : {}),
    },
    ...(resourceScopesSupported !== undefined
      ? { resourceScopesSupported }
      : {}),
  };
}

// RFC 7591 §3.2.1: request refresh_token only when the server's advertised
// grant_types_supported includes it, or the server didn't advertise grant
// types at all (nothing to negotiate against, so ask for what we want).
function grantTypesToRequest(
  grantTypesSupported: readonly string[] | undefined,
): string[] {
  const wantsRefresh =
    grantTypesSupported === undefined ||
    grantTypesSupported.includes("refresh_token");
  return wantsRefresh
    ? ["authorization_code", "refresh_token"]
    : ["authorization_code"];
}

// The registration response MAY echo back what was actually granted, which
// can narrow the request. Fall back to what was requested when the server
// stays silent on a field.
function grantedGrantTypes(
  echoed: string[] | undefined,
  requested: string[],
): string[] {
  return echoed ?? requested;
}

function grantedScope(
  echoed: string | undefined,
  requested: string | undefined,
): string | undefined {
  return echoed ?? requested;
}

/**
 * Register a loopback public client with the authorization server (RFC 7591).
 * Loopback clients cannot keep a secret, so registration requests
 * `token_endpoint_auth_method: "none"`. `grant_types` is negotiated from
 * `grantTypesSupported` (see grantTypesToRequest); `scope`, when supplied, is
 * carried on the registration request per RFC 7591 §2. Throws
 * OAuthDiscoveryError when the server has no registration endpoint or
 * rejects the request.
 */
export async function registerMcpClient(
  opts: RegisterMcpClientOptions,
): Promise<McpClientRegistration> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const requestedGrantTypes = grantTypesToRequest(opts.grantTypesSupported);

  let res: Response;
  try {
    res = await fetchImpl(opts.registrationEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        client_name: opts.clientName,
        redirect_uris: [...opts.redirectUris],
        grant_types: requestedGrantTypes,
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        ...(opts.scope !== undefined ? { scope: opts.scope } : {}),
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    throw new OAuthDiscoveryError(
      `registration request to ${opts.registrationEndpoint} failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = await res.text();
    } catch {
      // Non-2xx is the error; the body is optional detail.
    }
    throw new OAuthDiscoveryError(
      `registration endpoint ${opts.registrationEndpoint} returned status ${String(res.status)}${detail ? `: ${detail}` : ""}`,
    );
  }
  const payload = ClientRegistrationResponse(
    await readJson(res, opts.registrationEndpoint),
  );
  if (payload instanceof type.errors)
    throw new OAuthDiscoveryError(
      `registration endpoint ${opts.registrationEndpoint} returned a malformed response: ${payload.summary}`,
    );

  const scope = grantedScope(payload.scope, opts.scope);
  return {
    clientId: payload.client_id,
    grantTypes: grantedGrantTypes(payload.grant_types, requestedGrantTypes),
    ...(scope !== undefined ? { scope } : {}),
  };
}

// MCP authorization spec, "Scope Selection Strategy": priority order is (1)
// the `scope` parameter from a 401 WWW-Authenticate challenge, (2) all scopes
// in the protected resource's `scopes_supported`, (3) omit the scope
// parameter entirely. `offline_access` is layered on separately per the
// spec's "Refresh Tokens" section: `wantRefresh` defaults to true (this
// package always registers for refresh_token, see grantTypesToRequest), so
// offline_access is added whenever the authorization server's own
// `scopes_supported` lists it; pass `wantRefresh: false` to opt out.
export function selectMcpScopes(opts: SelectMcpScopesOptions): string[] {
  const priorityScopes = selectPriorityScopes(opts);
  return addOfflineAccessScope(priorityScopes, opts);
}

function selectPriorityScopes(opts: SelectMcpScopesOptions): string[] {
  if (opts.challengeScope !== undefined)
    return opts.challengeScope.split(" ").filter((scope) => scope.length > 0);
  const resourceScopes = opts.entry.resourceScopesSupported;
  if (resourceScopes !== undefined) return [...resourceScopes];
  return [];
}

function addOfflineAccessScope(
  scopes: string[],
  opts: SelectMcpScopesOptions,
): string[] {
  if (opts.wantRefresh === false) return scopes;
  const authServerScopes = opts.entry.authorizationServer.scopesSupported;
  if (authServerScopes === undefined) return scopes;
  if (!authServerScopes.includes("offline_access")) return scopes;
  if (scopes.includes("offline_access")) return scopes;
  return [...scopes, "offline_access"];
}

/**
 * Build the OAuth client config for a discovered entry plus a registered
 * client id. The RFC 8707 `resource` indicator binds the token to the MCP
 * server; callers pass further provider-required params through
 * `extraAuthorizeParams`. Scopes come from `selectMcpScopes` unless the
 * caller passes an explicit `scopes` override; `wantRefresh` defaults to
 * true, matching this package's default refresh_token registration request.
 */
export function mcpClientConfig(
  entry: McpLoginEntry,
  opts: McpClientConfigOptions,
): OAuthClientConfig {
  const scopes =
    opts.scopes ??
    selectMcpScopes({
      entry,
      ...(opts.challengeScope !== undefined
        ? { challengeScope: opts.challengeScope }
        : {}),
      wantRefresh: opts.wantRefresh ?? true,
    });
  return {
    clientId: opts.clientId,
    authorizeUrl: entry.authorizationServer.authorizationEndpoint,
    tokenUrl: entry.authorizationServer.tokenEndpoint,
    redirectUri: opts.redirectUri,
    scopes,
    extraAuthorizeParams: {
      resource: entry.resourceUrl,
      ...opts.extraAuthorizeParams,
    },
    tokenTimeoutMs: opts.tokenTimeoutMs ?? 30_000,
  };
}
