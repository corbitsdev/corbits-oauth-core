import { type } from "arktype";

import type { FetchLike, OAuthClientConfig } from "./client";

// Generic MCP-OAuth discovery (RFC 9728 protected-resource metadata, RFC 8414
// authorization-server metadata) plus RFC 7591 dynamic client registration.
// Nothing here names a provider: the caller supplies the MCP server's resource
// URL and gets back the endpoints plus a registered client id it can feed to
// buildAuthorizeUrl/exchangeCode. Hosts persist the client id alongside the
// tokens (see OAUTH_CLIENT_ID_METADATA_KEY in ./hub/credentials) so refresh
// keeps working after the login completes.

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
});

// RFC 8414 §2 — authorization-server metadata, narrowed to the endpoints a
// loopback PKCE login needs. `registration_endpoint` is optional: its absence
// means the server does not support dynamic registration.
const AuthorizationServerMetadata = type({
  issuer: "string",
  authorization_endpoint: "string",
  token_endpoint: "string",
  "registration_endpoint?": "string",
});

// RFC 7591 §3.2.1 — registration response, narrowed to the assigned client id.
const ClientRegistrationResponse = type({
  client_id: "string",
});

// The authorization server a protected resource points at.
export type McpAuthorizationServer = {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
};

// A login entry derived from a resource URL: everything the host needs to
// register a client and build an authorize URL, before any provider-specific
// state exists.
export type McpLoginEntry = {
  resourceUrl: string;
  authorizationServer: McpAuthorizationServer;
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
  fetchImpl?: FetchLike;
  timeoutMs?: number;
};

export type McpClientConfigOptions = {
  clientId: string;
  redirectUri: string;
  scopes?: readonly string[];
  extraAuthorizeParams?: Record<string, string>;
  tokenTimeoutMs?: number;
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

  return {
    resourceUrl,
    authorizationServer: {
      issuer: metadata.issuer,
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      ...(metadata.registration_endpoint !== undefined
        ? { registrationEndpoint: metadata.registration_endpoint }
        : {}),
    },
  };
}

/**
 * Register a loopback public client with the authorization server (RFC 7591).
 * Loopback clients cannot keep a secret, so registration requests
 * `token_endpoint_auth_method: "none"`. Throws OAuthDiscoveryError when the
 * server has no registration endpoint or rejects the request.
 */
export async function registerMcpClient(
  opts: RegisterMcpClientOptions,
): Promise<{ clientId: string }> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

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
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
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
  return { clientId: payload.client_id };
}

/**
 * Build the OAuth client config for a discovered entry plus a registered
 * client id. The RFC 8707 `resource` indicator binds the token to the MCP
 * server; callers pass further provider-required params through
 * `extraAuthorizeParams`.
 */
export function mcpClientConfig(
  entry: McpLoginEntry,
  opts: McpClientConfigOptions,
): OAuthClientConfig {
  return {
    clientId: opts.clientId,
    authorizeUrl: entry.authorizationServer.authorizationEndpoint,
    tokenUrl: entry.authorizationServer.tokenEndpoint,
    redirectUri: opts.redirectUri,
    scopes: opts.scopes ?? [],
    extraAuthorizeParams: {
      resource: entry.resourceUrl,
      ...opts.extraAuthorizeParams,
    },
    tokenTimeoutMs: opts.tokenTimeoutMs ?? 30_000,
  };
}
