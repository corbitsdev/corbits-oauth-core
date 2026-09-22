import { describe, expect, test } from "bun:test";

import {
  buildAuthorizeUrl,
  discoverMcpLoginEntry,
  generatePkce,
  generateState,
  mcpClientConfig,
  OAuthDiscoveryError,
  registerMcpClient,
  selectMcpScopes,
  type FetchLike,
  type McpLoginEntry,
} from "./index";

const resourceUrl = "https://mcp.example.com/mcp";

const asMetadata = {
  issuer: "https://auth.example.com",
  authorization_endpoint: "https://auth.example.com/authorize",
  token_endpoint: "https://auth.example.com/token",
  registration_endpoint: "https://auth.example.com/register",
  code_challenge_methods_supported: ["S256"],
};

// Real metadata (checked 2026-09-22) from two live MCP servers, used to keep
// the negotiation logic honest against shapes actual authorization servers
// send. No provider-specific behavior lives in src — these are fixtures only.
const linearProtectedResource = {
  resource: "https://mcp.linear.app/mcp",
  authorization_servers: ["https://mcp.linear.app"],
  scopes_supported: ["read", "write"],
};
const linearAsMetadata = {
  issuer: "https://mcp.linear.app",
  authorization_endpoint: "https://mcp.linear.app/authorize",
  token_endpoint: "https://mcp.linear.app/token",
  registration_endpoint: "https://mcp.linear.app/register",
  grant_types_supported: [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
  ],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post",
    "none",
  ],
  scopes_supported: ["read", "write", "openid", "email"],
  code_challenge_methods_supported: ["S256"],
};

const granolaProtectedResource = {
  resource: "https://mcp.granola.ai/mcp",
  authorization_servers: ["https://mcp-auth.granola.ai"],
  scopes_supported: ["mcp"],
};
const granolaAsMetadata = {
  issuer: "https://mcp-auth.granola.ai",
  authorization_endpoint: "https://mcp-auth.granola.ai/oauth2/authorize",
  token_endpoint: "https://mcp-auth.granola.ai/oauth2/token",
  registration_endpoint: "https://mcp-auth.granola.ai/oauth2/register",
  grant_types_supported: [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
  ],
  token_endpoint_auth_methods_supported: [
    "none",
    "client_secret_post",
    "client_secret_basic",
    "private_key_jwt",
  ],
  scopes_supported: ["email", "offline_access", "openid", "profile"],
  code_challenge_methods_supported: ["S256"],
};

function fakeFetch(routes: Record<string, { status: number; body: unknown }>): {
  fetchImpl: FetchLike;
  requests: { url: string; init: RequestInit | undefined }[];
} {
  const requests: { url: string; init: RequestInit | undefined }[] = [];
  const impl: FetchLike = async (input, init) => {
    const url = String(input);
    requests.push({ url, init });
    const route = routes[url];
    if (route === undefined) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(route.body), {
      status: route.status,
      headers: { "content-type": "application/json" },
    });
  };
  impl.preconnect = () => undefined;
  return { fetchImpl: impl, requests };
}

describe("MCP OAuth discovery", () => {
  test("resolves a resource URL to a login entry via protected-resource metadata", async () => {
    // Load-bearing: the entry must carry the AS endpoints AND the resource
    // URL itself, because the authorize request binds the token to the
    // resource via the RFC 8707 resource indicator.
    const { fetchImpl } = fakeFetch({
      "https://mcp.example.com/.well-known/oauth-protected-resource/mcp": {
        status: 200,
        body: {
          resource: resourceUrl,
          authorization_servers: ["https://auth.example.com"],
        },
      },
      "https://auth.example.com/.well-known/oauth-authorization-server": {
        status: 200,
        body: asMetadata,
      },
    });
    const entry = await discoverMcpLoginEntry({ resourceUrl, fetchImpl });
    expect(entry.resourceUrl).toBe(resourceUrl);
    expect(entry.authorizationServer.authorizationEndpoint).toBe(
      "https://auth.example.com/authorize",
    );
    expect(entry.authorizationServer.registrationEndpoint).toBe(
      "https://auth.example.com/register",
    );
  });

  test("falls back to authorization-server metadata served at the resource", async () => {
    // Load-bearing: some MCP servers skip the protected-resource document
    // (404) and serve RFC 8414 metadata directly; discovery must not fail.
    const { fetchImpl } = fakeFetch({
      "https://mcp.example.com/.well-known/oauth-authorization-server/mcp": {
        status: 200,
        body: asMetadata,
      },
    });
    const entry = await discoverMcpLoginEntry({ resourceUrl, fetchImpl });
    expect(entry.authorizationServer.tokenEndpoint).toBe(
      "https://auth.example.com/token",
    );
  });

  test("rejects protected-resource metadata naming a different resource", async () => {
    // Load-bearing: accepting metadata for another resource would send the
    // user to authorize against the wrong server.
    const { fetchImpl } = fakeFetch({
      "https://mcp.example.com/.well-known/oauth-protected-resource/mcp": {
        status: 200,
        body: {
          resource: "https://evil.example.com/mcp",
          authorization_servers: ["https://auth.example.com"],
        },
      },
    });
    await expect(
      discoverMcpLoginEntry({ resourceUrl, fetchImpl }),
    ).rejects.toThrow(OAuthDiscoveryError);
  });

  test("fails when neither metadata document exists", async () => {
    const { fetchImpl } = fakeFetch({});
    await expect(
      discoverMcpLoginEntry({ resourceUrl, fetchImpl }),
    ).rejects.toThrow(OAuthDiscoveryError);
  });

  test("refuses an authorization server that omits code_challenge_methods_supported", async () => {
    // Load-bearing: MCP spec "Security Considerations" — absence means the
    // server does not support PKCE and the client MUST refuse to proceed
    // rather than silently skip the challenge.
    const { code_challenge_methods_supported: _unused, ...metadataWithoutPkce } =
      asMetadata;
    const { fetchImpl } = fakeFetch({
      "https://mcp.example.com/.well-known/oauth-authorization-server/mcp": {
        status: 200,
        body: metadataWithoutPkce,
      },
    });
    await expect(
      discoverMcpLoginEntry({ resourceUrl, fetchImpl }),
    ).rejects.toThrow(OAuthDiscoveryError);
  });

  test("refuses an authorization server that advertises PKCE without S256", async () => {
    // Load-bearing: the spec requires S256 specifically, not any challenge
    // method; a plain-only server must be refused, not silently downgraded.
    const { fetchImpl } = fakeFetch({
      "https://mcp.example.com/.well-known/oauth-authorization-server/mcp": {
        status: 200,
        body: { ...asMetadata, code_challenge_methods_supported: ["plain"] },
      },
    });
    await expect(
      discoverMcpLoginEntry({ resourceUrl, fetchImpl }),
    ).rejects.toThrow(OAuthDiscoveryError);
  });

  test("refuses an authorization server whose auth methods exclude public clients", async () => {
    // Load-bearing: this package only ever registers a public client
    // (token_endpoint_auth_method: none); a server that can't accept one
    // cannot serve this login flow at all.
    const { fetchImpl } = fakeFetch({
      "https://mcp.example.com/.well-known/oauth-authorization-server/mcp": {
        status: 200,
        body: {
          ...asMetadata,
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
        },
      },
    });
    await expect(
      discoverMcpLoginEntry({ resourceUrl, fetchImpl }),
    ).rejects.toThrow(OAuthDiscoveryError);
  });

  test("carries the AS's negotiation metadata and the resource's own scopes into the entry", async () => {
    const { fetchImpl } = fakeFetch({
      "https://mcp.linear.app/.well-known/oauth-protected-resource/mcp": {
        status: 200,
        body: linearProtectedResource,
      },
      "https://mcp.linear.app/.well-known/oauth-authorization-server": {
        status: 200,
        body: linearAsMetadata,
      },
    });
    const entry = await discoverMcpLoginEntry({
      resourceUrl: "https://mcp.linear.app/mcp",
      fetchImpl,
    });
    expect(entry.resourceScopesSupported).toEqual(["read", "write"]);
    expect(entry.authorizationServer.grantTypesSupported).toEqual(
      linearAsMetadata.grant_types_supported,
    );
    expect(entry.authorizationServer.scopesSupported).toEqual(
      linearAsMetadata.scopes_supported,
    );
    expect(
      entry.authorizationServer.tokenEndpointAuthMethodsSupported,
    ).toEqual(linearAsMetadata.token_endpoint_auth_methods_supported);
    expect(entry.authorizationServer.codeChallengeMethodsSupported).toEqual([
      "S256",
    ]);
  });

  test("registers a public loopback client and builds a resource-bound authorize URL", async () => {
    // Load-bearing: the registration request must ask for a public client
    // (loopback apps cannot keep a secret), and the authorize URL must carry
    // the resource indicator so the token is bound to the MCP server.
    const entry: McpLoginEntry = {
      resourceUrl,
      authorizationServer: {
        issuer: asMetadata.issuer,
        authorizationEndpoint: asMetadata.authorization_endpoint,
        tokenEndpoint: asMetadata.token_endpoint,
        registrationEndpoint: asMetadata.registration_endpoint,
      },
    };
    const { fetchImpl, requests } = fakeFetch({
      "https://auth.example.com/register": {
        status: 200,
        body: { client_id: "dyn-client-id" },
      },
    });
    const registrationEndpoint = entry.authorizationServer.registrationEndpoint;
    if (registrationEndpoint === undefined)
      throw new Error("expected a registration endpoint in the test entry");
    const { clientId } = await registerMcpClient({
      registrationEndpoint,
      redirectUris: ["http://127.0.0.1:18080/callback"],
      clientName: "Corbits",
      fetchImpl,
    });
    expect(clientId).toBe("dyn-client-id");
    const registrationBody: unknown = JSON.parse(
      String(requests[0]?.init?.body ?? "{}"),
    );
    expect(registrationBody).toMatchObject({
      token_endpoint_auth_method: "none",
    });

    const authorizeUrl = buildAuthorizeUrl(
      mcpClientConfig(entry, {
        clientId,
        redirectUri: "http://127.0.0.1:18080/callback",
      }),
      generatePkce(),
      generateState(),
    );
    const parsed = new URL(authorizeUrl);
    expect(parsed.searchParams.get("client_id")).toBe("dyn-client-id");
    expect(parsed.searchParams.get("resource")).toBe(resourceUrl);
  });

  test("surfaces a registration rejection as a discovery error", async () => {
    const { fetchImpl } = fakeFetch({
      "https://auth.example.com/register": {
        status: 400,
        body: { error: "invalid_redirect_uri" },
      },
    });
    await expect(
      registerMcpClient({
        registrationEndpoint: "https://auth.example.com/register",
        redirectUris: ["http://127.0.0.1:18080/callback"],
        clientName: "Corbits",
        fetchImpl,
      }),
    ).rejects.toThrow(OAuthDiscoveryError);
  });

  test("requests refresh_token when the AS advertises it, and omits it when the AS explicitly doesn't", async () => {
    // Load-bearing: over-requesting a grant type an AS doesn't support risks
    // outright registration rejection on strict servers; under-requesting it
    // when unadvertised loses refresh entirely for servers like Linear/Granola
    // that do support it.
    const { fetchImpl: withRefresh, requests: withRefreshRequests } =
      fakeFetch({
        "https://mcp.linear.app/register": {
          status: 200,
          body: { client_id: "linear-client" },
        },
      });
    await registerMcpClient({
      registrationEndpoint: "https://mcp.linear.app/register",
      redirectUris: ["http://127.0.0.1:18080/callback"],
      clientName: "Corbits",
      grantTypesSupported: linearAsMetadata.grant_types_supported,
      fetchImpl: withRefresh,
    });
    const withRefreshBody: unknown = JSON.parse(
      String(withRefreshRequests[0]?.init?.body ?? "{}"),
    );
    expect(withRefreshBody).toMatchObject({
      grant_types: ["authorization_code", "refresh_token"],
    });

    const { fetchImpl: withoutRefresh, requests: withoutRefreshRequests } =
      fakeFetch({
        "https://auth.example.com/register": {
          status: 200,
          body: { client_id: "no-refresh-client" },
        },
      });
    await registerMcpClient({
      registrationEndpoint: "https://auth.example.com/register",
      redirectUris: ["http://127.0.0.1:18080/callback"],
      clientName: "Corbits",
      grantTypesSupported: ["authorization_code"],
      fetchImpl: withoutRefresh,
    });
    const withoutRefreshBody: unknown = JSON.parse(
      String(withoutRefreshRequests[0]?.init?.body ?? "{}"),
    );
    expect(withoutRefreshBody).toMatchObject({
      grant_types: ["authorization_code"],
    });
  });

  test("registration echoes back what was granted, falling back to the request when silent", async () => {
    // Load-bearing: RFC 7591 §3.2.1 lets the server narrow the request; a
    // host persisting "what was granted" must see the echoed value, not just
    // assume the request stuck.
    const { fetchImpl: echoed } = fakeFetch({
      "https://auth.example.com/register": {
        status: 200,
        body: {
          client_id: "echo-client",
          grant_types: ["authorization_code"],
          scope: "read",
        },
      },
    });
    const echoedResult = await registerMcpClient({
      registrationEndpoint: "https://auth.example.com/register",
      redirectUris: ["http://127.0.0.1:18080/callback"],
      clientName: "Corbits",
      scope: "read write",
      fetchImpl: echoed,
    });
    expect(echoedResult.grantTypes).toEqual(["authorization_code"]);
    expect(echoedResult.scope).toBe("read");

    const { fetchImpl: silent } = fakeFetch({
      "https://auth.example.com/register": {
        status: 200,
        body: { client_id: "silent-client" },
      },
    });
    const silentResult = await registerMcpClient({
      registrationEndpoint: "https://auth.example.com/register",
      redirectUris: ["http://127.0.0.1:18080/callback"],
      clientName: "Corbits",
      scope: "read write",
      fetchImpl: silent,
    });
    expect(silentResult.grantTypes).toEqual(["authorization_code", "refresh_token"]);
    expect(silentResult.scope).toBe("read write");
  });

  test("registration omits scope from the request when none was given, and from the result when none was echoed", async () => {
    const { fetchImpl, requests } = fakeFetch({
      "https://auth.example.com/register": {
        status: 200,
        body: { client_id: "no-scope-client" },
      },
    });
    const result = await registerMcpClient({
      registrationEndpoint: "https://auth.example.com/register",
      redirectUris: ["http://127.0.0.1:18080/callback"],
      clientName: "Corbits",
      fetchImpl,
    });
    const body: unknown = JSON.parse(String(requests[0]?.init?.body ?? "{}"));
    expect(body).not.toHaveProperty("scope");
    expect(result.scope).toBeUndefined();
  });
});

describe("selectMcpScopes", () => {
  test("prefers the WWW-Authenticate challenge scope over the resource's scopes_supported", () => {
    // Load-bearing: MCP spec "Scope Selection Strategy" priority order —
    // the challenge is authoritative for the current operation even when it
    // disagrees with scopes_supported.
    const entry: McpLoginEntry = {
      resourceUrl: linearProtectedResource.resource,
      authorizationServer: {
        issuer: linearAsMetadata.issuer,
        authorizationEndpoint: linearAsMetadata.authorization_endpoint,
        tokenEndpoint: linearAsMetadata.token_endpoint,
        scopesSupported: linearAsMetadata.scopes_supported,
      },
      resourceScopesSupported: linearProtectedResource.scopes_supported,
    };
    expect(
      selectMcpScopes({ entry, challengeScope: "read" }),
    ).toEqual(["read"]);
  });

  test("falls back to the resource's scopes_supported when there is no challenge", () => {
    const entry: McpLoginEntry = {
      resourceUrl: linearProtectedResource.resource,
      authorizationServer: {
        issuer: linearAsMetadata.issuer,
        authorizationEndpoint: linearAsMetadata.authorization_endpoint,
        tokenEndpoint: linearAsMetadata.token_endpoint,
        scopesSupported: linearAsMetadata.scopes_supported,
      },
      resourceScopesSupported: linearProtectedResource.scopes_supported,
    };
    expect(selectMcpScopes({ entry })).toEqual(["read", "write"]);
  });

  test("omits the scope parameter when neither a challenge nor scopes_supported is available", () => {
    const entry: McpLoginEntry = {
      resourceUrl,
      authorizationServer: {
        issuer: asMetadata.issuer,
        authorizationEndpoint: asMetadata.authorization_endpoint,
        tokenEndpoint: asMetadata.token_endpoint,
      },
    };
    expect(selectMcpScopes({ entry })).toEqual([]);
  });

  test("adds offline_access when refresh is wanted and the AS advertises it (Granola shape)", () => {
    // Load-bearing: Granola's AS scopes_supported includes offline_access;
    // wanting a refresh token should add it per the spec's Refresh Tokens
    // section, without the caller having to know the literal scope name.
    const entry: McpLoginEntry = {
      resourceUrl: granolaProtectedResource.resource,
      authorizationServer: {
        issuer: granolaAsMetadata.issuer,
        authorizationEndpoint: granolaAsMetadata.authorization_endpoint,
        tokenEndpoint: granolaAsMetadata.token_endpoint,
        scopesSupported: granolaAsMetadata.scopes_supported,
      },
      resourceScopesSupported: granolaProtectedResource.scopes_supported,
    };
    expect(selectMcpScopes({ entry, wantRefresh: true })).toEqual([
      "mcp",
      "offline_access",
    ]);
  });

  test("does not add offline_access when the AS doesn't advertise it (Linear shape)", () => {
    // Load-bearing: Linear's AS scopes_supported has no offline_access;
    // adding it anyway would send a scope the server never agreed to.
    const entry: McpLoginEntry = {
      resourceUrl: linearProtectedResource.resource,
      authorizationServer: {
        issuer: linearAsMetadata.issuer,
        authorizationEndpoint: linearAsMetadata.authorization_endpoint,
        tokenEndpoint: linearAsMetadata.token_endpoint,
        scopesSupported: linearAsMetadata.scopes_supported,
      },
      resourceScopesSupported: linearProtectedResource.scopes_supported,
    };
    expect(selectMcpScopes({ entry, wantRefresh: true })).toEqual([
      "read",
      "write",
    ]);
  });
});

describe("mcpClientConfig scope selection", () => {
  test("uses selectMcpScopes by default", () => {
    const entry: McpLoginEntry = {
      resourceUrl: granolaProtectedResource.resource,
      authorizationServer: {
        issuer: granolaAsMetadata.issuer,
        authorizationEndpoint: granolaAsMetadata.authorization_endpoint,
        tokenEndpoint: granolaAsMetadata.token_endpoint,
        scopesSupported: granolaAsMetadata.scopes_supported,
      },
      resourceScopesSupported: granolaProtectedResource.scopes_supported,
    };
    const config = mcpClientConfig(entry, {
      clientId: "client",
      redirectUri: "http://127.0.0.1:18080/callback",
      wantRefresh: true,
    });
    expect(config.scopes).toEqual(["mcp", "offline_access"]);
  });

  test("an explicit scopes option overrides selectMcpScopes", () => {
    const entry: McpLoginEntry = {
      resourceUrl: granolaProtectedResource.resource,
      authorizationServer: {
        issuer: granolaAsMetadata.issuer,
        authorizationEndpoint: granolaAsMetadata.authorization_endpoint,
        tokenEndpoint: granolaAsMetadata.token_endpoint,
        scopesSupported: granolaAsMetadata.scopes_supported,
      },
      resourceScopesSupported: granolaProtectedResource.scopes_supported,
    };
    const config = mcpClientConfig(entry, {
      clientId: "client",
      redirectUri: "http://127.0.0.1:18080/callback",
      scopes: ["custom"],
      wantRefresh: true,
    });
    expect(config.scopes).toEqual(["custom"]);
  });
});
