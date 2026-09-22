import { describe, expect, test } from "bun:test";

import {
  buildAuthorizeUrl,
  discoverMcpLoginEntry,
  generatePkce,
  generateState,
  mcpClientConfig,
  OAuthDiscoveryError,
  registerMcpClient,
  type FetchLike,
  type McpLoginEntry,
} from "./index";

const resourceUrl = "https://mcp.example.com/mcp";

const asMetadata = {
  issuer: "https://auth.example.com",
  authorization_endpoint: "https://auth.example.com/authorize",
  token_endpoint: "https://auth.example.com/token",
  registration_endpoint: "https://auth.example.com/register",
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
});
