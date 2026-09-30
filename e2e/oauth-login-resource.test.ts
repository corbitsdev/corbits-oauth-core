import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import type { TenantEnv } from "@intx/hub-api";
import { credential } from "@intx/db/schema";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

import type { FetchLike } from "../src/index.js";
import {
  createOAuthLoginStore,
  mountOAuthCallback,
  mountOAuthLogin,
  OAUTH_CLIENT_ID_METADATA_KEY,
  OAUTH_PROVIDER_METADATA_KEY,
  OAUTH_RESOURCE_METADATA_KEY,
  OAUTH_TOKEN_URL_METADATA_KEY,
} from "../src/hub/index.js";
import {
  createTestDb,
  plainCipher,
  seedPrincipal,
  seedProvider,
  seedTenant,
  type TestDb,
} from "./helpers.js";

const resourceUrl = "https://mcp.example.com/mcp";
const callbackUrl = "https://hub.example.com/api/oauth/callback";

/** A fake MCP server and authorization server behind one `fetch`. */
function fakeAuthorizationServer(
  grantTypesSupported?: string[],
  issParameterSupported = false,
) {
  const registrations: unknown[] = [];
  const tokenRequests: URLSearchParams[] = [];
  const json = (body: unknown, status = 200) =>
    Promise.resolve(Response.json(body, { status }));
  const fetchImpl: FetchLike = Object.assign(
    async (input: Parameters<FetchLike>[0], init?: RequestInit) => {
      const url = String(input);
      if (
        url ===
        "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
      )
        return json({
          resource: resourceUrl,
          authorization_servers: ["https://auth.example.com"],
        });
      if (
        url ===
        "https://auth.example.com/.well-known/oauth-authorization-server"
      )
        return json({
          issuer: "https://auth.example.com",
          authorization_endpoint: "https://auth.example.com/authorize",
          token_endpoint: "https://auth.example.com/token",
          registration_endpoint: "https://auth.example.com/register",
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: issParameterSupported,
          ...(grantTypesSupported !== undefined
            ? { grant_types_supported: grantTypesSupported }
            : {}),
        });
      if (url === "https://auth.example.com/register") {
        registrations.push(JSON.parse(String(init?.body)));
        return json({ client_id: "dyn-client" });
      }
      if (url === "https://auth.example.com/token") {
        tokenRequests.push(new URLSearchParams(String(init?.body)));
        return json({
          access_token: "access-1",
          refresh_token: "refresh-1",
          expires_in: 3600,
        });
      }
      return new Response("not found", { status: 404 });
    },
    { preconnect: () => undefined },
  );
  return { fetchImpl, registrations, tokenRequests };
}

let t: TestDb;

beforeAll(async () => {
  t = await createTestDb();
  await seedTenant(t.db, "t_a");
  await seedPrincipal(t.db, "t_a", "p_a");
  await seedProvider(t.db, "t_a", "prov_a");
});

afterAll(() => t.close());

function app(fetchImpl: FetchLike) {
  const store = createOAuthLoginStore();
  const root = new Hono();
  mountOAuthCallback(root, { store, path: "/api/oauth/callback" });
  const host = new Hono<TenantEnv>();
  host.use(async (c, next) => {
    const at = new Date(0);
    c.set("tenant", {
      id: "t_a",
      name: "t_a",
      slug: "t_a",
      domain: "t_a.example",
      parentId: null,
      config: null,
      createdAt: at,
      updatedAt: at,
    });
    c.set("principal", {
      id: "p_a",
      tenantId: "t_a",
      kind: "user",
      refId: "p_a",
      status: "active",
      createdAt: at,
      updatedAt: at,
    });
    await next();
  });
  mountOAuthLogin(host, {
    db: t.db,
    cipher: plainCipher,
    providers: {},
    callbackUrl,
    store,
    fetchImpl,
    requireGrant: async (_c, next) => {
      await next();
    },
  });
  // The tenant scope sits beside the root callback, as it does on a hub.
  root.route("/", host);
  return root;
}

async function settled(
  host: Hono,
  loginId: string,
): Promise<{ status: string; credentialId?: string; message?: string }> {
  let status: { status: string; credentialId?: string; message?: string } = {
    status: "pending",
  };
  for (let i = 0; i < 50 && status.status === "pending"; i++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    status = (await (
      await host.request(`/oauth-logins/${loginId}`)
    ).json()) as typeof status;
  }
  return status;
}

function post(host: Hono, body: unknown) {
  return host.request("/oauth-logins", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("a login started from a resource URL", () => {
  it("registers a client, completes through the mount's callback, and stores a refreshable credential", async () => {
    const as = fakeAuthorizationServer();
    const host = app(as.fetchImpl);
    const started = await post(host, {
      resourceUrl,
      providerId: "prov_a",
      credentialName: "remote",
    });
    expect(started.status).toBe(201);
    const { loginId, authorizeUrl } = (await started.json()) as {
      loginId: string;
      authorizeUrl: string;
    };

    expect(as.registrations[0]).toMatchObject({
      redirect_uris: [callbackUrl],
      grant_types: ["authorization_code", "refresh_token"],
    });
    const authorize = new URL(authorizeUrl);
    expect(authorize.searchParams.get("client_id")).toBe("dyn-client");
    expect(authorize.searchParams.get("redirect_uri")).toBe(callbackUrl);
    expect(authorize.searchParams.get("resource")).toBe(resourceUrl);

    const state = authorize.searchParams.get("state") ?? "";
    const stale = await host.request(`/api/oauth/callback?code=x&state=nope`);
    expect(stale.status).toBe(400);
    const callback = await host.request(
      `/api/oauth/callback?code=the-code&state=${state}`,
    );
    expect(callback.status).toBe(200);
    expect(callback.headers.get("cache-control")).toBe("no-store");
    expect(callback.headers.get("referrer-policy")).toBe("no-referrer");
    // Single use: the same state cannot complete a second time.
    const replay = await host.request(
      `/api/oauth/callback?code=again&state=${state}`,
    );
    expect(replay.status).toBe(400);

    const status = await settled(host, loginId);
    expect(status.status).toBe("completed");
    expect(as.tokenRequests[0]?.get("code")).toBe("the-code");
    expect(as.tokenRequests[0]?.get("redirect_uri")).toBe(callbackUrl);
    expect(as.tokenRequests[0]?.get("code_verifier")).toBeTruthy();
    // RFC 8707: the token request names the resource, not just the authorize request.
    expect(as.tokenRequests[0]?.get("resource")).toBe(resourceUrl);

    const row = await t.db.query.credential.findFirst({
      where: eq(credential.id, status.credentialId ?? ""),
    });
    expect(row?.metadata).toEqual({
      [OAUTH_PROVIDER_METADATA_KEY]: "https://mcp.example.com",
      [OAUTH_CLIENT_ID_METADATA_KEY]: "dyn-client",
      [OAUTH_TOKEN_URL_METADATA_KEY]: "https://auth.example.com/token",
      [OAUTH_RESOURCE_METADATA_KEY]: resourceUrl,
    });
  });

  it("does not ask for refresh_token from a server that advertises only the code grant", async () => {
    const as = fakeAuthorizationServer(["authorization_code"]);
    const res = await post(app(as.fetchImpl), {
      resourceUrl,
      providerId: "prov_a",
      credentialName: "remote-3",
    });
    expect(res.status).toBe(201);
    expect(as.registrations[0]).toMatchObject({
      grant_types: ["authorization_code"],
    });
  });

  it("rejects a redirect whose iss is not the discovered issuer (RFC 9207)", async () => {
    // Load-bearing: without this check a second authorization server that
    // learned the state could complete the login with its own code.
    const as = fakeAuthorizationServer(undefined, true);
    const host = app(as.fetchImpl);
    const started = await post(host, {
      resourceUrl,
      providerId: "prov_a",
      credentialName: "remote-4",
    });
    const { loginId, authorizeUrl } = (await started.json()) as {
      loginId: string;
      authorizeUrl: string;
    };
    const state = new URL(authorizeUrl).searchParams.get("state") ?? "";
    const forged = await host.request(
      `/api/oauth/callback?code=x&state=${state}&iss=${encodeURIComponent("https://other.example.com")}`,
    );
    expect(forged.status).toBe(400);
    expect((await settled(host, loginId)).status).toBe("failed");
    expect(as.tokenRequests).toHaveLength(0);
  });

  it("refuses a cleartext callbackUrl off loopback", () => {
    expect(() =>
      mountOAuthLogin(new Hono<TenantEnv>(), {
        db: t.db,
        cipher: plainCipher,
        providers: {},
        callbackUrl: "http://hub.example.com/api/oauth/callback",
        store: createOAuthLoginStore(),
        requireGrant: async (_c, next) => {
          await next();
        },
      }),
    ).toThrow(/https/);
  });

  it("surfaces a server without dynamic registration as a 502", async () => {
    const as = fakeAuthorizationServer();
    const noRegistration: FetchLike = Object.assign(
      async (input: Parameters<FetchLike>[0], init?: RequestInit) => {
        const res = await as.fetchImpl(input, init);
        if (
          String(input) !==
          "https://auth.example.com/.well-known/oauth-authorization-server"
        )
          return res;
        const { registration_endpoint: _omit, ...rest } =
          (await res.json()) as Record<string, unknown>;
        return Response.json(rest);
      },
      { preconnect: () => undefined },
    );
    const res = await post(app(noRegistration), {
      resourceUrl,
      providerId: "prov_a",
      credentialName: "remote-2",
    });
    expect(res.status).toBe(502);
  });
});
