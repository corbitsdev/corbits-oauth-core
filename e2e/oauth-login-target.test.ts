import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import type { TenantEnv } from "@intx/hub-api";
import { credential } from "@intx/db/schema";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

import { mountOAuthLogin, persistOAuthCredential } from "../src/hub/index.js";
import {
  createTestDb,
  plainCipher,
  seedCredential,
  seedPrincipal,
  seedProvider,
  seedTenant,
  type TestDb,
} from "./helpers.js";

const providers = {
  acme: {
    oauthConfig: {
      clientId: "client",
      authorizeUrl: "https://auth.example.com/authorize",
      tokenUrl: "https://auth.example.com/token",
      redirectUri: "http://127.0.0.1:1455/callback",
      scopes: ["openid"],
      tokenTimeoutMs: 1_000,
    },
    exchange: () => Promise.reject(new Error("not used")),
  },
};

let t: TestDb;

beforeAll(async () => {
  t = await createTestDb();
  await seedTenant(t.db, "t_parent");
  await seedTenant(t.db, "t_a", "t_parent");
  await seedTenant(t.db, "t_other");
  await seedPrincipal(t.db, "t_a", "p_a");
  await seedPrincipal(t.db, "t_a", "p_b");
  await seedProvider(t.db, "t_parent", "prov_inherited");
  await seedProvider(t.db, "t_other", "prov_foreign");
  await seedCredential(t.db, {
    id: "cred_b",
    tenantId: "t_a",
    providerId: "prov_inherited",
    principalId: "p_b",
    name: "prod-key",
    type: "oauth_token",
    secret: "b-secret",
  });
  await seedCredential(t.db, {
    id: "cred_key",
    tenantId: "t_a",
    providerId: "prov_inherited",
    principalId: "p_a",
    name: "api-key",
    type: "api_key",
    secret: "a-secret",
  });
});

afterAll(() => t.close());

function app(principalId: string) {
  const host = new Hono<TenantEnv>();
  host.use(async (c, next) => {
    const at = new Date(0);
    c.set("tenant", {
      id: "t_a",
      name: "t_a",
      slug: "t_a",
      domain: "t_a.example",
      parentId: "t_parent",
      config: null,
      createdAt: at,
      updatedAt: at,
    });
    c.set("principal", {
      id: principalId,
      tenantId: "t_a",
      kind: "user",
      refId: principalId,
      status: "active",
      createdAt: at,
      updatedAt: at,
    });
    await next();
  });
  mountOAuthLogin(host, {
    db: t.db,
    cipher: plainCipher,
    providers,
    requireGrant: async (_c, next) => {
      await next();
    },
  });
  return host;
}

function startLogin(providerId: string, credentialName: string) {
  return app("p_a").request("/oauth-logins", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ provider: "acme", providerId, credentialName }),
  });
}

describe("the OAuth login target", () => {
  it("404s a provider outside the caller's tenant chain", async () => {
    const res = await startLogin("prov_foreign", "mine");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Provider not found" });
  });

  it("409s a name owned by another principal", async () => {
    const res = await startLogin("prov_inherited", "prod-key");
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({
      error: "Credential name already exists in this tenant",
    });
  });

  it("409s a name held by a non-OAuth credential", async () => {
    const res = await startLogin("prov_inherited", "api-key");
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({
      error: "Credential name already exists in this tenant",
    });
  });

  it("never overwrites another principal's credential on persist", async () => {
    const write = persistOAuthCredential({
      db: t.db,
      cipher: plainCipher,
      tenantId: "t_a",
      principalId: "p_a",
      providerId: "prov_inherited",
      provider: "acme",
      name: "prod-key",
      scopes: ["openid"],
      tokens: { access: "new-access", refresh: "new-refresh" },
      metadata: {},
    });
    expect(write).rejects.toThrow("already exists");
    await write.catch(() => undefined);
    const row = await t.db.query.credential.findFirst({
      where: eq(credential.id, "cred_b"),
    });
    expect(row?.secret).toBe("b-secret");
  });

  it("replaces the caller's own OAuth credential in place", async () => {
    const login = (access: string) =>
      persistOAuthCredential({
        db: t.db,
        cipher: plainCipher,
        tenantId: "t_a",
        principalId: "p_a",
        providerId: "prov_inherited",
        provider: "acme",
        name: "relogin",
        scopes: ["openid"],
        tokens: { access, refresh: "refresh" },
        metadata: {},
      });
    const first = await login("first");
    expect(await login("second")).toBe(first);
  });
});
