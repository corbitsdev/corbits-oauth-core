import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import type { TenantEnv } from "@intx/hub-api";
import { credential, grant } from "@intx/db/schema";
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
  await seedTenant(t.db, "tparent");
  await seedTenant(t.db, "ta", "tparent");
  await seedTenant(t.db, "tother");
  await seedPrincipal(t.db, "ta", "p_a");
  await seedPrincipal(t.db, "ta", "p_b");
  await seedProvider(t.db, "tparent", "prov_inherited");
  await seedProvider(t.db, "tother", "prov_foreign");
  await seedCredential(t.db, {
    id: "cred_b",
    tenantId: "ta",
    providerId: "prov_inherited",
    principalId: "p_b",
    name: "prod-key",
    type: "oauth_token",
    secret: "b-secret",
  });
  await seedCredential(t.db, {
    id: "cred_key",
    tenantId: "ta",
    providerId: "prov_inherited",
    principalId: "p_a",
    name: "api-key",
    type: "api_key",
    secret: "a-secret",
  });
});

afterAll(() => t.close());

function app(principalId: string, owner?: "tenant") {
  const host = new Hono<TenantEnv>();
  host.use(async (c, next) => {
    const at = new Date(0);
    c.set("tenant", {
      id: "ta",
      name: "ta",
      slug: "ta",
      domain: "ta.example",
      parentId: "tparent",
      config: null,
      createdAt: at,
      updatedAt: at,
    });
    c.set("principal", {
      id: principalId,
      tenantId: "ta",
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
    ...(owner !== undefined ? { owner } : {}),
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
      tenantId: "ta",
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
        tenantId: "ta",
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

  // Interchange resolves only an organizational credential (principalId
  // null) for a catalog model provider, so a tenant-owned login must land
  // with no principal, and must not be replaceable by a personal one.
  describe("owned by the tenant", () => {
    const persistAs = (
      name: string,
      principalId: string,
      access: string,
      owner?: "tenant",
    ) =>
      persistOAuthCredential({
        db: t.db,
        cipher: plainCipher,
        tenantId: "ta",
        principalId,
        providerId: "prov_inherited",
        provider: "acme",
        name,
        scopes: ["openid"],
        tokens: { access, refresh: "refresh" },
        metadata: {},
        ...(owner !== undefined ? { owner } : {}),
      });

    it("stores no principal and no creator grant", async () => {
      const id = await persistAs("shared", "p_a", "first", "tenant");
      const row = await t.db.query.credential.findFirst({
        where: eq(credential.id, id),
      });
      expect(row?.principalId).toBeNull();
      const grants = await t.db.query.grant.findMany({
        where: eq(grant.resource, `credential:${id}`),
      });
      expect(grants).toEqual([]);
    });

    it("never replaces an existing name, so a login cannot take over an org credential", async () => {
      const id = await persistAs("org", "p_a", "first", "tenant");
      await expect(persistAs("org", "p_b", "second", "tenant")).rejects.toThrow(
        "already exists",
      );
      await expect(persistAs("org", "p_a", "third")).rejects.toThrow(
        "already exists",
      );
      const row = await t.db.query.credential.findFirst({
        where: eq(credential.id, id),
      });
      expect(row?.secret).toEndWith("|first");
    });

    it("stores a mount's completed login with no principal", async () => {
      const host = new Hono<TenantEnv>();
      host.use(async (c, next) => {
        const at = new Date(0);
        c.set("tenant", {
          id: "ta",
          name: "ta",
          slug: "ta",
          domain: "ta.example",
          parentId: "tparent",
          config: null,
          createdAt: at,
          updatedAt: at,
        });
        c.set("principal", {
          id: "p_a",
          tenantId: "ta",
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
        providers: {
          granting: {
            oauthConfig: {
              ...providers.acme.oauthConfig,
              redirectUri: "http://127.0.0.1:1457/callback",
            },
            exchange: () => Promise.resolve({ access: "minted", refresh: "r" }),
          },
        },
        requireGrant: async (_c, next) => {
          await next();
        },
        owner: "tenant",
      });
      const started = await host.request("/oauth-logins", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          provider: "granting",
          providerId: "prov_inherited",
          credentialName: "mounted",
        }),
      });
      expect(started.status).toBe(201);
      const { loginId, authorizeUrl } = (await started.json()) as {
        loginId: string;
        authorizeUrl: string;
      };
      const state = new URL(authorizeUrl).searchParams.get("state");
      await fetch(`http://127.0.0.1:1457/callback?code=c&state=${state}`);
      let polled: { status?: string; credentialId?: string } = {};
      for (let i = 0; i < 50 && polled.status !== "completed"; i++) {
        polled = (await (
          await host.request(`/oauth-logins/${loginId}`)
        ).json()) as typeof polled;
        if (polled.status !== "completed") await Bun.sleep(20);
      }
      expect(polled.status).toBe("completed");
      const row = await t.db.query.credential.findFirst({
        where: eq(credential.id, polled.credentialId ?? ""),
      });
      expect(row?.principalId).toBeNull();
      expect(row?.secret).toEndWith("|minted");
    });
  });
});
