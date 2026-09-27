import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { credential } from "@intx/db/schema";
import { credentialAad } from "@intx/types";
import { eq } from "drizzle-orm";

import { OAuthTokenEndpointError } from "../src/index.js";
import {
  createOAuthRefreshStore,
  createOAuthTokenRefresher,
} from "../src/hub/index.js";
import {
  createTestDb,
  plainCipher,
  seedPrincipal,
  seedProvider,
  seedTenant,
  type TestDb,
} from "./helpers.js";

let t: TestDb;

beforeAll(async () => {
  t = await createTestDb();
  await seedTenant(t.db, "t_a");
  await seedPrincipal(t.db, "t_a", "p_a");
  await seedProvider(t.db, "t_a", "prov");
});

afterAll(() => t.close());

async function seedDue(id: string): Promise<void> {
  await t.db.insert(credential).values({
    id,
    tenantId: "t_a",
    providerId: "prov",
    principalId: "p_a",
    name: id,
    type: "oauth_token",
    secret: await plainCipher.encrypt("access", credentialAad(id, "secret")),
    refreshSecret: await plainCipher.encrypt(
      "refresh",
      credentialAad(id, "refreshSecret"),
    ),
    expiresAt: new Date(Date.now() - 60_000),
    metadata: { oauthProvider: id },
  });
}

/** One tick of a refresher whose only provider answers with `status`. */
async function tickWith(
  id: string,
  status: number,
  detail: string,
): Promise<unknown[]> {
  const errors: unknown[] = [];
  let calls = 0;
  const refresher = createOAuthTokenRefresher({
    db: t.db,
    cipher: plainCipher,
    providers: {
      [id]: {
        oauthConfig: {
          clientId: "client",
          authorizeUrl: "https://auth.example.com/authorize",
          tokenUrl: "https://auth.example.com/token",
          redirectUri: "http://127.0.0.1:1455/callback",
          scopes: ["openid"],
          tokenTimeoutMs: 1_000,
        },
        exchange: () => Promise.reject(new Error("not used")),
        refresh: () => {
          calls += 1;
          return Promise.reject(new OAuthTokenEndpointError(status, detail));
        },
      },
    },
    onError: (error) => errors.push(error),
  });
  refresher.start();
  refresher.stop();
  for (let i = 0; i < 100 && calls === 0; i += 1) await Bun.sleep(10);
  await Bun.sleep(50);
  return errors;
}

async function statusOf(id: string): Promise<string | undefined> {
  const row = await t.db.query.credential.findFirst({
    where: eq(credential.id, id),
  });
  return row?.status;
}

const oauthError = (error: string) => JSON.stringify({ error });

describe("the OAuth token refresher", () => {
  it("marks a credential whose refresh token is rejected as needing a sign-in", async () => {
    await seedDue("dead");
    const errors = await tickWith("dead", 400, oauthError("invalid_grant"));
    expect(errors).toHaveLength(1);
    expect(String(errors[0])).toContain("invalid_grant");
    expect(await statusOf("dead")).toBe("error");
    const due = await createOAuthRefreshStore({
      db: t.db,
      cipher: plainCipher,
    }).listDue(new Date(), ["dead"]);
    expect(due).toEqual([]);
  });

  it.each([
    ["flaky", 503, "upstream down"],
    ["limited", 429, oauthError("slow_down")],
    ["timeout", 408, ""],
    ["badclient", 401, oauthError("invalid_client")],
  ])(
    "reports %s (%i) and keeps the credential due",
    async (id, status, detail) => {
      await seedDue(id);
      const errors = await tickWith(id, status, detail);
      expect(errors).toHaveLength(1);
      expect(String(errors[0])).toContain(String(status));
      expect(await statusOf(id)).toBe("active");
    },
  );
});
