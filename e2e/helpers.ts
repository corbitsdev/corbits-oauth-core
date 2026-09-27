import { createDB, dropSchema, runMigrations, type DB } from "@intx/db";
import { credential, principal, provider, tenant } from "@intx/db/schema";
import type { CredentialCipher } from "@intx/types";

const DATABASE_URL =
  process.env.DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/postgres";

function configFor(schema: string) {
  const url = new URL(DATABASE_URL);
  return {
    host: url.hostname,
    port: Number(url.port || 5432),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: url.pathname.slice(1),
    schema,
  };
}

export type TestDb = { db: DB["db"]; close: () => Promise<void> };

/** A migrated Interchange schema of its own, dropped on close. */
export async function createTestDb(): Promise<TestDb> {
  const config = configFor(
    `oauth_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
  );
  await runMigrations(config, { schema: config.schema });
  const handle = createDB(config);
  return {
    db: handle.db,
    close: async () => {
      await handle.close();
      await dropSchema(config, { schema: config.schema });
    },
  };
}

/** Reversible, not secret: the tests only check what was written where. */
export const plainCipher: CredentialCipher = {
  encrypt: (plaintext, aad) => Promise.resolve(`${aad}|${plaintext}`),
  decrypt: (blob, aad) => {
    if (!blob.startsWith(`${aad}|`)) throw new Error("aad mismatch");
    return Promise.resolve(blob.slice(aad.length + 1));
  },
};

export async function seedTenant(
  db: DB["db"],
  id: string,
  parentId: string | null = null,
): Promise<void> {
  await db.insert(tenant).values({
    id,
    name: id,
    slug: id,
    domain: `${id}.example`,
    parentId,
  });
}

export async function seedPrincipal(
  db: DB["db"],
  tenantId: string,
  id: string,
): Promise<void> {
  await db
    .insert(principal)
    .values({ id, tenantId, kind: "user", refId: id, status: "active" });
}

export async function seedProvider(
  db: DB["db"],
  tenantId: string,
  id: string,
): Promise<void> {
  await db.insert(provider).values({ id, tenantId, name: id, plugin: "oauth" });
}

export async function seedCredential(
  db: DB["db"],
  row: {
    id: string;
    tenantId: string;
    providerId: string;
    principalId: string | null;
    name: string;
    type: "api_key" | "oauth_token";
    secret: string;
  },
): Promise<void> {
  await db.insert(credential).values(row);
}
