import type { DB } from "@intx/db";
import { credential, grant as grantTable } from "@intx/db/schema";
import { generateId } from "@intx/hub-common";
import { credentialAad, type CredentialCipher } from "@intx/types";
import { eq } from "drizzle-orm";

import type { BaseTokens } from "../index";

export type PersistOAuthCredentialOpts = {
  readonly db: DB["db"];
  readonly cipher: CredentialCipher;
  readonly tenantId: string;
  readonly principalId: string;
  /** The stock `provider` row the credential hangs off; the host mints it. */
  readonly providerId: string;
  readonly name: string;
  readonly scopes: readonly string[];
  readonly tokens: BaseTokens;
  readonly metadata: Record<string, string>;
};

/**
 * Store freshly-minted OAuth tokens as a stock Interchange `oauth_token`
 * credential — the same row shape, AAD-bound encryption and creator grant
 * the platform's own `POST /credentials` writes, so nothing downstream can
 * tell a login-minted credential from a hand-entered one. Re-logging in
 * under the same name replaces the secrets in place rather than colliding
 * on the per-tenant unique name.
 */
export async function persistOAuthCredential(
  opts: PersistOAuthCredentialOpts,
): Promise<string> {
  const existing = await opts.db.query.credential.findFirst({
    where: (row, { and, eq }) =>
      and(eq(row.tenantId, opts.tenantId), eq(row.name, opts.name)),
  });

  const now = new Date();
  const credentialId = existing?.id ?? generateId("credential");
  const secret = await opts.cipher.encrypt(
    opts.tokens.access,
    credentialAad(credentialId, "secret"),
  );
  const refreshSecret = await opts.cipher.encrypt(
    opts.tokens.refresh,
    credentialAad(credentialId, "refreshSecret"),
  );
  const expiresAt =
    opts.tokens.expiresAt === undefined
      ? null
      : new Date(opts.tokens.expiresAt);

  if (existing !== undefined) {
    await opts.db
      .update(credential)
      .set({
        providerId: opts.providerId,
        type: "oauth_token",
        secret,
        refreshSecret,
        scopes: [...opts.scopes],
        expiresAt,
        status: "active",
        metadata: opts.metadata,
        updatedAt: now,
      })
      .where(eq(credential.id, credentialId));
    return credentialId;
  }

  await opts.db.transaction(async (tx) => {
    await tx.insert(credential).values({
      id: credentialId,
      tenantId: opts.tenantId,
      providerId: opts.providerId,
      principalId: opts.principalId,
      oauthClientId: null,
      name: opts.name,
      type: "oauth_token",
      description: null,
      secret,
      refreshSecret,
      scopes: [...opts.scopes],
      expiresAt,
      metadata: opts.metadata,
      createdAt: now,
      updatedAt: now,
    });
    // Mirrors the stock route: a personal credential grants its owner
    // durable `use` authority so no separate manual grant is needed.
    await tx.insert(grantTable).values({
      id: generateId("grant"),
      tenantId: opts.tenantId,
      principalId: opts.principalId,
      resource: `credential:${credentialId}`,
      action: "use",
      effect: "allow",
      origin: "creator",
      expiresAt: null,
      createdAt: now,
      updatedAt: now,
    });
  });

  return credentialId;
}
