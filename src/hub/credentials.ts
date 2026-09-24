import type { DB } from "@intx/db";
import { credential, grant as grantTable } from "@intx/db/schema";
import { generateId } from "@intx/hub-common";
import { credentialAad, type CredentialCipher } from "@intx/types";
import { eq } from "drizzle-orm";

import type { BaseTokens } from "../index.js";

/**
 * Credential-metadata key naming the registered provider the tokens were
 * minted by. The stock `provider` row a credential hangs off is host-named
 * and per-tenant, so it cannot identify a registry entry; this key can, and
 * it is what the refresher matches a credential against.
 */
export const OAUTH_PROVIDER_METADATA_KEY = "oauthProvider";

/** Everything the token writes below need — a `db` or an open transaction. */
export type OAuthCredentialWriter = Pick<DB["db"], "update">;

export type WriteOAuthTokensOpts = {
  readonly db: OAuthCredentialWriter;
  readonly cipher: CredentialCipher;
  readonly credentialId: string;
  readonly tokens: BaseTokens;
  readonly metadata: Record<string, string>;
  readonly scopes?: readonly string[];
  readonly providerId?: string;
};

/**
 * Write token material onto an existing credential row: both secrets are
 * sealed under the AAD the platform's own read path expects. Login and
 * refresh share this one write so a refreshed row is indistinguishable from
 * a freshly signed-in one.
 */
export async function writeOAuthTokens(
  opts: WriteOAuthTokensOpts,
): Promise<void> {
  const secret = await opts.cipher.encrypt(
    opts.tokens.access,
    credentialAad(opts.credentialId, "secret"),
  );
  const refreshSecret = await opts.cipher.encrypt(
    opts.tokens.refresh,
    credentialAad(opts.credentialId, "refreshSecret"),
  );
  await opts.db
    .update(credential)
    .set({
      ...(opts.providerId !== undefined ? { providerId: opts.providerId } : {}),
      ...(opts.scopes !== undefined ? { scopes: [...opts.scopes] } : {}),
      type: "oauth_token",
      secret,
      refreshSecret,
      expiresAt:
        opts.tokens.expiresAt === undefined
          ? null
          : new Date(opts.tokens.expiresAt),
      status: "active",
      metadata: opts.metadata,
      updatedAt: new Date(),
    })
    .where(eq(credential.id, opts.credentialId));
}

export type PersistOAuthCredentialOpts = {
  readonly db: DB["db"];
  readonly cipher: CredentialCipher;
  readonly tenantId: string;
  readonly principalId: string;
  /** The stock `provider` row the credential hangs off; the host mints it. */
  readonly providerId: string;
  /** The registered provider key, recorded so a refresher can find it again. */
  readonly provider: string;
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
  const metadata = {
    ...opts.metadata,
    [OAUTH_PROVIDER_METADATA_KEY]: opts.provider,
  };

  if (existing !== undefined) {
    await writeOAuthTokens({
      db: opts.db,
      cipher: opts.cipher,
      credentialId,
      tokens: opts.tokens,
      metadata,
      scopes: opts.scopes,
      providerId: opts.providerId,
    });
    return credentialId;
  }

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
      metadata,
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
