import type { DB } from "@intx/db";
import { credential } from "@intx/db/schema";
import { credentialAad, type CredentialCipher } from "@intx/types";
import { type } from "arktype";
import { and, eq, inArray, isNotNull, lte, sql } from "drizzle-orm";

import { OAuthTokenEndpointError, type BaseTokens } from "../index.js";
import {
  OAUTH_PROVIDER_METADATA_KEY,
  writeOAuthTokens,
} from "./credentials.js";
import type { OAuthLoginProviders } from "../provider.js";

const DEFAULT_INTERVAL_MS = 60_000;
const DEFAULT_MARGIN_MS = 10 * 60 * 1000;

/** Credential metadata is host-written JSON, so it is parsed, never asserted. */
const CredentialMetadata = type("Record<string, string>");

/** A credential the refresher holds the row lock on. */
export type ClaimedCredential = {
  readonly id: string;
  readonly tenantId: string;
  readonly expiresAt: Date | null;
  /** Decrypted: the provider's refresh call takes the token itself. */
  readonly refreshSecret: string;
  readonly metadata: Record<string, string>;
};

export type DueCredential = {
  readonly id: string;
  readonly tenantId: string;
  readonly provider: string;
};

export type OAuthRefreshStore = {
  /** Candidates: an `oauth_token` row of a registered provider, due by `dueBefore`. */
  listDue(
    dueBefore: Date,
    providers: readonly string[],
  ): Promise<readonly DueCredential[]>;
  /**
   * Take the row lock on one candidate and hand it to `refresh`. Returns
   * false when another hub holds the row or `refresh` declines it; true when
   * new material was written.
   */
  claim(
    credentialId: string,
    refresh: (row: ClaimedCredential) => Promise<{
      tokens: BaseTokens;
      metadata: Record<string, string>;
    } | null>,
  ): Promise<boolean>;
};

export type OAuthTokenRefresherOpts = {
  readonly db: DB["db"];
  readonly cipher: CredentialCipher;
  readonly providers: OAuthLoginProviders;
  readonly intervalMs?: number;
  /** How far ahead of expiry a token is refreshed; default 10 minutes. */
  readonly marginMs?: number;
  /** A refreshed credential's new material has to reach running consumers. */
  readonly onRefreshed?: (context: {
    tenantId: string;
    credentialId: string;
  }) => void | Promise<void>;
  readonly onError?: (
    error: unknown,
    context: { provider?: string; credentialId?: string },
  ) => void;
};

function dueAt(expiresAt: Date | null, deadline: number): boolean {
  return expiresAt !== null && expiresAt.getTime() <= deadline;
}

// A rejected token-endpoint call (invalid_grant and friends) means the
// refresh token itself is dead — only a fresh sign-in fixes it. Anything
// else (network, decrypt, our own bugs) is retried on the next pass.
function isReauthError(error: unknown): boolean {
  return error instanceof OAuthTokenEndpointError;
}

export type RefreshCredentialResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly reason: "reauth" | "error";
      readonly message: string;
    };

/**
 * Claim, refresh, and write one due credential. This holds the decision the
 * ticker makes on every row it walks; it is also the shape a future
 * Interchange serving-time hook would call directly for a single credential.
 */
export async function refreshCredential(
  store: OAuthRefreshStore,
  opts: Omit<OAuthTokenRefresherOpts, "db" | "cipher">,
  due: DueCredential,
): Promise<RefreshCredentialResult> {
  const marginMs = opts.marginMs ?? DEFAULT_MARGIN_MS;
  const deadline = Date.now() + marginMs;
  const provider = opts.providers[due.provider];
  const refresh = provider?.refresh;
  // A provider that cannot refresh leaves its credentials to a sign-in.
  if (provider === undefined || refresh === undefined) {
    return {
      ok: false,
      reason: "reauth",
      message: `provider "${due.provider}" has no refresh`,
    };
  }
  try {
    const written = await store.claim(due.id, async (row) => {
      // Re-checked under the lock: another hub may have renewed it since.
      if (!dueAt(row.expiresAt, deadline)) return null;
      const tokens = await refresh(row.refreshSecret, Date.now());
      // The prior metadata is carried forward: a refresh response may omit
      // what the first exchange established (an account id, say).
      return {
        tokens,
        metadata: { ...row.metadata, ...provider.metadata?.(tokens) },
      };
    });
    if (written) {
      await opts.onRefreshed?.({
        tenantId: due.tenantId,
        credentialId: due.id,
      });
    }
    return { ok: true };
  } catch (error) {
    return {
      ok: false,
      reason: isReauthError(error) ? "reauth" : "error",
      message: String(error),
    };
  }
}

/**
 * The Postgres half: candidate selection and the row claim. The claim takes
 * `FOR UPDATE SKIP LOCKED` inside the transaction that also writes the new
 * material, so two hubs ticking at once never both refresh one credential —
 * the loser skips the row rather than blocking on it.
 */
export function createOAuthRefreshStore(opts: {
  readonly db: DB["db"];
  readonly cipher: CredentialCipher;
}): OAuthRefreshStore {
  const providerKey = sql<string>`${credential.metadata} ->> ${OAUTH_PROVIDER_METADATA_KEY}`;
  return {
    async listDue(dueBefore, providers) {
      if (providers.length === 0) return [];
      return opts.db
        .select({
          id: credential.id,
          tenantId: credential.tenantId,
          provider: providerKey,
        })
        .from(credential)
        .where(
          and(
            eq(credential.type, "oauth_token"),
            eq(credential.status, "active"),
            isNotNull(credential.refreshSecret),
            isNotNull(credential.expiresAt),
            lte(credential.expiresAt, dueBefore),
            inArray(providerKey, [...providers]),
          ),
        );
    },
    async claim(credentialId, refresh) {
      return opts.db.transaction(async (tx) => {
        const [row] = await tx
          .select()
          .from(credential)
          .where(eq(credential.id, credentialId))
          .for("update", { skipLocked: true })
          .limit(1);
        if (row === undefined || row.refreshSecret === null) return false;

        const metadata = CredentialMetadata(row.metadata ?? {});
        if (metadata instanceof type.errors) {
          throw new Error(
            `credential ${credentialId} has unreadable metadata: ${metadata.summary}`,
          );
        }
        const refreshSecret = await opts.cipher.decrypt(
          row.refreshSecret,
          credentialAad(row.id, "refreshSecret"),
        );
        const result = await refresh({
          id: row.id,
          tenantId: row.tenantId,
          expiresAt: row.expiresAt,
          refreshSecret,
          metadata,
        });
        if (result === null) return false;

        await writeOAuthTokens({
          db: tx,
          cipher: opts.cipher,
          credentialId,
          tokens: result.tokens,
          metadata: result.metadata,
        });
        return true;
      });
    },
  };
}

/**
 * Refresh `oauth_token` credentials ahead of their expiry. Stock Interchange
 * has no serving-time refresh hook, so a token that lapses between uses
 * would fail the next inference call; this walks the rows on a timer instead
 * and renews them while they are still valid.
 */
export function createOAuthTokenRefresher(
  opts: OAuthTokenRefresherOpts,
): OAuthTokenRefresher {
  return createRefreshTicker(
    createOAuthRefreshStore({ db: opts.db, cipher: opts.cipher }),
    opts,
  );
}

export type OAuthTokenRefresher = { start(): void; stop(): void };

/** The timer and per-credential decisions, over any store. */
export function createRefreshTicker(
  store: OAuthRefreshStore,
  opts: Omit<OAuthTokenRefresherOpts, "db" | "cipher">,
): OAuthTokenRefresher {
  const intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
  const marginMs = opts.marginMs ?? DEFAULT_MARGIN_MS;
  let timer: ReturnType<typeof setInterval> | undefined;
  let ticking = false;
  let stopped = true;

  async function tick() {
    if (ticking) return;
    ticking = true;
    try {
      const deadline = Date.now() + marginMs;
      const due = await store.listDue(
        new Date(deadline),
        Object.keys(opts.providers),
      );
      for (const candidate of due) {
        const result = await refreshCredential(store, opts, candidate);
        // A "reauth" outcome (no refresh capability, or the provider
        // rejected the refresh token) is expected and silent — the person
        // signs in again. Anything else is worth surfacing.
        if (!result.ok && result.reason === "error") {
          opts.onError?.(new Error(result.message), {
            provider: candidate.provider,
            credentialId: candidate.id,
          });
        }
      }
    } catch (error) {
      opts.onError?.(error, {});
    } finally {
      ticking = false;
    }
  }

  return {
    start() {
      if (!stopped) return;
      stopped = false;
      // Awaited internally so a token that lapsed while the hub was down is
      // fresh before sidecars re-register; start() itself stays sync.
      void tick().finally(() => {
        if (!stopped) {
          timer = setInterval(() => void tick(), intervalMs);
        }
      });
    },
    stop() {
      stopped = true;
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
    },
  };
}
