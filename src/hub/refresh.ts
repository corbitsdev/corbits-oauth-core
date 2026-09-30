import type { DB } from "@intx/db";
import { credential } from "@intx/db/schema";
import { credentialAad, type CredentialCipher } from "@intx/types";
import { type } from "arktype";
import { and, eq, inArray, isNotNull, lte, or, sql } from "drizzle-orm";

import {
  baseTokensFromResponse,
  OAuthTokenEndpointError,
  refreshTokenRequest,
  type BaseTokens,
} from "../index.js";
import {
  OAUTH_CLIENT_ID_METADATA_KEY,
  OAUTH_PROVIDER_METADATA_KEY,
  OAUTH_RESOURCE_METADATA_KEY,
  OAUTH_TOKEN_URL_METADATA_KEY,
  writeOAuthTokens,
} from "./credentials.js";
import type { OAuthLoginProviders } from "../provider.js";

const DEFAULT_INTERVAL_MS = 60_000;
const DEFAULT_MARGIN_MS = 10 * 60 * 1000;
const REGISTERED_CLIENT_TOKEN_TIMEOUT_MS = 30_000;

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
  /**
   * Candidates: an `oauth_token` row due by `dueBefore` that either names a
   * registered provider or carries its own client id and token URL.
   */
  listDue(
    dueBefore: Date,
    providers: readonly string[],
  ): Promise<readonly DueCredential[]>;
  /**
   * Take the row lock on one candidate and hand it to `refresh`. Returns
   * false when another hub holds the row or `refresh` declines it; true when
   * new material was written. When the provider rejects the refresh token
   * the row is marked `error`, so it is no longer due, and the rejection is
   * rethrown.
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

/**
 * A login whose client was registered dynamically stores what a refresh
 * needs on the row, so no registry entry is required to renew it.
 */
function registeredClientRefresh(
  metadata: Record<string, string>,
): ((refreshSecret: string, now: number) => Promise<BaseTokens>) | undefined {
  const clientId = metadata[OAUTH_CLIENT_ID_METADATA_KEY];
  const tokenUrl = metadata[OAUTH_TOKEN_URL_METADATA_KEY];
  const resource = metadata[OAUTH_RESOURCE_METADATA_KEY];
  if (clientId === undefined || tokenUrl === undefined) return undefined;
  return async (refreshSecret, now) =>
    baseTokensFromResponse(
      await refreshTokenRequest(
        {
          clientId,
          tokenUrl,
          tokenTimeoutMs: REGISTERED_CLIENT_TOKEN_TIMEOUT_MS,
          ...(resource !== undefined ? { resource } : {}),
        },
        refreshSecret,
      ),
      now,
      refreshSecret,
    );
}

function dueAt(expiresAt: Date | null, deadline: number): boolean {
  return expiresAt !== null && expiresAt.getTime() <= deadline;
}

// Only `invalid_grant` (RFC 6749 §5.2) means the refresh token itself is
// dead and a fresh sign-in is the fix. Everything else — 429, 408, a 401
// `invalid_client`, 5xx, network, decrypt — is retried on the next pass.
function isReauthError(error: unknown): boolean {
  if (!(error instanceof OAuthTokenEndpointError)) return false;
  try {
    const body: unknown = JSON.parse(error.detail);
    return (
      typeof body === "object" &&
      body !== null &&
      "error" in body &&
      body.error === "invalid_grant"
    );
  } catch {
    return false;
  }
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
  // A registered provider that cannot refresh leaves its credentials to a
  // sign-in. An unregistered key falls through to the row's own client.
  if (provider !== undefined && provider.refresh === undefined) {
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
      const refresh =
        provider?.refresh ?? registeredClientRefresh(row.metadata);
      if (refresh === undefined) return null;
      const tokens = await refresh(row.refreshSecret, Date.now());
      // The prior metadata is carried forward: a refresh response may omit
      // what the first exchange established (an account id, say).
      return {
        tokens,
        metadata: { ...row.metadata, ...provider?.metadata?.(tokens) },
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
    if (isReauthError(error)) {
      // Reported once: the row is now `error`, so listDue skips it.
      opts.onError?.(
        new Error(
          `credential ${due.id} refresh token rejected (invalid_grant); marked error until a new sign-in`,
        ),
        { provider: due.provider, credentialId: due.id },
      );
    }
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
  const clientIdKey = sql<string>`${credential.metadata} ->> ${OAUTH_CLIENT_ID_METADATA_KEY}`;
  const tokenUrlKey = sql<string>`${credential.metadata} ->> ${OAUTH_TOKEN_URL_METADATA_KEY}`;
  return {
    async listDue(dueBefore, providers) {
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
            or(
              providers.length === 0
                ? undefined
                : inArray(providerKey, [...providers]),
              and(isNotNull(clientIdKey), isNotNull(tokenUrlKey)),
            ),
          ),
        );
    },
    async claim(credentialId, refresh) {
      const outcome = await opts.db.transaction(async (tx) => {
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
        let result;
        try {
          result = await refresh({
            id: row.id,
            tenantId: row.tenantId,
            expiresAt: row.expiresAt,
            refreshSecret,
            metadata,
          });
        } catch (error) {
          if (!isReauthError(error)) throw error;
          // Committed, not rolled back: the row needs a sign-in either way.
          await tx
            .update(credential)
            .set({ status: "error", updatedAt: new Date() })
            .where(eq(credential.id, credentialId));
          return { rejected: error };
        }
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
      if (typeof outcome === "object") throw outcome.rejected;
      return outcome;
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
        // A "reauth" outcome is not re-reported here: a provider without
        // refresh is expected, and a rejected token was reported once by
        // refreshCredential. Anything else is retried next tick.
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
