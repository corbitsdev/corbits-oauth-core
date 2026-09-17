import type { BaseTokens } from "./tokens";

/**
 * Whether `tokens` is at or within `skewMs` of its expiry at `now`.
 *
 * `expiresAt` is absent when the token endpoint omitted `expires_in` (RFC
 * 6749 §5.1 makes it RECOMMENDED, not required). With no stated lifetime, a
 * token of unknown age is treated as not expired: it is used until the
 * server rejects it. Refreshing eagerly instead would rotate the refresh
 * token (on a provider that rotates it every use) on every single call.
 */
export function isTokenExpired(
  tokens: BaseTokens,
  now: number,
  skewMs: number,
): boolean {
  return tokens.expiresAt !== undefined && now >= tokens.expiresAt - skewMs;
}

// A named profile had no tokens.
export class OAuthProfileNotFoundError extends Error {
  constructor(name: string) {
    super(`No OAuth profile named "${name}".`);
    this.name = "OAuthProfileNotFoundError";
  }
}

// A stored refresh token failed to mint a new access token.
export class OAuthRefreshFailedError extends Error {
  constructor(name: string, cause: unknown) {
    super(`Refreshing the OAuth profile "${name}" failed.`, { cause });
    this.name = "OAuthRefreshFailedError";
  }
}

// Dependencies for createTokenSession, all injectable for testing.
export type TokenSessionDeps<TTokens extends BaseTokens, TAccess> = {
  skewMs: number;
  loadProfile: (name: string) => Promise<{ tokens: TTokens } | undefined>;
  updateTokens: (name: string, tokens: TTokens) => Promise<void>;
  refreshTokens: (refreshToken: string, now: number) => Promise<TTokens>;
  // Project stored tokens into the access shape returned to callers.
  toAccess: (tokens: TTokens) => TAccess;
  // Merge when a refresh response omits fields the caller wants carried forward.
  mergeRefreshed?: (refreshed: TTokens, previous: TTokens) => TTokens;
};

export type TokenSession<TTokens extends BaseTokens, TAccess> = {
  isExpired: (tokens: TTokens, now: number) => boolean;
  getValidToken: (name: string, now?: number) => Promise<TAccess>;
};

/**
 * Resolve a valid access token for a named profile, refreshing transparently
 * when the stored token is at or near expiry. Multiple concurrent calls for
 * the same profile coalesce into a single refresh; the rest observe the
 * result of that one call rather than racing the authorization server's
 * refresh-token rotation policy.
 */
export function createTokenSession<TTokens extends BaseTokens, TAccess>(
  deps: TokenSessionDeps<TTokens, TAccess>,
): TokenSession<TTokens, TAccess> {
  const inflightRefresh = new Map<string, Promise<TAccess>>();

  const isExpired = (tokens: TTokens, now: number): boolean =>
    isTokenExpired(tokens, now, deps.skewMs);

  async function doRefresh(name: string, now: number): Promise<TAccess> {
    const profile = await deps.loadProfile(name);
    if (profile === undefined) throw new OAuthProfileNotFoundError(name);
    // Re-check expiry after the I/O; another caller may have refreshed already.
    if (!isExpired(profile.tokens, now)) return deps.toAccess(profile.tokens);
    let refreshed: TTokens;
    try {
      refreshed = await deps.refreshTokens(profile.tokens.refresh, now);
    } catch (err) {
      throw new OAuthRefreshFailedError(name, err);
    }
    const merged =
      deps.mergeRefreshed !== undefined
        ? deps.mergeRefreshed(refreshed, profile.tokens)
        : refreshed;
    await deps.updateTokens(name, merged);
    return deps.toAccess(merged);
  }

  async function getValidToken(
    name: string,
    now: number = Date.now(),
  ): Promise<TAccess> {
    const existingProfile = await deps.loadProfile(name);
    if (existingProfile === undefined)
      throw new OAuthProfileNotFoundError(name);
    if (!isExpired(existingProfile.tokens, now))
      return deps.toAccess(existingProfile.tokens);

    // Deduplicate via the in-flight map so concurrent callers share the same
    // refresh rather than racing.
    const pending = inflightRefresh.get(name);
    if (pending !== undefined) return pending;

    const refreshPromise = doRefresh(name, now);
    inflightRefresh.set(name, refreshPromise);
    // Clean up regardless of outcome so a subsequent call after a failure
    // can retry rather than returning the cached error. .then(cleanup,
    // cleanup) instead of .finally() avoids an abandoned promise chain
    // whose pass-through rejection could become an unhandled rejection —
    // callers catch the original refreshPromise.
    const cleanup = (): void => {
      if (inflightRefresh.get(name) === refreshPromise)
        inflightRefresh.delete(name);
    };
    refreshPromise.then(cleanup, cleanup);

    return refreshPromise;
  }

  return { isExpired, getValidToken };
}
