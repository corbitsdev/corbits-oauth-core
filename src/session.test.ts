import { describe, expect, test } from "bun:test";

import {
  createTokenSession,
  OAuthMissingRefreshTokenError,
  OAuthRefreshFailedError,
  type BaseTokens,
} from "./index.js";

describe("Token session createTokenSession — refresh coalescing", () => {
  test("coalesces concurrent refreshes for the same profile into one request", async () => {
    // Load-bearing: two callers racing a refresh against a provider that
    // rotates refresh tokens would otherwise invalidate one attempt.
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let refreshCount = 0;
    const stored: { tokens: BaseTokens } = {
      tokens: { access: "old", refresh: "ref", expiresAt: 1_000 },
    };
    const session = createTokenSession<BaseTokens, string>({
      skewMs: 100,
      loadProfile: async () => stored,
      updateTokens: async (_name, tokens) => {
        stored.tokens = tokens;
      },
      refreshTokens: async () => {
        refreshCount += 1;
        await gate;
        return { access: "new", refresh: "ref2", expiresAt: 10_000 };
      },
      toAccess: (tokens) => tokens.access,
    });
    const first = session.getValidToken("p", 2_000);
    const second = session.getValidToken("p", 2_000);
    release?.();
    expect(await Promise.all([first, second])).toEqual(["new", "new"]);
    expect(refreshCount).toBe(1);
  });

  test("uses an access-token-only grant until it expires, then asks for a new login", async () => {
    // Load-bearing: a grant with no refresh token is still a usable access
    // token. Refreshing it would require a refresh token this session does
    // not have, so expiry is a reauthorization, not a token request.
    let refreshCount = 0;
    const stored: { tokens: BaseTokens } = { tokens: { access: "only" } };
    const session = createTokenSession<BaseTokens, string>({
      skewMs: 0,
      loadProfile: async () => stored,
      updateTokens: async () => undefined,
      refreshTokens: async () => {
        refreshCount += 1;
        return { access: "should-not-run" };
      },
      toAccess: (tokens) => tokens.access,
    });
    expect(await session.getValidToken("p", 500)).toBe("only");
    stored.tokens = { access: "only", expiresAt: 1_000 };
    const expiredError = await session.getValidToken("p", 1_000).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(expiredError).toBeInstanceOf(OAuthRefreshFailedError);
    expect(
      expiredError instanceof OAuthRefreshFailedError
        ? expiredError.cause
        : undefined,
    ).toBeInstanceOf(OAuthMissingRefreshTokenError);
    expect(refreshCount).toBe(0);
  });
});
