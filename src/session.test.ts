import { describe, expect, test } from "bun:test";

import { createTokenSession, type BaseTokens } from "./index";

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
});
