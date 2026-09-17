import { describe, expect, test } from "bun:test";

import { startOAuthLogin, type BaseTokens, type CallbackServer } from "./index";

function fakeCallbackServer(code: string): CallbackServer & { closed: number } {
  const server = {
    closed: 0,
    waitForCode: async () => code,
    close: () => {
      server.closed += 1;
    },
  };
  return server;
}

describe("OAuth login startOAuthLogin — staging and commit", () => {
  test("does not persist until commit, and coalesces a second commit into the same write", async () => {
    // Load-bearing: the host must be able to show the staged profile and let
    // the user cancel without writing tokens. Persisting inside `completed`
    // would make cancel a no-op after the browser round-trip. A second
    // commit() sharing the in-flight write is what stops a double-click from
    // racing two saves against a store that is not idempotent.
    const saves: {
      name: string;
      tokens: BaseTokens;
      createdAt: number;
    }[] = [];
    const server = fakeCallbackServer("auth-code");
    const tokens: BaseTokens = {
      access: "access-1",
      refresh: "refresh-1",
      expiresAt: 10_000,
    };

    const handle = await startOAuthLogin(
      {
        profile: "acct",
        signal: new AbortController().signal,
        now: () => 1234,
      },
      {
        startCallbackServer: async () => server,
        buildAuthorizeUrl: () => "https://auth.example.com/authorize",
        exchangeCode: async () => tokens,
        saveProfile: async (profile) => {
          saves.push(profile);
        },
        openInBrowser: () => undefined,
      },
    );

    const staged = await handle.completed;
    expect(saves).toEqual([]);
    expect(server.closed).toBe(1);
    expect(staged.profile).toEqual({
      name: "acct",
      tokens,
      createdAt: 1234,
    });

    await Promise.all([staged.commit(), staged.commit()]);
    expect(saves).toEqual([{ name: "acct", tokens, createdAt: 1234 }]);
  });
});
