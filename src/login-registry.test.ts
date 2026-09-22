import { describe, expect, test } from "bun:test";

import {
  createLoginRegistry,
  type BaseTokens,
  type OAuthLoginHandle,
  type StagedOAuthProfile,
} from "./index";

type Settle = {
  readonly handle: OAuthLoginHandle<BaseTokens>;
  readonly finish: () => void;
  readonly fail: (cause: Error) => void;
};

/** A login handle whose completion the test drives. */
function stubLogin(authorizeUrl: string, onCancel?: () => void): Settle {
  let finish!: () => void;
  let fail!: (cause: Error) => void;
  const completed = new Promise<StagedOAuthProfile<BaseTokens>>((_, reject) => {
    fail = reject;
    finish = () => {
      reject(new Error("completed"));
    };
  });
  return {
    handle: {
      authorizeUrl,
      completed,
      cancel: () => onCancel?.(),
    },
    finish,
    fail,
  };
}

describe("createLoginRegistry", () => {
  test("a second start for the same key resumes the login in flight", async () => {
    const registry = createLoginRegistry();
    const first = stubLogin("https://auth.example/authorize?state=first");
    let starts = 0;

    const begun = await registry.startOrResume("codex", () => {
      starts += 1;
      return Promise.resolve(first.handle);
    });
    const again = await registry.startOrResume("codex", () => {
      starts += 1;
      return Promise.resolve(
        stubLogin("https://auth.example/authorize?state=second").handle,
      );
    });

    // One attempt, so one state and one PKCE pair: the authorize page already
    // open still matches what the loopback expects.
    expect(starts).toBe(1);
    expect(again.resumed).toBe(true);
    expect(again.handle.authorizeUrl).toBe(begun.handle.authorizeUrl);
  });

  test("a login started by someone else is not resumed for another tag", async () => {
    const registry = createLoginRegistry();
    let starts = 0;
    const begin = (url: string) => () => {
      starts += 1;
      return Promise.resolve(stubLogin(url).handle);
    };

    await registry.startOrResume("codex", begin("https://auth.example/a"), {
      tag: "tenant:alice",
    });
    const other = await registry.startOrResume(
      "codex",
      begin("https://auth.example/b"),
      {
        tag: "tenant:bob",
      },
    );

    expect(starts).toBe(2);
    expect(other.resumed).toBe(false);
  });

  test("a settled login is not resumed; the next start is a new one", async () => {
    const registry = createLoginRegistry();
    const first = stubLogin("https://auth.example/a");

    await registry.startOrResume("codex", () => Promise.resolve(first.handle));
    first.fail(new Error("authorization failed"));
    // Let the registry observe the rejection before asking again.
    await Promise.resolve();
    await Promise.resolve();

    expect(registry.has("codex")).toBe(false);
    const next = await registry.startOrResume("codex", () =>
      Promise.resolve(stubLogin("https://auth.example/b").handle),
    );
    expect(next.resumed).toBe(false);
  });

  test("cancelling releases the key and cancels the login", async () => {
    const registry = createLoginRegistry();
    let cancelled = 0;
    const first = stubLogin("https://auth.example/a", () => {
      cancelled += 1;
    });

    await registry.startOrResume("codex", () => Promise.resolve(first.handle));
    expect(registry.cancel("codex")).toBe(true);

    expect(cancelled).toBe(1);
    expect(registry.has("codex")).toBe(false);
    expect(registry.cancel("codex")).toBe(false);
  });
});
