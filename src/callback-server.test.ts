import { describe, expect, test } from "bun:test";

import { startCallbackServer } from "./index";

describe("Callback server startCallbackServer — state validation", () => {
  test("rejects a redirect whose state does not match, without trusting the code", async () => {
    // Load-bearing: the state check is what stops a redirect from an
    // unrelated flow (or an attacker's crafted link) from being accepted as
    // this login's authorization code.
    const server = await startCallbackServer("expected-state", {
      port: 18234,
      path: "/callback",
      doneHtml: "<html>done</html>",
      failedHtml: (reason) => `<html>failed: ${reason}</html>`,
    });
    try {
      const waiting = server.waitForCode(new AbortController().signal);
      const resPromise = fetch(
        `http://127.0.0.1:18234/callback?code=some-code&state=wrong-state`,
      );
      await expect(waiting).rejects.toThrow(/state did not match/);
      expect((await resPromise).status).toBe(400);
    } finally {
      server.close();
    }
  });
});
