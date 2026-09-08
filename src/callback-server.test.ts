import { describe, expect, test } from "bun:test";

import { OAuthCallbackPortInUseError, startCallbackServer } from "./index";

describe("Callback server startCallbackServer — state validation", () => {
  test("listens on the configured loopback hostname", async () => {
    const server = await startCallbackServer("expected-state", {
      port: 18235,
      host: "localhost",
      path: "/callback",
      doneHtml: "<html>done</html>",
      failedHtml: (reason) => `<html>failed: ${reason}</html>`,
    });
    try {
      const waiting = server.waitForCode(new AbortController().signal);
      const response = await fetch(
        "http://localhost:18235/callback?code=some-code&state=expected-state",
      );
      expect(response.status).toBe(200);
      await expect(waiting).resolves.toBe("some-code");
    } finally {
      server.close();
    }
  });

  test.each(["0.0.0.0", "::", "192.168.1.10"])(
    "rejects non-loopback host %s",
    async (host) => {
      await expect(
        startCallbackServer("expected-state", {
          port: 18237,
          host,
          path: "/callback",
          doneHtml: "<html>done</html>",
          failedHtml: (reason) => `<html>failed: ${reason}</html>`,
        }),
      ).rejects.toThrow(/loopback/);
    },
  );

  test("includes the configured host in port-in-use errors", async () => {
    const first = await startCallbackServer("expected-state", {
      port: 18236,
      host: "127.0.0.1",
      path: "/callback",
      doneHtml: "<html>done</html>",
      failedHtml: (reason) => `<html>failed: ${reason}</html>`,
    });
    try {
      const error = await startCallbackServer("expected-state", {
        port: 18236,
        host: "127.0.0.1",
        path: "/callback",
        doneHtml: "<html>done</html>",
        failedHtml: (reason) => `<html>failed: ${reason}</html>`,
      }).then(
        () => undefined,
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(OAuthCallbackPortInUseError);
      expect(error).toMatchObject({ port: 18236, host: "127.0.0.1" });
      expect(error).toHaveProperty(
        "message",
        expect.stringContaining("127.0.0.1"),
      );
    } finally {
      first.close();
    }
  });

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
