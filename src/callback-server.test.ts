import { describe, expect, test } from "bun:test";

import {
  OAuthCallbackAddressUnavailableError,
  OAuthCallbackPortInUseError,
  startCallbackServer,
  type CallbackServer,
} from "./index";

const config = (port: number, host?: string) => ({
  port,
  ...(host === undefined ? {} : { host }),
  path: "/callback",
  doneHtml: "<html>done</html>",
  failedHtml: (reason: string) => `<html>failed: ${reason}</html>`,
});

const getPort = (server: CallbackServer): number => {
  if (server.port === undefined) throw new Error("test server has no port");
  return server.port;
};

describe("Callback server startCallbackServer — state validation", () => {
  test.each([undefined, "127.0.0.1", "localhost", "::1"])(
    "listens on loopback host %s",
    async (host) => {
      const server = await startCallbackServer(
        "expected-state",
        config(0, host),
      );
      server.close();
    },
  );

  test("accepts a callback on the configured loopback hostname", async () => {
    const server = await startCallbackServer(
      "expected-state",
      config(0, "localhost"),
    );
    try {
      const waiting = server.waitForCode(new AbortController().signal);
      const response = await fetch(
        `http://localhost:${getPort(server)}/callback?code=some-code&state=expected-state`,
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
        startCallbackServer("expected-state", config(0, host)),
      ).rejects.toThrow(/loopback/);
    },
  );

  test("includes the configured host in port-in-use errors", async () => {
    const first = await startCallbackServer(
      "expected-state",
      config(0, "127.0.0.1"),
    );
    try {
      const error = await startCallbackServer(
        "expected-state",
        config(getPort(first), "127.0.0.1"),
      ).then(
        () => undefined,
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(OAuthCallbackPortInUseError);
      expect(error).toMatchObject({ port: getPort(first), host: "127.0.0.1" });
      expect(error).toHaveProperty(
        "message",
        expect.stringContaining("127.0.0.1"),
      );
    } finally {
      first.close();
    }
  });

  test("keeps the previous port-only error constructor compatible", () => {
    const error = new OAuthCallbackPortInUseError(1234);
    expect(error.port).toBe(1234);
    expect(error.host).toBeUndefined();
    expect(error.message).not.toContain("undefined");
  });

  test("names an unavailable address with host and port", () => {
    const error = new OAuthCallbackAddressUnavailableError(1234, "127.0.0.99");
    expect(error.name).toBe("OAuthCallbackAddressUnavailableError");
    expect(error).toMatchObject({ port: 1234, host: "127.0.0.99" });
    expect(error.message).toContain("127.0.0.99");
    expect(error.message).toContain("1234");
  });

  test("rejects a redirect whose state does not match, without trusting the code", async () => {
    // Load-bearing: the state check is what stops a redirect from an
    // unrelated flow (or an attacker's crafted link) from being accepted as
    // this login's authorization code.
    const server = await startCallbackServer("expected-state", config(0));
    try {
      const waiting = server.waitForCode(new AbortController().signal);
      const resPromise = fetch(
        `http://127.0.0.1:${getPort(server)}/callback?code=some-code&state=wrong-state`,
      );
      await expect(waiting).rejects.toThrow(/state did not match/);
      expect((await resPromise).status).toBe(400);
    } finally {
      server.close();
    }
  });
});
