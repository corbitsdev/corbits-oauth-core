import { describe, expect, test } from "bun:test";

import { OAuthCallbackError } from "../callback-server.js";
import { createRouteCallbacks } from "./route-callback.js";

const issuer = "https://auth.example.com";

async function started(options: {
  expectedIssuer?: string;
  requireIssuer?: boolean;
}) {
  const callbacks = createRouteCallbacks();
  const server = await callbacks.start("state-1", options);
  return { callbacks, server };
}

describe("route callback issuer binding", () => {
  test("rejects a present iss that is not the issuer recorded with the state", async () => {
    // Load-bearing: metadata that omits authorization_response_iss_parameter_supported
    // used to skip iss entirely, so a mix-up redirect carrying another issuer
    // completed the login. The issuer is bound before the code is read.
    const { callbacks, server } = await started({ expectedIssuer: issuer });
    const pending = server.waitForCode(new AbortController().signal);
    const response = callbacks.handle({
      state: "state-1",
      code: "the-code",
      error: "access_denied",
      iss: "https://other.example.com",
    });
    expect(response.status).toBe(400);
    expect(response.html).toContain("no longer the sign-in");
    expect(response.html).not.toContain("access_denied");
    await expect(pending).rejects.toBeInstanceOf(OAuthCallbackError);
  });

  test("allows a missing iss only when the server did not advertise it", async () => {
    const open = await started({ expectedIssuer: issuer });
    const openCode = open.server.waitForCode(new AbortController().signal);
    expect(
      open.callbacks.handle({
        state: "state-1",
        code: "the-code",
        error: undefined,
      }).status,
    ).toBe(200);
    expect(await openCode).toBe("the-code");

    const required = await started({
      expectedIssuer: issuer,
      requireIssuer: true,
    });
    const requiredCode = required.server.waitForCode(
      new AbortController().signal,
    );
    expect(
      required.callbacks.handle({
        state: "state-1",
        code: "the-code",
        error: undefined,
      }).status,
    ).toBe(400);
    await expect(requiredCode).rejects.toBeInstanceOf(OAuthCallbackError);
  });

  test("rejects a repeated parameter before accepting its code", async () => {
    const { callbacks, server } = await started({ expectedIssuer: issuer });
    const pending = server.waitForCode(new AbortController().signal);
    const response = callbacks.handle({
      state: "state-1",
      code: "the-code",
      error: undefined,
      iss: issuer,
      repeatedParameter: true,
    });
    expect(response.status).toBe(400);
    await expect(pending).rejects.toBeInstanceOf(OAuthCallbackError);
  });
});
