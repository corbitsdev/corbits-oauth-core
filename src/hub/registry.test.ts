import { describe, expect, it } from "bun:test";

import { callbackTargetFor } from "./registry";

const base = {
  clientId: "client",
  authorizeUrl: "https://auth.example.com/authorize",
  tokenUrl: "https://auth.example.com/token",
  scopes: ["openid"],
  tokenTimeoutMs: 1_000,
};

describe("callbackTargetFor", () => {
  it("binds the host the provider registered, not a normalized loopback", () => {
    // A provider that registered `localhost` is not interchangeable with
    // `127.0.0.1`: the authorization server matches redirect_uri literally.
    expect(
      callbackTargetFor({
        ...base,
        redirectUri: "http://localhost:1455/auth/callback",
      }),
    ).toEqual({ host: "localhost", port: 1455, path: "/auth/callback" });
  });

  it("refuses a redirect_uri with no explicit port", () => {
    expect(() =>
      callbackTargetFor({
        ...base,
        redirectUri: "http://127.0.0.1/callback",
      }),
    ).toThrow(/explicit loopback port/);
  });
});
