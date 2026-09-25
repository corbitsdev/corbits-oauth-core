import { describe, expect, it } from "bun:test";

import { callbackTargetFor, type OAuthClientConfig } from "./index.js";

const configFor = (redirectUri: string): OAuthClientConfig => ({
  clientId: "client",
  authorizeUrl: "https://auth.example.com/authorize",
  tokenUrl: "https://auth.example.com/token",
  redirectUri,
  scopes: ["openid"],
  tokenTimeoutMs: 1_000,
});

describe("callbackTargetFor", () => {
  it("binds the host the provider registered, not a normalized loopback", () => {
    // A provider that registered `localhost` is not interchangeable with
    // `127.0.0.1`: the authorization server matches redirect_uri literally.
    expect(
      callbackTargetFor(configFor("http://localhost:1455/auth/callback")),
    ).toEqual({ host: "localhost", port: 1455, path: "/auth/callback" });
  });

  it("refuses a redirect_uri with no explicit port", () => {
    expect(() =>
      callbackTargetFor(configFor("http://127.0.0.1/callback")),
    ).toThrow(/explicit loopback port/);
  });
});
