import { createServer } from "node:net";

import { describe, expect, it, test } from "bun:test";

import {
  callbackTargetFor,
  loginWithProvider,
  type BaseTokens,
  type OAuthClientConfig,
  type OAuthLoginProvider,
} from "./index.js";

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  await new Promise((resolve) => server.close(resolve));
  if (address === null || typeof address === "string") {
    throw new Error("no TCP address");
  }
  return address.port;
}

describe("loginWithProvider", () => {
  test("binds the provider's redirect_uri, exchanges the code, and saves before returning", async () => {
    const port = await freePort();
    // Load-bearing: the helper derives every login dependency from the
    // provider. A wrong callback target or a skipped save only shows up as a
    // login that hangs or a profile that is gone on the next run.
    const tokens: BaseTokens = {
      access: "access-1",
      refresh: "refresh-1",
      expiresAt: 10_000,
    };
    const exchanged: string[] = [];
    const provider: OAuthLoginProvider = {
      oauthConfig: {
        clientId: "client",
        authorizeUrl: "https://auth.example/authorize",
        tokenUrl: "https://auth.example/token",
        redirectUri: `http://127.0.0.1:${String(port)}/cb`,
        scopes: ["openid"],
        tokenTimeoutMs: 1_000,
      },
      exchange: async (code) => {
        exchanged.push(code);
        return tokens;
      },
    };
    const saved: string[] = [];
    let callback: Promise<Response> | undefined;

    const done = loginWithProvider(provider, {
      profile: "work",
      signal: AbortSignal.timeout(5_000),
      save: async (profile) => {
        saved.push(profile.name);
      },
      openInBrowser: (url) => {
        const state = new URL(url).searchParams.get("state") ?? "";
        callback = fetch(
          `http://127.0.0.1:${String(port)}/cb?code=the-code&state=${state}`,
        );
      },
    });
    const profile = await done;
    expect((await callback)?.status).toBe(200);
    expect(profile.tokens).toEqual(tokens);
    expect(exchanged).toEqual(["the-code"]);
    expect(saved).toEqual(["work"]);
  });
});

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
