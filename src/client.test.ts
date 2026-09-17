import { describe, expect, test } from "bun:test";

import {
  baseTokensFromResponse,
  exchangeCode,
  OAuthTokenResponseSchemaError,
  type FetchLike,
  type OAuthClientConfig,
} from "./index";

const config: OAuthClientConfig = {
  clientId: "client-id",
  authorizeUrl: "https://auth.example.com/authorize",
  tokenUrl: "https://auth.example.com/token",
  redirectUri: "http://127.0.0.1:1455/callback",
  scopes: ["openid"],
  tokenTimeoutMs: 1_000,
};

function fakeFetch(payload: unknown, status = 200): FetchLike {
  const impl: FetchLike = async (_input, _init) =>
    new Response(JSON.stringify(payload), {
      status,
      headers: { "content-type": "application/json" },
    });
  impl.preconnect = () => undefined;
  return impl;
}

describe("OAuth client — hostile token responses", () => {
  test("rejects a malformed expires_in instead of letting a NaN expiry through", async () => {
    // Load-bearing: checking only that access_token is a string lets
    // `expires_in: "soon"` survive into a NaN expiry that never compares as
    // expired, so a session would hold a token that can never refresh.
    await expect(
      exchangeCode(
        config,
        "auth-code",
        "verifier",
        fakeFetch({
          access_token: "tok",
          refresh_token: "ref",
          expires_in: "soon",
        }),
      ),
    ).rejects.toThrow(OAuthTokenResponseSchemaError);
  });

  test("carries the prior refresh token forward when a refresh response omits one", () => {
    // Load-bearing: providers may or may not rotate refresh tokens on
    // refresh; dropping the prior one whenever a response omits it would
    // strand the session with no way to refresh again.
    const tokens = baseTokensFromResponse(
      { access_token: "a" },
      0,
      "prior-refresh",
    );
    expect(tokens.refresh).toBe("prior-refresh");
  });

  test("leaves expiresAt unset when the server omits expires_in, rather than guessing a lifetime", () => {
    // Load-bearing: RFC 6749 §5.1 makes expires_in RECOMMENDED, not
    // required. Falling back to a made-up lifetime would let a session
    // treat a token as fresh well past whatever the server actually issued.
    const tokens = baseTokensFromResponse(
      { access_token: "a", refresh_token: "r" },
      1_000,
      undefined,
    );
    expect(tokens.expiresAt).toBeUndefined();
  });
});
