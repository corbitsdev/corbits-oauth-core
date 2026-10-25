import { describe, expect, test } from "bun:test";

import {
  baseTokensFromResponse,
  buildAuthorizeUrl,
  exchangeCode,
  OAuthTokenEndpointError,
  OAuthTokenResponseSchemaError,
  type FetchLike,
  type OAuthClientConfig,
} from "./index.js";
import { generatePkce } from "./pkce.js";

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

  test("wraps a non-JSON 2xx body in the schema error", async () => {
    const html: FetchLike = async () =>
      new Response("<html>gateway</html>", { status: 200 });
    html.preconnect = () => undefined;
    await expect(
      exchangeCode(config, "auth-code", "verifier", html),
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

  test("accepts an access token with no refresh token instead of inventing one", () => {
    // Load-bearing: some grants never issue a refresh token. Throwing here
    // rejects a valid token response; storing a fabricated refresh token
    // would later be presented to the authorization server.
    const tokens = baseTokensFromResponse(
      { access_token: "access-only" },
      0,
      undefined,
    );
    expect(tokens.access).toBe("access-only");
    expect(tokens.refresh).toBeUndefined();
  });
});

describe("buildAuthorizeUrl — protected parameters", () => {
  test("ignores extras that would replace PKCE, state, or the client fields", () => {
    // Load-bearing: extraAuthorizeParams are caller-controlled. Applied
    // after the protected fields, they could point the code exchange at a
    // challenge the caller does not hold or swap the CSRF state.
    const pkce = generatePkce();
    const url = new URL(
      buildAuthorizeUrl(
        {
          ...config,
          scopes: ["openid"],
          resource: "https://mcp.example.com/mcp",
          extraAuthorizeParams: {
            state: "attacker-state",
            code_challenge: "attacker-challenge",
            code_challenge_method: "plain",
            client_id: "other-client",
            redirect_uri: "https://evil.example/callback",
            response_type: "token",
            scope: "admin",
            resource: "https://evil.example/resource",
            prompt: "consent",
          },
        },
        pkce,
        "real-state",
      ),
    );
    expect(url.searchParams.get("state")).toBe("real-state");
    expect(url.searchParams.get("code_challenge")).toBe(pkce.challenge);
    expect(url.searchParams.get("code_challenge_method")).toBe(pkce.method);
    expect(url.searchParams.get("client_id")).toBe(config.clientId);
    expect(url.searchParams.get("redirect_uri")).toBe(config.redirectUri);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid");
    expect(url.searchParams.get("resource")).toBe(
      "https://mcp.example.com/mcp",
    );
    expect(url.searchParams.get("prompt")).toBe("consent");
  });

  test("omits scope when the caller has none", () => {
    const url = new URL(
      buildAuthorizeUrl({ ...config, scopes: [] }, generatePkce(), "state-1"),
    );
    expect(url.searchParams.has("scope")).toBe(false);
  });
});

describe("token endpoint — redirects and error bodies", () => {
  test("does not follow a redirect or copy its body into the error", async () => {
    // Load-bearing: the POST body holds the code or refresh token. Following
    // a 307 replays that secret at Location, and echoing the body can put a
    // token into logs.
    let calls = 0;
    let redirect: RequestInit["redirect"];
    const impl: FetchLike = async (_input, init) => {
      calls += 1;
      redirect = init?.redirect;
      return new Response("secret-refresh-token", {
        status: 307,
        headers: {
          location: "https://evil.example/collect?token=secret-refresh-token",
        },
      });
    };
    impl.preconnect = () => undefined;
    const error = await exchangeCode(
      config,
      "auth-code",
      "verifier",
      impl,
    ).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(calls).toBe(1);
    expect(redirect).toBe("manual");
    expect(error).toBeInstanceOf(OAuthTokenEndpointError);
    expect(String(error)).not.toContain("secret-refresh-token");
    expect(String(error)).not.toContain("evil.example");
    expect(String(error)).toContain("redirect_refused");
  });

  test("keeps only the oauth error code from a non-2xx body", async () => {
    const error = await exchangeCode(
      config,
      "auth-code",
      "verifier",
      fakeFetch(
        {
          error: "invalid_grant",
          error_description: "leaked-access-token",
        },
        400,
      ),
    ).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(error).toBeInstanceOf(OAuthTokenEndpointError);
    expect(String(error)).toContain("invalid_grant");
    expect(String(error)).not.toContain("leaked-access-token");
  });
});
