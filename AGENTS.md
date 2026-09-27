# AGENTS.md

## Purpose

`@corbits/oauth-core` is the PKCE + loopback login that an Interchange host
uses to mint the secret the harness injects as `InferenceSource.apiKey`. It
owns the request shape and session lifecycle (refresh-ahead, coalesced
in-flight refresh). It does not persist credentials — that is the host
(Interchange `oauth_token` or OS vault). It never owns an endpoint, client
id, or product name.

## Layout

- `src/pkce.ts` — PKCE verifier/challenge and CSRF state generation.
- `src/client.ts` — `OAuthClientConfig`, authorize URL building, token
  endpoint calls, response validation.
- `src/callback-server.ts` — the fixed-port loopback server and its state
  check.
- `src/tokens.ts` — `BaseTokens` / `AuthProfile` shapes.
- `src/session.ts` — `createTokenSession`, the refresh-ahead-of-expiry logic.
- `src/browser.ts` — best-effort browser launch.
- `src/login.ts` — `startOAuthLogin`, wiring the above into one flow.
- `src/provider.ts` — `OAuthLoginProvider` and `loginWithProvider`, which
  builds the login deps from a provider and saves the result.
- `src/index.ts` — the only module consumers import from.
- `src/*.test.ts` — tests next to the module they cover.

## Rules

- Parse every trust boundary with arktype; never `as T` untrusted input.
- `exactOptionalPropertyTypes` is on — omit optional keys, never assign
  `undefined` to them.
- No branding baked in: no provider name, product name, or default that
  names one. Endpoints, client id, and callback HTML are caller-supplied.
- No credential storage in this package.
- Tests exist only for a named, load-bearing risk (see each test's comment).
  No coverage theater.

## Local development

```sh
bun install
bun run check   # typecheck + lint + format:check + test
```

## Distribution

The package ships compiled `dist/` on npm as `@corbits/oauth-core`:
`exports` points at `dist/index.js` (types at `dist/index.d.ts`), plus
`./hub` at `dist/hub/index.js`, built with `bun run build` (`tsc -p
tsconfig.build.json`) via the `prepack` hook. Consumers install the
published package (`bun add @corbits/oauth-core` or `npm install
@corbits/oauth-core`) on Bun >= 1.2 or Node.js >= 24, both of which load
the compiled output. A release is a version bump followed by
`npm publish --access public`, with `dist/` built automatically by
`prepack`.
