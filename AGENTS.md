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

The package ships TypeScript source: `exports` points at `src/index.ts`,
there is no build step and no `dist/`. Consumers install it straight from
git (`bun add github:corbitsdev/corbits-oauth-core`) and Bun runs the source
as-is, so a change here is consumable the moment it is pushed. An npm
publish, if one is ever wanted, is `npm publish --access public` on a version
bump with no other preparation.
