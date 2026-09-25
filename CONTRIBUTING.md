# Contributing

```sh
git clone https://github.com/corbitsdev/corbits-oauth-core.git
cd corbits-oauth-core
bun install
bun run check
```

`bun run check` runs typecheck, lint, format check and tests. `bun run format` rewrites the tree.

## How it works

`startOAuthLogin` stages the exchanged profile behind `commit()`. The redirect carrying the code is cleartext HTTP on loopback. The hub entry runs the same login in-process behind `mountOAuthLogin` and writes a stock `oauth_token` credential encrypted under the host's `CredentialCipher`. `createOAuthTokenRefresher` claims due credentials with `FOR UPDATE SKIP LOCKED`, so two hubs never refresh the same credential at once.

## Commit messages

Commit subjects and PR titles follow [Conventional Commits](https://www.conventionalcommits.org): `feat`, `fix`, `refactor`, `test`, `docs`, `build`, `ci`, `perf`, and `chore(release): x.y.z` for releases.
Add `!` only for public API breaks: removed or renamed exports, changed signatures, newly required params. Peer and dependency range changes are `build(deps):` with no `!`.
Keep subjects imperative, lowercase after the colon, 72 characters or less, and free of ticket IDs.
Every PR links its issue with a `Closes <issue id>` line in the PR body.
