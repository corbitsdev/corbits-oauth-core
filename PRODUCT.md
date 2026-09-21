# @corbits/oauth-core — Product

## What it is

A provider-agnostic OAuth 2.0 authorization-code login for desktop, CLI, and
Interchange hosts. The host supplies endpoints, client id, scopes, and
callback HTML. This package runs PKCE S256, a fixed-port loopback callback,
token exchange, and an expiring-token session that refreshes ahead of expiry.
The access token is the secret a harness injects as `InferenceSource.apiKey`.

Typical callers: `@corbits/xai-provider`, `@corbits/codex-provider`, and an
Interchange hub that mounts `@corbits/oauth-core/hub`.

## Why it exists

Issuer-specific login code does not belong in every provider package. Hosts
need one flow shape — public client, PKCE, loopback redirect, no client
secret — that they can point at any authorization server. Persistence is the
host's job (an OS vault, an Interchange `oauth_token` credential, or
anything else). This package owns the request shape and the session
lifecycle, not the store and not the product name.

## Who it is for

- Provider packages that mint an access token for inference.
- Desktop and CLI hosts that can bind a loopback port and open a browser.
- Interchange hubs that want a browser-driven login without shipping
  verifiers or tokens to the browser.

## What users can do

- Drive a loopback PKCE login and receive a staged profile that is not
  persisted until the host calls `commit()`.
- Exchange an authorization code and refresh an access token against
  caller-supplied token URLs.
- Resolve a still-valid access token for a named profile, with concurrent
  refreshes coalesced so a rotating refresh token is not raced.
- Mount hub login: the browser sees an authorize URL and a login id; the
  process keeps the PKCE verifier, the loopback listener, and the exchange.
  Completed tokens are written as a stock `oauth_token` credential.
- Walk those credentials ahead of expiry so running consumers keep a live
  access token.

## What it is not

- Not a vault. Tokens leave this package through host callbacks.
- Not a client for a particular issuer. No provider name, product name, or
  default endpoint lives here.
- Not MCP OAuth. Protected-resource metadata, authorization-server
  discovery, and dynamic client registration are a different product
  surface and are not part of this PKCE loopback stack.

## Goals

1. One public-client PKCE loopback shape that any host can point at an
   issuer.
2. CSRF-safe redirects (state) and intercepted-code resistance (PKCE S256).
3. Loopback-only callback binds so the cleartext authorization code never
   rides a routable interface.
4. Host-owned persistence, including cancel-before-commit.
5. Refresh that does not guess lifetimes the token endpoint omitted, and
   that coalesces in-flight work per profile.
