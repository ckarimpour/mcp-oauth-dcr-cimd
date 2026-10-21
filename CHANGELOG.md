# Changelog

## v1.0.1 — 2026-10-21

### Fixed

- **MCP SDK clients (Claude Code) can discover the authorization server behind a base path.**
  When the gateway serves only the issuer's base path, `B/.well-known/openid-configuration` is the
  one discovery URL those clients reach, and they validate it as OIDC provider metadata. v1.0.0
  omitted the OIDC-required fields, so discovery failed ("jwks_uri: expected string") and the
  client fell back to a non-existent registration URL. The metadata now includes `jwks_uri`
  (`B/oauth/jwks`, which serves an empty JWK set), `subject_types_supported: ["public"]` and
  `id_token_signing_alg_values_supported: ["RS256"]`. The gateway still issues no tokens and
  relays no ID token. Found while testing with Entra ID and Claude Code.

## v1.0.0 — 2026-10-19

First tagged release, addressing P4A catalog review round 1 (commit `ab6d5ea`).

### Security (blocking review items)

- **#1 PKCE is verified at the gateway.** The S256 `code_challenge` is sealed into the state and
  the wrapped code. `/oauth/token` requires a well-formed `code_verifier` and checks
  `BASE64URL(SHA256(verifier))` against it in constant time before calling the IdP
  (`invalid_grant` on mismatch). The verifier is still forwarded upstream.
- **#2 Requested scopes are constrained.** Without `upstreamScope`, clients may only request
  `scopesSupported` (plus `offline_access`); other scopes get `invalid_scope`. One of the two
  settings is now required. Refreshes can only narrow the granted scope. The consent page lists
  the scopes. A `resource` that isn't this MCP server is refused with `invalid_target`
  (RFC 8707), at `/oauth/authorize` and `/oauth/token`.
- **#3 Prefix redirect matching is hardened.** Dot segments (literal or percent-encoded), encoded
  slashes and backslashes are rejected in redirect URIs. Prefix entries match on parsed scheme,
  authority and path, and must be `http(s)` URLs with a host and a path ending in `/`. A bare
  `https://` is refused at configuration time.

### Fixes (follow-up review items)

- **#4** Registrations whose sealed `client_id` would exceed the open limit are refused with
  `invalid_client_metadata` instead of returning an unusable ID.
- **#5** Placeholder and low-entropy `signingSecret` values are refused. Separate MAC and
  encryption keys are derived from the secret.
- **#6** The browser-binding cookie is expired on the callback redirect.
- **#7** The IdP's `id_token` is removed from token responses. `openid-configuration` is
  documented as an OAuth metadata alias, not OIDC discovery.
- **#8** `www-authenticate` is appended to `Access-Control-Expose-Headers` instead of replacing
  it, and challenges carry a `scope` parameter.
- **#9** CIMD `client_id` URLs with percent-encoded dot segments, encoded separators or a query
  string are refused. Failed fetches are negatively cached for 30 s. Known limits (document read
  bound and refresh re-validation) are documented in `docs/spec.md`.
- **#10** The consent page shows the destination's scheme, warns about non-loopback `http`, shows
  private-use schemes correctly, and strips control and bidi characters from client names.
- **#11** Docs match the code: codes and refresh tokens are encrypted, the clock-failure status
  is documented per endpoint, and `upstreamAuthorizeUrl` must be `https` (`http` only on
  loopback).

### Breaking changes

- Existing DCR client IDs, state, codes and refresh tokens are invalidated: the MAC key is now
  derived from `signingSecret`. Clients re-register automatically.
- A configuration without `upstreamScope` or `scopesSupported`, with a placeholder signing
  secret, or with an over-broad prefix in `allowedRedirectUris` no longer loads.
