# MCP OAuth Client Registration (DCR + CIMD)

MCP clients (MCP spec 2025-11-25) discover an authorization server from the MCP server, then
register themselves either with Dynamic Client Registration (RFC 7591) or by presenting an HTTPS
`client_id` that points at a Client ID Metadata Document (CIMD,
draft-ietf-oauth-client-id-metadata-document). Most enterprise IdPs support neither.

This policy makes the gateway an **OAuth authorization-server facade** in front of the real IdP:

- it serves protected-resource (RFC 9728) and authorization-server (RFC 8414) metadata,
- it accepts DCR and CIMD clients,
- it brokers the authorization-code + PKCE flow to **one** application pre-registered at the IdP,
- it keeps **no server-side state**: client IDs, `state`, codes and refresh tokens are
  HMAC-sealed values, so it works on any number of replicas without Redis.

Access tokens are minted by the real IdP and validated by a separate policy (JWT Validation or
OAuth 2.0 Token Introspection) placed **after** this one.

## Configuration

See `definition/gcl.yaml` for every property. Invariants checked at configure time
(the policy refuses to load otherwise):

- `publicBaseUrl` is an absolute `https://` URL (or `http://` on a loopback host, for the local
  playground) with no query, fragment or trailing slash.
- `mcpResourcePath` starts with `/`.
- `signingSecret` is at least 32 characters, is not a placeholder (e.g. contains `change_me`,
  `generate`, `example`), has at least 12 distinct characters and an estimated ≥ 128 bits of
  entropy. Generate it with `openssl rand -base64 48`.
- `upstreamAuthorizeUrl` is `https` (or `http` on loopback), without credentials or fragment.
- `upstreamScope` or `scopesSupported` is set, and every `scopesSupported` entry is a valid scope
  token. Client-requested scopes never pass through unrestricted.
- Every `allowedRedirectUris` prefix entry (ending in `/`) is an `http(s)` URL with a host, no
  credentials, query or dot segments; exact entries are valid redirect URIs.
- `upstreamClientSecret` is set unless `upstreamClientAuthMethod` is `none`.
- At least one of `enableDcr` / `enableCimd` is true.
- If `enableDcr`, at least one redirect source exists (`allowLoopbackRedirects` or a non-empty
  `allowedRedirectUris`).
- Every `cimdTrustedHosts` entry is an `https` origin, and `enableCimd` requires at least one.
- `cimdCacheTtlSeconds` and `clientRegistrationTtlSeconds` are not negative.

## Behavior

`B` is the path of `publicBaseUrl` (the API base path). Paths are matched after removing the query
string and any trailing `/`.

### Request flow

| Method + path | Action |
|---|---|
| `OPTIONS` on a metadata, register or token path | 204 CORS preflight |
| `GET B/.well-known/oauth-protected-resource[B-relative MCP path]` | RFC 9728 metadata |
| `GET B/.well-known/oauth-authorization-server`, `GET B/.well-known/openid-configuration` | RFC 8414 metadata |
| `GET B/oauth/jwks` | empty JWK set (`{"keys":[]}`) |
| `POST B/oauth/register` | DCR (if enabled) |
| `GET B/oauth/authorize` | validate client, consent page (or 302 to IdP) |
| `GET B/oauth/callback` | 302 back to the MCP client |
| `POST B/oauth/token` | redeem code / refresh token at IdP |
| anything else, no `Authorization` header, `challengeUnauthenticated` | 401 with `resource_metadata` |
| anything else | continue untouched |

Root-level path-insertion forms (`/.well-known/oauth-authorization-server` + `B`, etc.) are also
answered, so the same policy works when applied to an API mounted at `/`.

`B/.well-known/openid-configuration` serves the same document, as a discovery alias for MCP
clients that try the OIDC path. When the gateway serves only `B`, it is the one discovery URL those
clients can reach, and MCP SDK clients (Claude Code among them) validate it as OIDC provider
metadata. So the document also carries the three OIDC-required fields: `jwks_uri`
(`B/oauth/jwks`, an empty JWK set), `subject_types_supported: ["public"]` and
`id_token_signing_alg_values_supported: ["RS256"]` (OIDC Discovery requires RS256). This server
still issues no tokens of its own: access tokens are the IdP's, and no ID token is ever returned
(see Token).

### Response flow

If `challengeUnauthenticated` and the response status is 401, append
`resource_metadata="<PRM URL>"` to the `WWW-Authenticate` Bearer challenge (or set one) when it is
missing. This makes 401s from a downstream JWT/introspection policy discoverable by MCP clients.
Challenges also carry `scope="…"` (`scopesSupported`, else `upstreamScope` without
`offline_access`) unless one is already present, and `www-authenticate` is appended to any
existing `Access-Control-Expose-Headers` value (never overwritten).

### Rules

**Sealed values.** Every sealed payload is a JSON envelope `{k: kind, exp, d}` (`exp` 0 = never),
bound to its kind.
- **Keys.** Two independent keys are derived from `signingSecret` with HMAC-SHA256 as a KDF:
  the MAC key (label `"mcp-oauth-dcr-cimd/mac-key/v1"`) and the encryption key (label
  `"mcp-oauth-dcr-cimd/encryption-key/v1"`). The raw secret is never used as a key.
- **Signed** (`client`, `state`): `v1.<base64url(json)>.<base64url(hmac)>`, HMAC-SHA256 over
  `"<kind>." + body` with the MAC key. The holder can read these: they contain only its own
  redirect URIs, name, state, PKCE challenge and requested scope.
- **Encrypted** (`code`, `refresh`): `v1e.<base64url(nonce || ciphertext)>`, XChaCha20-Poly1305
  with the encryption key, a random 192-bit nonce, kind as associated data. The holder can neither
  read nor change the IdP code or refresh token inside, so it cannot redeem them at the IdP
  outside the gateway's checks. No randomness from the host → `server_error`.
- A sealed value longer than 8192 characters is rejected when opened.

**Client resolution** (`client_id`):
1. Starts with `https://` → CIMD (rejected if `enableCimd` is false).
2. Otherwise → opened as a sealed `client` (rejected if `enableDcr` is false).

**DCR** (`POST B/oauth/register`, JSON, ≤ 16 KiB):
- `redirect_uris` required, 1–10 entries, each ≤ 2048 chars, absolute, no fragment, no control
  characters, no `javascript:`/`data:`/`vbscript:`/`file:` scheme, and no path traversal (`.`/`..`
  segments, `%2e`, `%2f`, `%5c` or `\` in the path). Each must be allowed by the redirect policy:
  loopback `http` (127.0.0.1, [::1], localhost) when `allowLoopbackRedirects`, or an
  `allowedRedirectUris` entry: exact string match, or for a prefix entry (ending in `/`) the same
  scheme and authority and a path starting with the entry's path (compared on parsed parts).
- `client_name` is stripped of control, bidi-override and zero-width characters.
- `grant_types` ⊆ {authorization_code, refresh_token}; `response_types` ⊆ {code}.
- `token_endpoint_auth_method` is always returned as `none` (public clients, PKCE).
- 201 with `client_id` = sealed `client` {redirect URIs, name, iat, 96-bit random nonce},
  expiring after `clientRegistrationTtlSeconds`. The nonce keeps identical registrations distinct.
  If the host has no randomness, the nonce is omitted and a warning is logged.
- If the sealed `client_id` would exceed the 8192-character open limit → 400
  `invalid_client_metadata` (never return a client_id that can't be used).

**CIMD**:
- URL must be `https`, have a non-root path, no query, fragment or userinfo, no path traversal
  (`.`/`..` segments, `%2e`, `%2f`, `%5c`, `\`), ≤ 2048 chars. Rejecting queries stops
  per-query cache misses.
- Its origin must match a `cimdTrustedHosts` service (default port normalised).
- GET via that service, 5 s timeout. Status 200, body ≤ 5 KiB, JSON object.
- Document `client_id` must equal the URL exactly; `redirect_uris` a non-empty array of safe
  redirect URIs (same rules as DCR, minus the allow-list); no `client_secret`;
  `token_endpoint_auth_method` absent or `none`. `client_name` is sanitized as for DCR.
- Parsed result cached per worker for `cimdCacheTtlSeconds`. A failed fetch or invalid document
  is negatively cached for 30 s, so repeated `/authorize` calls don't re-fetch it.
- Known limits: the 5 KiB check runs after the PDK HTTP client has buffered the response (it
  can't bound the read earlier), and refresh tokens issued to a CIMD client are not re-checked
  against its current document.
- CIMD redirect URIs are trusted as published by the trusted host; the DCR redirect policy does
  not apply to them.

**Authorize** (`GET B/oauth/authorize`):
- Before `redirect_uri` is validated, errors are a 400 page (never redirect to an unvalidated URI).
- `redirect_uri` is required and must match a registered URI exactly, except loopback URIs, whose
  port is ignored (RFC 8252 §7.3).
- After that, errors redirect to `redirect_uri` with `error`, `state`, `iss`:
  `response_type` must be `code`; `code_challenge` required (43–128 chars) with
  `code_challenge_method=S256`; `resource`, if sent, must equal the protected resource
  (`invalid_target`, RFC 8707); and the scope must be allowed (`invalid_scope`).
- **Scope.** With `upstreamScope` set, that value is always requested. Otherwise the client's
  `scope` may only contain `scopesSupported` entries plus `offline_access`; an empty request gets
  all of `scopesSupported`. All clients share one IdP app, so any other scope that app holds
  (e.g. tenant-wide Graph scopes) can never be requested through the gateway.
- The IdP URL is `upstreamAuthorizeUrl` with the upstream client ID, redirect URI
  `publicBaseUrl/oauth/callback`, the client's `code_challenge`, the effective scope, and
  `state` = sealed `state` {client hash, redirect URI, client state, browser binding,
  code_challenge, effective scope}, 10 min.
- `resource` is not forwarded (some IdPs, e.g. Entra v2, reject `resource` alongside `scope`).
- `requireConsent` false → 302 straight to the IdP URL.
- `requireConsent` true (default) → 200 consent page. MCP spec, security considerations: proxies
  using a static client ID MUST obtain user consent for each dynamically registered client, and
  CIMD servers MUST clearly display the redirect URI hostname. The page shows:
  - the client name (DCR: self-reported and labelled unverified; CIMD: from the metadata
    document, with the `client_id` host that published it),
  - the MCP resource URL,
  - the permissions (effective scopes) that will be requested,
  - the destination: `scheme://host[:port]` for http(s), or just the scheme for private-use
    schemes such as `myapp://callback` (whose "host" is not a real host),
  - for loopback redirects, a warning that access goes to an app on this computer; for
    non-loopback plain `http`, a warning that access travels unencrypted,
  - **Continue** (link to the IdP URL) and **Cancel** (link to `redirect_uri` with
    `error=access_denied`, `state`, `iss`).
  All values are HTML-escaped and names truncated to 120 characters. Headers:
  `Cache-Control: no-store`, `X-Frame-Options: DENY`,
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
  `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`.
- **Browser binding.** With consent, the page sets a cookie named `__Host-mcp-auth-<key>` (or
  `mcp-auth-<key>` when `publicBaseUrl` is http) holding a 128-bit random value;
  `HttpOnly; SameSite=Lax; Path=/; Max-Age=600` (+ `Secure` over https). `<key>` is 48 random bits,
  so concurrent sign-ins don't collide. The sealed state carries `<key>` and the value's
  fingerprint. This defeats consent bypass: an IdP link copied from one browser's consent page
  fails in any other browser. The cookie is set when the consent page renders (there is no
  separate approve POST: Continue is a plain link), and the callback expires it.
- No randomness from the host while consent is required → error redirect `server_error`
  (fail closed).

**Callback** (`GET B/oauth/callback`):
- Invalid/expired `state` → 400 page.
- Browser binding: if the state carries a binding, the request's `Cookie` must contain
  `<cookie name>=<value>` whose fingerprint matches; a state with no binding is accepted only
  when `requireConsent` is false. Otherwise → 400 page, before anything is forwarded.
- IdP `error` → redirect with `error` (+ `error_description`), `state`, `iss`.
- Otherwise redirect with `code` = encrypted `code` {IdP code, client hash, redirect URI,
  code_challenge, effective scope}, 5 min, plus `state` and `iss` (RFC 9207).
- Both redirects expire the binding cookie (`Max-Age=0`).

**Token** (`POST B/oauth/token`, form, ≤ 16 KiB). `client_id` comes from the form or a Basic
`Authorization` header.
- `resource`, if sent, must equal the protected resource (`invalid_target`).
- `authorization_code`: `code`, `redirect_uri`, `code_verifier`, `client_id` required. Sealed code
  must open, its client hash must match `client_id`, its redirect URI must equal `redirect_uri`.
  A DCR `client_id` must still open as a valid sealed `client`.
- **PKCE is verified by the gateway.** `code_verifier` must be 43–128 unreserved characters
  (`invalid_request`), and `BASE64URL(SHA256(code_verifier))` must equal the sealed
  `code_challenge`, compared in constant time (`invalid_grant`). Only then is the IdP called, with
  the callback URL as `redirect_uri`, the `code_verifier` (defense in depth) and upstream
  credentials. The gateway adds its own client credentials upstream, so it can't rely on the IdP
  to bind the verifier to this client.
- `refresh_token`: sealed `refresh` must open and match `client_id`. Sends `upstreamScope` if set;
  otherwise the client's `scope`, which may only narrow the scope granted at authorization
  (`invalid_scope`), or the granted scope if none is sent.
- IdP 200 → returned with `refresh_token` (if any) encrypted as `refresh` (bound to the client
  and the granted scope), expiring after `clientRegistrationTtlSeconds`. `id_token` is removed:
  its issuer is the IdP, not this server. A 200 that is not a JSON object → 502 `server_error`.
- IdP 401, or `invalid_client` / `unauthorized_client` → 502 `server_error`, logged at error level.
  These mean the gateway's own upstream credentials are wrong; relaying them would make MCP
  clients think their registration is bad and re-register.
- Other IdP 4xx → same status, with the IdP's `error` (mapped to a standard code) and
  `error_description` (truncated); a non-JSON 4xx body is replaced by `invalid_grant`.
- IdP 5xx or transport failure → 503 `temporarily_unavailable`.
- All token responses carry `Cache-Control: no-store`.

### Missing context (local-mode)

The policy reads no `ApiContext` data: everything comes from configuration. It behaves the same in
local and connected mode and logs no missing-context warnings.

### Injection point

Inbound, on the MCP server API instance (`endpoint.type=mcp`). Chain order: MCP Support (must
be first) → this policy → token validation (JWT Validation / Introspection) → others.

### Principal propagation

None. The downstream validation policy sets the authentication object.

### Edge cases

- Requests to facade paths with an unexpected method → 405 with `Allow` (`OPTIONS` is answered
  only on metadata, register and token).
- `POST B/oauth/register` with `enableDcr` false → 404 `invalid_request`.
- Bodies above 16 KiB (by `content-length` or actual size) → 413.
- `state` from the client is optional and echoed verbatim; if absent, none is returned.
- Clock: `SystemTime::now()`; never a panic if it fails. Browser endpoints (`/oauth/authorize`,
  `/oauth/callback`) then answer with the 400 error page; API endpoints (`/oauth/register`,
  `/oauth/token`) with 500 `server_error` JSON.

### Error responses

OAuth endpoints return RFC 6749 JSON (`{"error": ..., "error_description": ...}`):
`invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`,
`invalid_redirect_uri`, `invalid_client_metadata`, `invalid_scope`, `invalid_target`,
`temporarily_unavailable`, `server_error`.
Browser endpoints (`authorize`, `callback`) return a minimal `text/plain` 400 when they cannot
redirect.

Fail mode: **fail closed**. If the IdP token endpoint or a CIMD host is unreachable, the flow
fails with 503 / `temporarily_unavailable`; MCP traffic itself is unaffected (the policy does not
call out on the MCP request path).

### Benchmarks

Not applicable: the MCP request path does only a header check; network calls happen only on
`/oauth/token` and on CIMD cache misses.

## Architecture

- `src/lib.rs`: entrypoint, routing, async orchestration (state transitions, HTTP calls).
- `src/settings.rs`: validated runtime settings derived from generated `Config`.
- `src/seal.rs`: HMAC sealing/opening.
- `src/uri.rs`: URI parsing, loopback and redirect matching, query building.
- `src/oauth.rs`: pure OAuth logic: metadata, DCR, authorize, callback, token request/response.
- `src/consent.rs`: consent page rendering and browser-binding cookies.
- `src/filter_tests.rs`: `pdk-unit` tests that drive the real entrypoint and filters.
- `src/cimd.rs`: CIMD URL and document validation (pure) and fetch (async).

All business logic is synchronous and unit-tested; `lib.rs` only moves bytes between PDK states
and these functions.

## Examples

```yaml
# policy configuration
publicBaseUrl: https://gateway.example.com/mcp-server
mcpResourcePath: /mcp
upstreamAuthorizeUrl: https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize
upstreamTokenService: https://login.microsoftonline.com:443/TENANT_ID/oauth2/v2.0/token
upstreamClientId: UPSTREAM_CLIENT_ID
upstreamClientSecret: UPSTREAM_CLIENT_SECRET
upstreamClientAuthMethod: client_secret_post
upstreamScope: "api://mcp-server/.default offline_access"
signingSecret: <output of openssl rand -base64 48>
enableDcr: true
enableCimd: true
cimdTrustedHosts: ["https://client.example.com:443"]
allowLoopbackRedirects: true
allowedRedirectUris: ["https://client.example.com/oauth/callback"]
```

```http
# example request
POST /mcp-server/oauth/register
Content-Type: application/json

{"redirect_uris":["http://127.0.0.1:33418/callback"],"client_name":"My MCP client"}
```

```http
# example response
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store

{"client_id":"v1.eyJr...","client_id_issued_at":1792000000,"redirect_uris":["http://127.0.0.1:33418/callback"],
 "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
 "token_endpoint_auth_method":"none","client_name":"My MCP client"}
```
