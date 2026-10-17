# MCP OAuth Client Registration (DCR + CIMD), an Omni Gateway custom policy

MCP clients such as Claude, VS Code and MCP Inspector expect the MCP server's authorization server
to let them register themselves. They do this with **Dynamic Client Registration** (RFC 7591) or,
since the 2025-11-25 MCP spec, a **Client ID Metadata Document** (CIMD). In CIMD, the `client_id`
is an HTTPS URL that describes the client. Enterprise IdPs (Entra ID, Okta, PingFederate) usually
support neither for this use.

This policy turns the Omni Gateway in front of an MCP server into a thin **OAuth
authorization-server facade**:

```
MCP client ──(1) discovery, DCR / CIMD, /authorize, /token──▶ Gateway (this policy)
                                                               │  one pre-registered IdP app
                                                               ▼
                                                     Enterprise IdP (authorize + token)
MCP client ──(2) MCP calls with IdP access token──▶ Gateway ──JWT Validation──▶ MCP server
```

- It serves RFC 9728 protected-resource metadata and RFC 8414 authorization-server metadata. The
  metadata advertises `registration_endpoint` and `client_id_metadata_document_supported`.
- DCR clients get a signed, self-contained `client_id`. CIMD clients are accepted from trusted hosts.
- The browser is sent to the real IdP using one pre-registered application. PKCE is end-to-end:
  the MCP client's `code_challenge` goes to the IdP, and its `code_verifier` is forwarded at
  `/token`.
- Access tokens are the IdP's own tokens. A standard **JWT Validation** (or OAuth 2.0 Token
  Introspection) policy validates them on MCP calls.
- **Stateless.** Client IDs, `state`, codes and refresh tokens are HMAC-signed values. It works
  on any number of replicas with no Redis and no extra app to host.

The full behaviour is in [docs/spec.md](docs/spec.md).

## Status

Builds against PDK 1.10.0 with Rust 1.99.1:
- all 62 tests pass (`cargo test`): 48 logic tests plus 14 `pdk-unit` tests that run the real
  filters in-process;
- `cargo clippy` is clean for host and `wasm32-wasip1`, and `cargo fmt --check` passes;
- `cargo build --release --target wasm32-wasip1` produces a ~1 MB module that imports only
  standard proxy-wasm and WASI calls.

It has been reviewed against the `omni-gateway-pdk-skills` and `p4a-skills` conventions. P4A
catalog content is ready in [docs/p4a/](docs/p4a/).

**Verified live (2026-10-17):** a DEV build on a managed Omni Gateway 1.12.9 (`mcp` API instance:
MCP Support → this policy), in front of an A2D mock MCP server, with Okta as the IdP. MCP
Inspector completed discovery → DCR → consent page → Okta → callback → token exchange, then
`tools/list` with the Okta access token (`aud=api://default`, scopes `offline_access mcp.read`).
MCP Support passes `/.well-known/*` and `/oauth/*` through to this policy.

**Known gap:** the built-in JWT Validation policy (1.4.1 and the Flex 0.12.0 line) has no
implementation for `mcp` instances, so nothing on that instance validates access tokens yet. On a
real MCP server, add token validation before production use.

Still to do: a CIMD client test, the refresh-token flow, real clients (Claude, VS Code), and the
P4A submission (public repo).

## Endpoints

`B` is the path of `publicBaseUrl`, which is the API instance base path.

| Endpoint | Purpose |
|---|---|
| `GET B/.well-known/oauth-protected-resource` (also `…/oauth-protected-resource/mcp`) | Protected-resource metadata |
| `GET B/.well-known/openid-configuration`, `GET B/.well-known/oauth-authorization-server` | Authorization-server metadata |
| `POST B/oauth/register` | DCR |
| `GET B/oauth/authorize` | Validates the client, shows the gateway consent page, then continues to the IdP |
| `GET B/oauth/callback` | The IdP returns here; the gateway redirects to the MCP client |
| `POST B/oauth/token` | Redeems codes and refresh tokens at the IdP |
| Any other request without `Authorization` | 401 + `WWW-Authenticate: Bearer resource_metadata="…"` |

MCP clients discover the authorization server from `resource_metadata` in the 401. For an issuer
with a path, they then try `B/.well-known/openid-configuration`, which this policy serves. The
root-level path-insertion forms (`/.well-known/oauth-authorization-server/B`) only reach this
policy if the API is mounted at `/`. If a client insists on those forms, publish the MCP server
on its own hostname at `/`.

## 1. Register one application at the IdP

- Type: confidential web app (a public app works with `upstreamClientAuthMethod: none`).
- Redirect URI: `<publicBaseUrl>/oauth/callback`, for example
  `https://gateway.example.com/mcp-server/oauth/callback`.
- Allow the authorization-code grant with PKCE, plus refresh tokens if wanted.
- Expose the scope that the MCP server's access tokens need. With Entra ID, set `upstreamScope`
  to `api://<app-id>/.default offline_access`.

## 2. Build and publish the policy

You need Node.js 22.12 or later for the PDK plugin, Rust with the `wasm32-wasip1` target, and a
signed-in `anypoint-cli-v4` with `anypoint-pdk-plugin`. Set `group_id` in `Cargo.toml` to your
business group, then:

```bash
make install-cargo-anypoint
```

```bash
make build
```

```bash
make publish
```

This project's `Makefile`, `.project.yaml`, `AGENTS.md`, `playground/` and `tests/config/` come
from `anypoint-cli-v4 pdk policy-project create` (PDK plugin 1.10.1). The Makefile pins
`cargo-anypoint` 1.10.0.

`src/generated/config.rs` is generator output from `make build-asset-files`, and the P4A pipeline
regenerates it on every build. Don't edit it. Its `init` registers the IdP token endpoint and the
CIMD hosts as outbound services.

Known generator behavior: if the configuration ever fails to parse at gateway startup, the
generated error message includes the raw configuration, secrets included. API Manager validates
the config against the schema first, so this is unlikely. Treat gateway startup logs as
sensitive anyway.

## 3. Apply it to the MCP server API instance

Use an API instance of type `mcp`. This policy is an inbound policy. Apply the policies in this
order:

1. **MCP Support.** It must be first in the chain on an MCP instance, because it keeps SSE
   framing and `Mcp-Session-Id` intact for everything after it.
2. **This policy.** It answers the discovery, `/oauth/*` and unauthenticated-401 requests itself.
   It has to come before token validation, because those requests carry no token.
3. **JWT Validation**, with the IdP's JWKS URL, issuer and audience. Or use OAuth 2.0 Token
   Introspection.
4. Optionally, **Rate Limiting** on `B/oauth/register` and `B/oauth/token`.

Still to verify on a live gateway: that MCP Support lets `B/.well-known/*` and `B/oauth/*`
requests through to this policy.

Example configuration (placeholders):

```yaml
publicBaseUrl: https://gateway.example.com/mcp-server
mcpResourcePath: /mcp
upstreamAuthorizeUrl: https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize
upstreamTokenService: https://login.microsoftonline.com:443/TENANT_ID/oauth2/v2.0/token
upstreamClientId: UPSTREAM_CLIENT_ID
upstreamClientSecret: UPSTREAM_CLIENT_SECRET          # sensitive
upstreamClientAuthMethod: client_secret_post
upstreamScope: "api://UPSTREAM_APP_ID/.default offline_access"
signingSecret: GENERATE_32_PLUS_RANDOM_CHARACTERS      # sensitive; same on every replica
enableDcr: true
allowLoopbackRedirects: true                          # CLI/desktop clients
allowedRedirectUris:
  - https://client.example.com/oauth/callback         # exact
  - https://other-client.example.com/oauth/           # prefix (ends with /)
enableCimd: true
cimdTrustedHosts:
  - https://client.example.com:443                    # hosts allowed to serve CIMD documents
```

To generate a signing secret:

```bash
openssl rand -base64 48
```

## Security notes: review these with the customer

- **One IdP identity for all MCP clients.** Every registered client reaches the IdP as the one
  pre-registered app. The IdP's consent screen and audit logs show that app, not the MCP
  client's name, and the tokens' `azp`/`appid` are the same for every client. This is the
  inherent trade-off of a DCR facade, and the same trade-off as the custom-IdP-app workaround. It
  also needs no separate public app to host.
- **Gateway consent page (on by default).** Because the IdP can't tell clients apart, the MCP
  spec requires a proxy like this to get the user's consent for each dynamically registered
  client. Before sending the browser to the IdP, the gateway shows:
  - the client's name (marked unverified for DCR; for CIMD, the host that published it),
  - the MCP server being accessed,
  - the host that will receive access, with a warning for localhost.

  A random `__Host-` cookie binds the sign-in to that browser. An IdP link copied out of an
  attacker's own consent page fails in a victim's browser, so consent can't be skipped. Without
  this, an attacker could register a client, send a user a link, and silent IdP SSO would deliver
  a code to the attacker's redirect URI. Only set `requireConsent: false` if the IdP shows
  equivalent per-client consent.
- **DCR is open by design.** Anyone who can reach the gateway can register. The guardrail is the
  redirect-URI policy: loopback URIs (native and CLI clients) plus the explicit
  `allowedRedirectUris` list. A user still has to sign in at the IdP, and codes only go to the
  registered redirect URI and require the client's PKCE verifier. Rate-limit the endpoint.
- **CIMD only from trusted hosts.** Flex policies can only call pre-registered services, so the
  gateway cannot fetch arbitrary `client_id` URLs. This also rules out SSRF. A client's CIMD
  host must be listed in `cimdTrustedHosts`. CIMD redirect URIs are trusted as published by
  that host.
- **No per-client revocation.** Registrations are stateless. To invalidate all of them, rotate
  `signingSecret` (this also invalidates wrapped refresh tokens) or shorten
  `clientRegistrationTtlSeconds`. Revoke users at the IdP as usual.
- **Codes and refresh tokens are encrypted.** The IdP's authorization code and refresh token are
  wrapped with XChaCha20-Poly1305 and bound to the client that requested them. A client can't
  extract them and redeem them at the IdP outside the gateway's checks. Client IDs and `state`
  are only signed, because they contain nothing secret.
- **Redirect URIs are strict.** Control characters, whitespace and `javascript:` / `data:` /
  `vbscript:` / `file:` schemes are rejected, so a redirect URI can't inject headers or script.
- **Bad upstream credentials show up as gateway errors.** If the IdP rejects the gateway's own
  client ID or secret, MCP clients get `502 server_error` (logged at error level), not
  `invalid_client`. That stops clients from re-registering in a loop.
- **Secrets.** The client secret and signing secret are marked `security:sensitive` and are never
  logged.

## Tests

```bash
cargo test
```

**Logic tests** (in each module) cover:
- signing, encryption and tamper detection;
- URI, loopback and header-injection rules;
- CIMD URL and document validation, and DCR validation;
- the authorize → consent → callback → token round trip;
- consent-page content and HTML escaping;
- rejection of callbacks from a browser that didn't see the consent page;
- fail-closed behaviour without randomness;
- binding codes and refresh tokens to the client;
- Basic-auth encoding to the IdP, and mapping of IdP errors.

**Filter tests** (`src/filter_tests.rs`, `pdk-unit`) drive the real `configure`, request filter
and response filter. They cover:
- discovery and the 401 challenge;
- DCR never reaching the MCP upstream, including bodies split across chunks;
- `resource_metadata` added to upstream 401s;
- the full register → authorize → callback → token flow against a mocked IdP;
- IdP rejections and credential errors, and an unreachable IdP;
- the missing binding cookie;
- local mode and invalid configuration.

pdk-unit doesn't run the `entrypoint_flex` init and can't control the policy's clock, so expiry
is tested in the logic tests.

Next: a playground run with a mock IdP, then checks against real clients (MCP Inspector, Claude,
VS Code) and the P4A MCP test flow (`p4a-test-mcp-policies-with-a2d`).
