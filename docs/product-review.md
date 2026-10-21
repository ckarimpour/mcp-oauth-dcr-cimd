# Product review brief

A short guide for reviewing this policy as a candidate for an official Omni Gateway feature: the
gap it fills, how it works, how it is secured and tested, its limits, and what productizing it
would take. Behaviour details are in [spec.md](spec.md); setup is in the [README](../README.md).

## Summary

MCP clients (Claude Code, Codex, VS Code and others) expect to register themselves with the
authorization server, using **CIMD** (Client ID Metadata Documents, a SHOULD in the MCP
authorization spec) or **DCR** (Dynamic Client Registration, a MAY). Most enterprise IdPs,
**Microsoft Entra ID** first among them, support neither. This policy makes Omni Gateway the
registration layer in front of any OAuth 2.0 IdP:

- MCP clients register at the gateway with CIMD or DCR; nothing is registered at the IdP.
- Users approve each client on a gateway consent page, then sign in at the real IdP.
- IT registers **one** confidential client at the IdP, once.
- The IdP's access token reaches the client unchanged: the gateway signs no tokens.
- It is stateless: no database, no extra service.

**Status:** v1.0.1, published on the P4A catalog after a 12-point security review. Verified live
on a managed Omni Gateway 1.12.9 with Okta (MCP Inspector, DCR) and with Entra ID (Claude Code
from a clean profile, CIMD), including `tools/list` and `tools/call`.

## The gap

| Option today | Cost |
|---|---|
| Register every MCP client at the IdP by hand | IT work per client; clients need custom configuration; does not scale as new AI clients appear |
| Put a second IdP that supports DCR/CIMD in front of Entra | Another identity system to buy, run and secure; often rejected by IAM teams |
| A facade that signs its own client-facing tokens | Becomes an additional token issuer, which enterprise IAM teams treat as an exception needing explicit approval |
| **This policy: a non-issuing adapter** | Registration, metadata, redirects and consent move to the gateway; the IdP stays the only token issuer |

Enterprise customers evaluating MCP gateways have made Entra ID compatibility a hard requirement,
with acceptance tests such as: "from a clean Claude Code profile, complete browser SSO with Entra
without manual token handling; the IdP remains the sole issuer; all OAuth and MCP traffic goes
through the gateway". This policy is built to pass that test.

## How it works

1. An MCP request without a token gets a 401 with `resource_metadata` (RFC 9728).
2. The client reads the protected-resource and authorization-server metadata (RFC 8414 / OIDC
   discovery) served by the policy, which advertise DCR and CIMD.
3. The client registers: DCR at `/oauth/register` (RFC 7591), or a CIMD `client_id` URL that the
   gateway fetches from a trusted host and validates.
4. `/oauth/authorize` validates the client, redirect URI, PKCE (S256), scope and `resource`, then
   shows the consent page and sets a browser-binding cookie.
5. The browser goes to the IdP with the gateway's single client ID; the IdP returns to
   `/oauth/callback`, which redirects to the MCP client with a wrapped code.
6. `/oauth/token` verifies PKCE, redeems the code at the IdP with the gateway's credentials, and
   returns the IdP's access token unchanged (refresh tokens are wrapped and client-bound; ID tokens
   are dropped).
7. MCP traffic with a token continues to the upstream untouched.

**Design principles**

- **Non-issuing.** Access tokens are the IdP's. The OIDC metadata's `jwks_uri` serves an empty
  key set on purpose.
- **Stateless.** Client IDs and `state` are HMAC-signed; codes and refresh tokens are encrypted
  (XChaCha20-Poly1305). MAC and encryption keys are derived from one `signingSecret`, which must be
  the same on every replica.
- **Gateway-only.** All endpoints are served under the API instance's base path, so the policy
  works on a shared gateway with one instance per MCP server.
- **Consent per client.** Required by the MCP spec for proxies that use one static IdP client ID.

## Code layout

| File | Responsibility | Tests |
|---|---|---|
| `src/lib.rs` | PDK entrypoint, request routing, HTTP calls (IdP token endpoint, CIMD fetch), caching, response filter | via `filter_tests.rs` |
| `src/oauth.rs` | Settings validation, metadata, DCR, authorize, callback, token logic, error mapping (pure functions) | 31 |
| `src/cimd.rs` | CIMD `client_id` URL rules and document validation | 3 |
| `src/consent.rs` | Consent page rendering, escaping, name sanitising, browser-binding cookie | 8 |
| `src/seal.rs` | Signing, encryption, key derivation, PKCE, constant-time comparison | 11 |
| `src/uri.rs` | URL parsing, redirect matching, path-traversal checks | 12 |
| `src/settings.rs` | Maps the generated config to runtime settings | (covered by oauth and filter tests) |
| `src/filter_tests.rs` | `pdk-unit` tests running the real filters in-process, with a mocked IdP | 16 |
| `definition/gcl.yaml` | Policy schema shown in API Manager | — |

Logic is kept in plain, unit-tested functions; `lib.rs` is the thin PDK layer.

## Security model

| Threat | Mitigation |
|---|---|
| Stolen or intercepted authorization code | PKCE S256 required and verified at the gateway before calling the IdP; codes are encrypted, client-bound and short-lived (5 min) |
| Open redirect / code sent to an attacker | Redirect URIs must match the registration or CIMD document exactly (loopback on any port, per RFC 8252); dot segments, encoded separators and unsafe schemes rejected; optional prefix rules are path-safe |
| Client impersonation via localhost | Consent page shows the client, the CIMD host and the redirect host, with an explicit warning for localhost redirects |
| Sign-in completed from another browser (confused deputy) | Consent sets a `__Host-` cookie bound into the state; the callback refuses without it, then clears it |
| SSRF through CIMD fetches | Only hosts listed in `cimdTrustedHosts` are fetched (the gateway can only call pre-registered services); 5 s timeout, 5 KiB limit, no query, fragment, credentials or dot segments |
| Forged client IDs, state or codes | HMAC-SHA256 signatures and authenticated encryption with derived keys; constant-time comparisons |
| Weak or example secrets | `signingSecret` length, character variety and estimated entropy are checked; known placeholders are rejected |
| Scope escalation | Requested scopes limited to `scopesSupported` (or replaced by `upstreamScope`); refresh can only narrow the scope; a foreign `resource` gets `invalid_target` |
| Gateway credential errors leaking as client errors | IdP 401 / `invalid_client` mapped to 502 so clients do not retry with bad assumptions |
| Header injection, HTML injection on the consent page | Values validated and HTML-escaped; client names stripped of control, bidi and zero-width characters |

## Standards conformance

The policy follows the MCP authorization spec (2025-11-25), RFC 9728, RFC 8414 (and OIDC
discovery as an alias), RFC 7591, the CIMD draft, PKCE (RFC 7636), RFC 8707 resource checks,
RFC 9207 `iss` in responses and RFC 8252 loopback redirects. For the MCP spec's CIMD
requirements on authorization servers:

| Requirement | Status |
|---|---|
| Advertise `client_id_metadata_document_supported` | Met |
| Fetch the document for URL client IDs (SHOULD) | Met, from trusted hosts only |
| `client_id` in the document matches its URL (MUST) | Met |
| Redirect URIs checked against the document (MUST) | Met |
| Valid JSON with required fields (MUST) | Met (`client_id`, `redirect_uris`) |
| SSRF precautions (SHOULD) | Met, by allowlist |
| Localhost warning (SHOULD); show redirect host (MUST); show CIMD host | Met |
| Consent per client for a proxy with one IdP client (MUST) | Met |
| Cache per HTTP cache headers (SHOULD) | Partly: fixed, configurable cache time instead |
| `private_key_jwt` for CIMD clients (MAY) | Not supported: public clients only |

## Evidence

- **Automated:** 81 tests (`cargo test`), `cargo clippy` and `cargo fmt --check` clean, WebAssembly
  build about 1 MB.
- **Security review:** 12 findings from the P4A catalog review, all fixed in v1.0.0 (see
  [CHANGELOG](../CHANGELOG.md)).
- **Live, Okta (2026-10-16):** MCP Inspector, DCR, consent, Okta sign-in, token exchange,
  `tools/list`.
- **Live, Entra ID (2026-10-21):** Claude Code from a clean profile, CIMD registration
  (identified by claude.ai), consent, Entra sign-in, `tools/list` and `tools/call`. Negative
  checks refused: unregistered redirect URI, untrusted CIMD host, CIMD URL with query, dot
  segments or `http`.
- **Client library:** the official MCP TypeScript SDK (1.32.1) discovers the authorization server
  without errors. This check found the one bug fixed in v1.0.1.

## Known limitations and trade-offs

- **No access-token validation on MCP calls.** The built-in JWT Validation policy has no
  implementation for MCP instances (tested with 1.4.1 and 0.12.0). Planned for 1.1.0: signature
  (IdP JWKS), issuer, audience and expiry checks, with the identity handed to later policies such
  as MCP Attribute-Based Access Control.
- **No per-client revocation.** Registrations are stateless; rotating `signingSecret` invalidates
  all of them (and all wrapped refresh tokens) at once.
- **Wrapped refresh tokens.** Clients receive the IdP refresh token encrypted and client-bound,
  not raw. This is not a signed access token, but IAM teams may ask about it.
- **One IdP client for all MCP clients.** In the IdP's logs every MCP client appears as the
  gateway's app; the gateway's consent page is where users see which client is asking.
- **Discovery under a base path.** Root-level discovery paths reach the policy only if the
  instance is mounted at `/`; clients rely on `<base>/.well-known/openid-configuration`.
- **Not yet tested:** load and HA, the refresh-token flow live, Codex and VS Code, MCP protocol
  versions after 2025-06-18 with MCP ABAC.
- **No decision audit log** beyond the gateway's standard logs.

## Path to an official feature

1. **Settings in API Manager:** a guided form (IdP presets for Entra, Okta, Ping) instead of raw
   URLs and scopes.
2. **Built-in token validation** for MCP instances, either in this policy or by enabling JWT
   Validation on MCP instances, feeding identity and claims to MCP ABAC.
3. **Secret management:** `signingSecret` and the IdP client secret from a secrets manager, with
   rotation support (for example, accepting a previous key during a grace period).
4. **Observability:** registration, consent and token-exchange events and metrics, plus a
   decision audit log.
5. **Optional persistence:** a revocable client registry for customers who need per-client
   revocation.
6. **Hardening and scale:** HA and load testing, and conformance testing as MCP auth test suites
   mature.
7. **Ownership:** a product owner, support model and release process.

## Questions for Product

1. Does this gap match what the field and the roadmap are seeing, and is there a native plan for
   IdPs without DCR/CIMD?
2. Will JWT Validation be supported on MCP instances, or should validation live in this policy?
3. Which MCP protocol versions will MCP Support and MCP ABAC support next?
4. How does native CIMD for Platform MCP servers relate to this (for example, when Entra is the IdP)?
5. What would the support path be for running this policy in production before any native feature?

## How to review

Suggested reading order: this brief, [spec.md](spec.md), `src/oauth.rs` (`authorize`, `callback`,
`token_request`, `token_response`), `src/cimd.rs`, `src/seal.rs`, then `src/lib.rs`.

```bash
cargo test
```

```bash
make build
```

A live demo on the test gateway takes about ten minutes and shows the Claude Code flow with
Entra ID end to end.
