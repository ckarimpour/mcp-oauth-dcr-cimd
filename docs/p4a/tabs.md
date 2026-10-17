# P4A catalog doc tabs

Upload with `set_policy_doc_tab` (one call per tab, always with the full `bodyMd`) after the policy
is submitted. See the `p4a-document-policy` skill. Each `## key` section below is one tab; its body
is everything until the next `## `.

| sortOrder | key | title |
| --- | --- | --- |
| 0 | `overview` | `Overview` |
| 1 | `configuration` | `Configuration` |
| 2 | `examples` | `Examples` |
| 3 | `security` | `Security` |
| 4 | `deployment` | `Deployment & Ordering` |
| 5 | `faq` | `FAQ & See Also` |

Later, once the P4A MCP server is connected: add `doc_url` links for the MuleSoft built-ins
(`search_policies` with `source: "mulesoft"`, then `get_mulesoft_policy`), and links to related P4A
policies that are `approved` with a non-null `published_at`.

## overview

Lets MCP clients sign in to an MCP server behind Omni Gateway when the identity provider supports
neither **Client ID Metadata Documents (CIMD)** nor **Dynamic Client Registration (DCR)**. That
covers most enterprise IdPs, such as Entra ID, Okta and PingFederate.

The gateway becomes a thin OAuth authorization-server facade:

1. It serves the discovery metadata MCP clients look for (RFC 9728 and RFC 8414). The metadata
   advertises CIMD and DCR.
2. It accepts clients that identify themselves with an HTTPS `client_id` URL (CIMD, the MCP
   spec's preferred method) or that register with DCR (the backwards-compatible fallback).
3. It shows the user a **gateway consent page** that names the client and where access will go.
4. It sends the browser to the real IdP using **one** pre-registered application, then returns
   the IdP's tokens to the client. PKCE runs end to end between the MCP client and the IdP.

**Key caveat.** All MCP clients share that one IdP application identity, so IdP consent screens
and audit logs show the gateway app. This policy does not validate access tokens; something after
it must (see **Deployment & Ordering**).

**Category:** Security. **Stateless:** client IDs, state, codes and refresh tokens are signed or
encrypted values, so it runs on any number of replicas with no storage.

**Configuration:** the policy won't load without its required properties: the public URL, the IdP
endpoints, the IdP app credentials and a signing secret. There is no empty-config mode.

## configuration

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `publicBaseUrl` | string (uri) | — (required) | External URL of this API instance, no trailing slash (e.g. `https://gateway.example.com/mcp-server`). The OAuth issuer; its path must equal the API base path. `http` only on localhost. |
| `mcpResourcePath` | string | `/mcp` | MCP endpoint path under `publicBaseUrl`, advertised as the protected resource. |
| `upstreamAuthorizeUrl` | string (uri) | — (required) | The IdP's authorization endpoint (browser redirect). |
| `upstreamTokenService` | string (service) | — (required) | Full URL of the IdP's token endpoint; called by the gateway. Keep the explicit port, e.g. `:443`. |
| `upstreamClientId` | string | — (required) | Client ID of the pre-registered IdP application. |
| `upstreamClientSecret` | string, sensitive | none | Its client secret. Required unless `upstreamClientAuthMethod` is `none`. |
| `upstreamClientAuthMethod` | enum | `client_secret_post` | `client_secret_post`, `client_secret_basic` or `none`. |
| `upstreamScope` | string | none | Sent to the IdP instead of the client's scope (e.g. Entra `api://<app>/.default offline_access`). |
| `scopesSupported` | array of string | none | Scopes advertised in discovery metadata. |
| `signingSecret` | string, sensitive | — (required) | At least 32 characters; the same on every replica. Signs client IDs and state; encrypts wrapped codes and refresh tokens. Rotating it invalidates all registrations and refresh tokens. |
| `enableCimd` | boolean | `false` | Accept HTTPS `client_id` URLs. Requires `cimdTrustedHosts`. |
| `cimdTrustedHosts` | array of string (service) | none | Origins allowed to host client metadata documents, e.g. `https://client.example.com:443`. |
| `cimdCacheTtlSeconds` | integer | `300` | Per-worker cache lifetime for fetched documents. `0` disables caching. |
| `enableDcr` | boolean | `true` | Accept DCR at `/oauth/register`. |
| `allowLoopbackRedirects` | boolean | `true` | Let DCR clients register `http://127.0.0.1`, `[::1]` or `localhost` redirect URIs (CLI and desktop clients). |
| `allowedRedirectUris` | array of string | none | Other redirect URIs DCR clients may register. An entry ending in `/` is a prefix; otherwise it must match exactly. |
| `clientRegistrationTtlSeconds` | integer | `7776000` (90 days) | Lifetime of DCR client IDs and wrapped refresh tokens. `0` means no expiry. |
| `challengeUnauthenticated` | boolean | `true` | Answer token-less MCP requests with a 401 that points to the metadata, and add that pointer to 401s from later policies. |
| `requireConsent` | boolean | `true` | Show the gateway consent page and bind the sign-in to the browser. Only disable it if the IdP shows equivalent per-client consent. |

**`cimdTrustedHosts` entries:** an `https` origin with an explicit port. Only `client_id` URLs on
these hosts are fetched.

**`allowedRedirectUris` entries:** an absolute URI without a fragment. Control characters and the
`javascript:`, `data:`, `vbscript:` and `file:` schemes are always rejected.

**Failure behavior** (fail closed):
- Invalid configuration → the policy doesn't load (secrets are never echoed).
- IdP token endpoint unreachable or failing → `503 temporarily_unavailable`.
- IdP rejects the gateway's own credentials → `502 server_error`, logged at error level.
- CIMD host unreachable → the authorization request is refused.
- MCP traffic itself never waits on an outbound call.

## examples

**Entra ID with CIMD and DCR.** The typical enterprise setup:

```yaml
publicBaseUrl: https://gateway.example.com/mcp-server
upstreamAuthorizeUrl: https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize
upstreamTokenService: https://login.microsoftonline.com:443/TENANT_ID/oauth2/v2.0/token
upstreamClientId: UPSTREAM_CLIENT_ID
upstreamClientSecret: UPSTREAM_CLIENT_SECRET
upstreamScope: "api://UPSTREAM_APP_ID/.default offline_access"
signingSecret: GENERATE_32_PLUS_RANDOM_CHARACTERS
enableCimd: true
cimdTrustedHosts: ["https://client.example.com:443"]
enableDcr: true
allowLoopbackRedirects: true
```

**CIMD only.** No open registration; only clients published by trusted hosts:

```yaml
publicBaseUrl: https://gateway.example.com/mcp-server
upstreamAuthorizeUrl: https://idp.example.com/oauth2/authorize
upstreamTokenService: https://idp.example.com:443/oauth2/token
upstreamClientId: UPSTREAM_CLIENT_ID
upstreamClientSecret: UPSTREAM_CLIENT_SECRET
signingSecret: GENERATE_32_PLUS_RANDOM_CHARACTERS
enableDcr: false
enableCimd: true
cimdTrustedHosts:
  - https://client-a.example.com:443
  - https://client-b.example.com:443
```

**DCR for desktop/CLI clients plus one web client.** Loopback redirects and one exact web callback:

```yaml
publicBaseUrl: https://gateway.example.com/mcp-server
upstreamAuthorizeUrl: https://idp.example.com/oauth2/authorize
upstreamTokenService: https://idp.example.com:443/oauth2/token
upstreamClientId: UPSTREAM_CLIENT_ID
upstreamClientSecret: UPSTREAM_CLIENT_SECRET
signingSecret: GENERATE_32_PLUS_RANDOM_CHARACTERS
enableDcr: true
allowLoopbackRedirects: true
allowedRedirectUris: ["https://web-client.example.com/oauth/callback"]
clientRegistrationTtlSeconds: 2592000
```

**Local playground.** Plain HTTP is allowed on localhost only:

```yaml
publicBaseUrl: http://localhost:8081/mcp-server
upstreamAuthorizeUrl: https://idp.example.com/oauth2/authorize
upstreamTokenService: https://idp.example.com:443/oauth2/token
upstreamClientId: TEST_CLIENT_ID
upstreamClientSecret: TEST_CLIENT_SECRET
signingSecret: LOCAL_TEST_SECRET_AT_LEAST_32_CHARACTERS
```

## security

**Trust model.**
- The IdP still authenticates every user.
- The gateway decides which *clients* may start a sign-in, and shows the user which client is
  asking.
- Tokens are the IdP's own. They must be validated after this policy; see **Deployment &
  Ordering**.

**Controls in this policy:**
- **Per-client consent.** The MCP spec requires a proxy that uses one static IdP client ID to get
  consent for each dynamically registered client. The consent page shows:
  - the client name (marked unverified for DCR; for CIMD, the host that published it),
  - the MCP server,
  - the host that will receive access, with a warning for localhost.
- **Browser binding.** A random `__Host-` cookie ties each sign-in to the browser that saw the
  consent page. An IdP link copied out of someone else's consent page fails.
- **PKCE (S256) required**, end to end between the client and the IdP.
- **Exact redirect-URI matching.** Loopback ports are ignored, per RFC 8252. Control characters
  and script-capable schemes are rejected.
- **Encrypted codes and refresh tokens.** They are bound to the requesting client and expire.
  Client IDs and state are signed.
- **CIMD from trusted hosts only.** Outbound fetches go only to configured services, so a
  `client_id` URL can't be used to make the gateway call internal endpoints (SSRF).
- **Secrets** are marked sensitive and never logged. Configuration errors never echo the config.

**Limits to plan for:**
- All clients share one IdP app identity in consent screens, audit logs and token claims.
- DCR is open to anyone who can reach the gateway. Rate-limit `/oauth/register`.
- There is no per-client revocation. To invalidate everything, rotate `signingSecret` or shorten
  `clientRegistrationTtlSeconds`.

## deployment

**API instance:** type `mcp`. The policy is **inbound**; apply it without an upstream ID.

**Chain order:**

1. **MCP Support.** Always first on an MCP instance.
2. **This policy.** It answers discovery, `/oauth/*` and token-less MCP requests itself, so it must
   run before token validation.
3. **Token validation:** signature, issuer, audience and expiry of the IdP's access token. The built-in JWT Validation policy can't currently be applied to `mcp` API instances (tested on Omni Gateway 1.12.9), so validate tokens in the MCP server itself until a token-validation policy is available for MCP instances.
4. Optionally, **Rate Limiting** on `/oauth/register` and `/oauth/token`.

**IdP application:** register one app with:
- redirect URI `<publicBaseUrl>/oauth/callback`,
- the authorization-code grant with PKCE (plus refresh tokens if wanted),
- the API scope that the MCP server's tokens need.

**Requirements:** Omni/Flex Gateway **1.9.3 or later** (the policy reads request bodies with stop
iteration). Same `signingSecret` on every replica.

**Discovery paths:** for an issuer with a path, clients find the authorization server at
`<publicBaseUrl>/.well-known/openid-configuration`, which this policy serves. Root-level forms
(`/.well-known/oauth-authorization-server/<path>`) reach the policy only when the API is mounted
at `/`. Use a dedicated hostname if a client needs them.

## faq

**Do I still need token validation?** Yes. This policy registers clients and brokers sign-in; on
MCP calls it only checks that an `Authorization` header is present. The built-in JWT Validation policy can't currently be applied to `mcp` API instances (tested on Omni Gateway 1.12.9), so validate tokens in the MCP server itself until a token-validation policy is available for MCP instances.

**Why does every client show up as the same app at the IdP?** The IdP can't register clients
dynamically, so the gateway uses one pre-registered app for all of them. That's why the gateway
shows its own consent page (see **Security**).

**Can it accept any CIMD client URL?** No, only `client_id` URLs on hosts listed in
`cimdTrustedHosts`. Omni Gateway policies can only call pre-configured services. This also
prevents SSRF.

**Do I need DCR if I have CIMD?** The MCP spec prefers CIMD and keeps DCR for backwards
compatibility. Many clients still use DCR today; turn it off with `enableDcr: false` if all of
yours support CIMD.

**Does it need Redis or a database?** No. Everything is carried in signed or encrypted values.
Use the same `signingSecret` on every replica.

**How do I revoke a client?** Individually, you can't. Rotate `signingSecret` to invalidate all
registrations and refresh tokens, or shorten `clientRegistrationTtlSeconds`. User access is
revoked at the IdP as usual.

**My IdP already supports CIMD. Do I need this?** No. Point the protected-resource metadata at the
IdP and validate its tokens.

### See Also

- **Specs:**
  - [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  - [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00)
  - [RFC 9728 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
  - [RFC 8414 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
  - [RFC 7591 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- **MuleSoft built-in policies** (Omni Gateway included policies):
  - MCP Support: must run first on the MCP instance.
  - JWT Validation: validates IdP access tokens on HTTP instances (not yet on `mcp` instances).
  - OAuth 2.0 Token Introspection: the alternative for opaque tokens.
  - Rate Limiting: protects `/oauth/register` and `/oauth/token`.
- **Framework:** [PDK overview](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview)
