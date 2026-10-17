# P4A submission

Metadata for `submit_policy` (see the `p4a-verify-requirements` skill). Restate the full payload
and get approval before submitting.

| Field | Value |
| --- | --- |
| `name` | `MCP OAuth Client Registration (DCR + CIMD)` (42 chars; limit 2–120) |
| `category` | `Security` (matches `gcl.yaml`; `MCP` is the alternative) |
| `projectType` | `unified` |
| `githubUrl` | `https://github.com/<owner>/<repo>/tree/<ref>/<subPath>` (**public** repo; TODO) |
| `implementationGithubUrl` | omit (unified project) |
| `examplesUrl` | GitHub-rendered `README.md` of the repo (TODO) |
| `iconUrl` / `iconDisabled` | optional |
| `videoTutorialUrl` | optional |
| `deliversIdeaId` | optional; only an approved P4A idea |
| `description` | the section below (~2,600 chars; limit 10–20,000) |

## description

Becomes the catalog page and the Exchange page. Paste everything below the line.

Verified live on 2026-10-17: Omni Gateway 1.12.9 `mcp` instance (MCP Support → this policy), Okta
as the IdP, MCP Inspector completing DCR → consent → Okta → token exchange → `tools/list`.

---

**Lets MCP clients sign in to an MCP server behind Omni Gateway through an identity provider that
supports neither Client ID Metadata Documents (CIMD) nor Dynamic Client Registration (DCR).** The
gateway acts as a thin OAuth facade. It serves the MCP discovery metadata, accepts CIMD clients
(and DCR as the backwards-compatible fallback), shows a per-client consent page, and brokers the
authorization-code + PKCE flow to **one** application pre-registered at the IdP (Entra ID, Okta,
PingFederate and others).

> **Key caveat.** Every MCP client reaches the IdP as the same pre-registered application. The
> IdP's consent screen, audit logs and token `azp`/`appid` show that one app, not the individual
> MCP client. This policy does **not** validate access tokens; something after it must. The
> built-in JWT Validation policy can't currently be applied to `mcp` API instances (tested on Omni
> Gateway 1.12.9), so validate tokens in the MCP server itself until that's available.

### What it serves

| Endpoint (under the API base path) | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource` | RFC 9728 protected-resource metadata |
| `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | Authorization-server metadata (CIMD and DCR advertised) |
| `/oauth/register` | DCR (RFC 7591) |
| `/oauth/authorize` → consent page → IdP | Validates the client and shows consent |
| `/oauth/callback` | Returns the result to the MCP client |
| `/oauth/token` | Redeems codes and refresh tokens at the IdP |

Unauthenticated MCP requests get a `401` whose `WWW-Authenticate` points to the metadata. The same
pointer is added to `401`s from later policies.

### Configuration summary

| Property | Purpose |
| --- | --- |
| `publicBaseUrl` | External URL of the API instance; the OAuth issuer |
| `upstreamAuthorizeUrl`, `upstreamTokenService` | The IdP's authorize and token endpoints |
| `upstreamClientId`, `upstreamClientSecret`, `upstreamClientAuthMethod` | The pre-registered IdP app |
| `upstreamScope` | Scope always sent to the IdP (e.g. Entra `api://…/.default offline_access`) |
| `signingSecret` | Key that signs client IDs and state, and encrypts wrapped codes and tokens |
| `enableCimd`, `cimdTrustedHosts` | CIMD, limited to allow-listed client hosts |
| `enableDcr`, `allowLoopbackRedirects`, `allowedRedirectUris` | DCR and its redirect-URI policy |
| `requireConsent` | Gateway consent page and browser binding (default on) |

### Example

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

### Positioning

Use it on an `mcp` API instance whose IdP can't register MCP clients itself. Chain order:
**MCP Support → this policy →** token validation (in the MCP server for now). It is stateless: no Redis and
no extra app to host. Because Omni Gateway can only call pre-configured hosts, CIMD works for
allow-listed client hosts only. If the IdP already supports CIMD, you don't need this policy:
point the protected-resource metadata at the IdP instead.
