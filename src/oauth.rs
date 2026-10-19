// Copyright 2026 Salesforce, Inc. All rights reserved.

//! Pure OAuth facade logic: discovery metadata, DCR, authorize, callback and token handling.
//! Nothing here touches the PDK runtime, so all of it is unit-tested directly.

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::cimd;
use crate::consent::{self, BrowserSecret, ConsentView};
use crate::seal::{self, Sealer, KIND_CLIENT, KIND_CODE, KIND_REFRESH, KIND_STATE, NONCE_LEN};
use crate::uri::{self, Params};

const WELL_KNOWN_PRM: &str = "/.well-known/oauth-protected-resource";
const WELL_KNOWN_AS: &str = "/.well-known/oauth-authorization-server";
const WELL_KNOWN_OIDC: &str = "/.well-known/openid-configuration";

const STATE_TTL_SECS: u64 = 600;
const CODE_TTL_SECS: u64 = 300;
const MIN_SECRET_LEN: usize = 32;
const MIN_SECRET_DISTINCT_CHARS: usize = 12;
const MIN_SECRET_BITS: f64 = 128.0;
/// Substrings of the example values in this project's docs and common placeholders.
const PLACEHOLDER_SECRET_MARKERS: [&str; 8] = [
    "changeme",
    "change_me",
    "placeholder",
    "generate",
    "your_",
    "your-",
    "example",
    "secret_at_least",
];
const OFFLINE_ACCESS: &str = "offline_access";
const MAX_REDIRECT_URIS: usize = 10;
const MAX_REDIRECT_URI_LEN: usize = 2048;
const MAX_CLIENT_NAME_CHARS: usize = 200;
const MAX_ERROR_DESCRIPTION_CHARS: usize = 200;

const AUTHORIZE_PARAMS: [&str; 8] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "state",
    "scope",
    "code_challenge",
    "code_challenge_method",
    "resource",
];
const TOKEN_PARAMS: [&str; 8] = [
    "grant_type",
    "code",
    "redirect_uri",
    "client_id",
    "code_verifier",
    "refresh_token",
    "scope",
    "resource",
];
const GRANT_TYPES: [&str; 2] = ["authorization_code", "refresh_token"];

// ---------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UpstreamAuth {
    ClientSecretPost,
    ClientSecretBasic,
    None,
}

pub struct RedirectPolicy {
    pub allow_loopback: bool,
    /// Exact URIs, or prefixes when they end in "/".
    pub allowed: Vec<String>,
}

impl RedirectPolicy {
    pub fn allows(&self, redirect_uri: &str) -> bool {
        if !uri::is_safe_redirect_uri(redirect_uri) {
            return false;
        }
        (self.allow_loopback && uri::is_loopback_http(redirect_uri))
            || self.allowed.iter().any(|allowed| {
                if allowed.ends_with('/') {
                    uri::matches_prefix(allowed, redirect_uri)
                } else {
                    redirect_uri == allowed
                }
            })
    }

    fn is_empty(&self) -> bool {
        !self.allow_loopback && self.allowed.is_empty()
    }
}

/// Plain configuration values, before validation.
pub struct OAuthInput {
    pub public_base_url: String,
    pub mcp_resource_path: String,
    pub upstream_authorize_url: String,
    pub upstream_client_id: String,
    pub upstream_client_secret: Option<String>,
    pub upstream_client_auth_method: String,
    pub upstream_scope: Option<String>,
    pub scopes_supported: Vec<String>,
    pub signing_secret: String,
    pub enable_dcr: bool,
    pub enable_cimd: bool,
    pub allow_loopback_redirects: bool,
    pub allowed_redirect_uris: Vec<String>,
    pub client_registration_ttl_seconds: i64,
    pub challenge_unauthenticated: bool,
    pub require_consent: bool,
}

pub struct OAuthSettings {
    pub issuer: String,
    pub resource_url: String,
    pub prm_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub callback_url: String,
    pub routes: Routes,
    pub upstream_authorize_url: String,
    pub upstream_client_id: String,
    pub upstream_client_secret: Option<String>,
    pub upstream_auth: UpstreamAuth,
    pub upstream_scope: Option<String>,
    pub scopes_supported: Vec<String>,
    pub sealer: Sealer,
    pub enable_dcr: bool,
    pub enable_cimd: bool,
    pub redirect_policy: RedirectPolicy,
    pub registration_ttl_secs: u64,
    pub challenge_unauthenticated: bool,
    /// Show the gateway consent page and bind the flow to the browser.
    pub require_consent: bool,
    /// Whether binding cookies can be `Secure` (`__Host-`): true unless publicBaseUrl is http.
    pub secure_cookies: bool,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn is_secure_or_loopback(parsed: &uri::ParsedUri) -> bool {
    parsed.scheme == "https"
        || (parsed.scheme == "http"
            && matches!(parsed.host.as_str(), "127.0.0.1" | "[::1]" | "localhost"))
}

/// Rejects short, placeholder and low-entropy signing secrets. Every DCR client_id is a public
/// HMAC sample, so a guessable secret could be brute-forced offline.
fn check_signing_secret(secret: &str) -> Result<(), String> {
    const GENERATE_HINT: &str = "generate one with `openssl rand -base64 48`";
    if secret.len() < MIN_SECRET_LEN {
        return Err(format!(
            "signingSecret must be at least {MIN_SECRET_LEN} characters; {GENERATE_HINT}"
        ));
    }
    let lower = secret.to_ascii_lowercase();
    if PLACEHOLDER_SECRET_MARKERS.iter().any(|m| lower.contains(m)) {
        return Err(format!(
            "signingSecret looks like a placeholder; {GENERATE_HINT}"
        ));
    }
    let distinct = secret.chars().collect::<BTreeSet<_>>().len();
    let alphabet: u32 = [
        (secret.chars().any(|c| c.is_ascii_lowercase()), 26),
        (secret.chars().any(|c| c.is_ascii_uppercase()), 26),
        (secret.chars().any(|c| c.is_ascii_digit()), 10),
        (secret.chars().any(|c| !c.is_ascii_alphanumeric()), 32),
    ]
    .iter()
    .filter(|(present, _)| *present)
    .map(|(_, size)| size)
    .sum();
    let estimated_bits = secret.chars().count() as f64 * f64::from(alphabet.max(1)).log2();
    if distinct < MIN_SECRET_DISTINCT_CHARS || estimated_bits < MIN_SECRET_BITS {
        return Err(format!(
            "signingSecret has too little entropy; {GENERATE_HINT}"
        ));
    }
    Ok(())
}

/// RFC 6749 section 3.3 scope-token: printable ASCII without space, `"` or `\`.
fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

/// Splits a space-separated scope string into unique tokens, keeping order.
fn scope_tokens(scope: &str) -> Vec<&str> {
    let mut tokens: Vec<&str> = Vec::new();
    for token in scope.split(' ').filter(|t| !t.is_empty()) {
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    }
    tokens
}

impl OAuthSettings {
    /// The scope to request from the IdP at /authorize. With `upstreamScope` set it is always that
    /// value. Otherwise the client may only request scopes from `scopesSupported` (plus
    /// `offline_access` for refresh tokens), and gets all of `scopesSupported` if it asks for none.
    fn effective_scope(&self, requested: Option<&str>) -> Result<String, String> {
        if let Some(fixed) = &self.upstream_scope {
            return Ok(fixed.clone());
        }
        let requested = requested.map(scope_tokens).unwrap_or_default();
        if requested.is_empty() {
            return Ok(self.scopes_supported.join(" "));
        }
        match requested
            .iter()
            .find(|s| **s != OFFLINE_ACCESS && !self.scopes_supported.iter().any(|a| a == *s))
        {
            Some(bad) => Err(format!(
                "scope '{}' is not supported",
                truncate_chars(bad, 64)
            )),
            None => Ok(requested.join(" ")),
        }
    }

    /// The scope to send on a refresh: `upstreamScope` if set, else the client's requested
    /// scope, which may only narrow the scope granted at authorization.
    fn refresh_scope(
        &self,
        granted: &str,
        requested: Option<&str>,
    ) -> Result<Option<String>, String> {
        if let Some(fixed) = &self.upstream_scope {
            return Ok(Some(fixed.clone()));
        }
        let granted = scope_tokens(granted);
        let requested = match requested.map(scope_tokens) {
            Some(tokens) if !tokens.is_empty() => tokens,
            _ => return Ok(Some(granted.join(" ")).filter(|s| !s.is_empty())),
        };
        match requested.iter().find(|s| !granted.contains(s)) {
            Some(bad) => Err(format!(
                "scope '{}' was not granted to this refresh token",
                truncate_chars(bad, 64)
            )),
            None => Ok(Some(requested.join(" "))),
        }
    }

    /// RFC 8707: a `resource` parameter, if sent, must name this MCP server.
    fn resource_matches(&self, resource: Option<&str>) -> bool {
        match resource {
            None => true,
            Some(resource) => {
                resource.trim_end_matches('/') == self.resource_url.trim_end_matches('/')
            }
        }
    }

    /// Scope hint for `WWW-Authenticate` challenges.
    pub fn challenge_scope(&self) -> Option<String> {
        let scopes: Vec<String> = if !self.scopes_supported.is_empty() {
            self.scopes_supported.clone()
        } else {
            self.upstream_scope
                .as_deref()
                .map(scope_tokens)
                .unwrap_or_default()
                .into_iter()
                .filter(|s| *s != OFFLINE_ACCESS)
                .map(str::to_string)
                .collect()
        };
        Some(scopes.join(" ")).filter(|s| !s.is_empty())
    }
}

fn truncate_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

impl OAuthSettings {
    pub fn build(input: OAuthInput) -> Result<Self, String> {
        let issuer = input
            .public_base_url
            .trim()
            .trim_end_matches('/')
            .to_string();
        if issuer.contains('?') || issuer.contains('#') {
            return Err("publicBaseUrl must not contain a query or fragment".into());
        }
        let parsed = uri::parse(&issuer).ok_or("publicBaseUrl is not a valid URL")?;
        if !is_secure_or_loopback(&parsed) {
            return Err("publicBaseUrl must use https (http is allowed only on loopback)".into());
        }
        let secure_cookies = parsed.scheme == "https";
        if parsed.has_userinfo {
            return Err("publicBaseUrl must not contain credentials".into());
        }
        let base_path = parsed.path_and_query.to_string();

        let mcp_path = input.mcp_resource_path.trim().to_string();
        if !mcp_path.starts_with('/') {
            return Err("mcpResourcePath must start with '/'".into());
        }

        check_signing_secret(&input.signing_secret)?;

        let upstream_authorize_url = input.upstream_authorize_url.trim().to_string();
        match uri::parse(&upstream_authorize_url) {
            Some(u) if !u.has_fragment && !u.has_userinfo && is_secure_or_loopback(&u) => {}
            _ => {
                return Err(
                    "upstreamAuthorizeUrl must be an absolute https URL (http only on loopback)"
                        .into(),
                )
            }
        }

        let upstream_auth = match input.upstream_client_auth_method.as_str() {
            "client_secret_post" => UpstreamAuth::ClientSecretPost,
            "client_secret_basic" => UpstreamAuth::ClientSecretBasic,
            "none" => UpstreamAuth::None,
            other => return Err(format!("unsupported upstreamClientAuthMethod '{other}'")),
        };
        let upstream_client_secret = non_empty(input.upstream_client_secret);
        if upstream_auth != UpstreamAuth::None && upstream_client_secret.is_none() {
            return Err(
                "upstreamClientSecret is required unless upstreamClientAuthMethod is none".into(),
            );
        }
        if input.upstream_client_id.trim().is_empty() {
            return Err("upstreamClientId must not be empty".into());
        }

        if !input.enable_dcr && !input.enable_cimd {
            return Err("enable at least one of enableDcr or enableCimd".into());
        }
        let redirect_policy = RedirectPolicy {
            allow_loopback: input.allow_loopback_redirects,
            allowed: input
                .allowed_redirect_uris
                .into_iter()
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
                .collect(),
        };
        for entry in &redirect_policy.allowed {
            if entry.ends_with('/') {
                if !uri::is_valid_prefix_entry(entry) {
                    return Err(format!(
                        "allowedRedirectUris prefix entry '{entry}' must be an http(s) URL with a \
                         host and a path ending in '/', without credentials, query or dot segments"
                    ));
                }
            } else if !uri::is_safe_redirect_uri(entry) {
                return Err(format!(
                    "allowedRedirectUris entry '{entry}' is not a valid absolute redirect URI"
                ));
            }
        }
        if input.enable_dcr && redirect_policy.is_empty() {
            return Err(
                "DCR needs allowLoopbackRedirects or at least one allowedRedirectUris entry".into(),
            );
        }
        if input.client_registration_ttl_seconds < 0 {
            return Err("clientRegistrationTtlSeconds must not be negative".into());
        }
        let upstream_scope = non_empty(input.upstream_scope);
        let scopes_supported: Vec<String> = input
            .scopes_supported
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        // Every client reaches the IdP through one shared app, so client-requested scopes must
        // never pass through unrestricted.
        if upstream_scope.is_none() && scopes_supported.is_empty() {
            return Err(
                "set upstreamScope or scopesSupported: client-requested scopes are only accepted \
                 from scopesSupported"
                    .into(),
            );
        }
        if let Some(bad) = scopes_supported.iter().find(|s| !is_scope_token(s)) {
            return Err(format!(
                "scopesSupported entry '{bad}' is not a valid scope"
            ));
        }

        Ok(Self {
            resource_url: format!("{issuer}{mcp_path}"),
            prm_url: format!("{issuer}{WELL_KNOWN_PRM}"),
            authorization_endpoint: format!("{issuer}/oauth/authorize"),
            token_endpoint: format!("{issuer}/oauth/token"),
            registration_endpoint: format!("{issuer}/oauth/register"),
            callback_url: format!("{issuer}/oauth/callback"),
            routes: Routes::new(&base_path, &mcp_path),
            issuer,
            upstream_authorize_url,
            upstream_client_id: input.upstream_client_id.trim().to_string(),
            upstream_client_secret,
            upstream_auth,
            upstream_scope,
            scopes_supported,
            sealer: Sealer::new(&input.signing_secret),
            enable_dcr: input.enable_dcr,
            enable_cimd: input.enable_cimd,
            redirect_policy,
            registration_ttl_secs: input.client_registration_ttl_seconds as u64,
            challenge_unauthenticated: input.challenge_unauthenticated,
            require_consent: input.require_consent,
            secure_cookies,
        })
    }

    fn registration_expiry(&self, now: u64) -> u64 {
        if self.registration_ttl_secs == 0 {
            0
        } else {
            now.saturating_add(self.registration_ttl_secs)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Route {
    ProtectedResourceMetadata,
    AuthorizationServerMetadata,
    Register,
    Authorize,
    Callback,
    Token,
    Preflight,
    MethodNotAllowed(&'static str),
    /// Not a facade endpoint: MCP traffic.
    Other,
}

pub struct Routes {
    prm: Vec<String>,
    asm: Vec<String>,
    register: String,
    authorize: String,
    callback: String,
    token: String,
}

impl Routes {
    fn new(base: &str, mcp: &str) -> Self {
        let mut prm = vec![
            format!("{base}{WELL_KNOWN_PRM}"),
            format!("{base}{WELL_KNOWN_PRM}{mcp}"),
            format!("{WELL_KNOWN_PRM}{base}{mcp}"),
            format!("{WELL_KNOWN_PRM}{base}"),
        ];
        let mut asm = vec![
            format!("{base}{WELL_KNOWN_AS}"),
            format!("{base}{WELL_KNOWN_OIDC}"),
            format!("{WELL_KNOWN_AS}{base}"),
            format!("{WELL_KNOWN_OIDC}{base}"),
        ];
        prm.dedup();
        asm.dedup();
        Self {
            prm,
            asm,
            register: format!("{base}/oauth/register"),
            authorize: format!("{base}/oauth/authorize"),
            callback: format!("{base}/oauth/callback"),
            token: format!("{base}/oauth/token"),
        }
    }

    pub fn route(&self, method: &str, path: &str) -> Route {
        let path = uri::route_path(path);
        let (route, allowed_method, allow) = if self.prm.iter().any(|p| p == path) {
            (Route::ProtectedResourceMetadata, "GET", "GET, OPTIONS")
        } else if self.asm.iter().any(|p| p == path) {
            (Route::AuthorizationServerMetadata, "GET", "GET, OPTIONS")
        } else if path == self.register {
            (Route::Register, "POST", "POST, OPTIONS")
        } else if path == self.authorize {
            (Route::Authorize, "GET", "GET")
        } else if path == self.callback {
            (Route::Callback, "GET", "GET")
        } else if path == self.token {
            (Route::Token, "POST", "POST, OPTIONS")
        } else {
            return Route::Other;
        };
        if method == allowed_method {
            route
        } else if method == "OPTIONS" && allow.contains("OPTIONS") {
            Route::Preflight
        } else {
            Route::MethodNotAllowed(allow)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Errors and clients
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct OAuthError {
    pub status: u32,
    pub error: &'static str,
    pub description: String,
}

impl OAuthError {
    fn new(status: u32, error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            error,
            description: description.into(),
        }
    }

    pub fn body(&self) -> Vec<u8> {
        json!({"error": self.error, "error_description": self.description})
            .to_string()
            .into_bytes()
    }
}

fn invalid_request(description: impl Into<String>) -> OAuthError {
    OAuthError::new(400, "invalid_request", description)
}

fn invalid_client(description: impl Into<String>) -> OAuthError {
    OAuthError::new(401, "invalid_client", description)
}

fn invalid_grant(description: impl Into<String>) -> OAuthError {
    OAuthError::new(400, "invalid_grant", description)
}

fn invalid_client_metadata(description: impl Into<String>) -> OAuthError {
    OAuthError::new(400, "invalid_client_metadata", description)
}

pub fn server_error() -> OAuthError {
    OAuthError::new(500, "server_error", "internal error")
}

pub fn temporarily_unavailable() -> OAuthError {
    OAuthError::new(
        503,
        "temporarily_unavailable",
        "the identity provider is unavailable",
    )
}

/// A client the facade recognises: from a sealed DCR client_id or a CIMD document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    /// Display name, shown on the consent page.
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct DcrClient {
    ru: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    iat: u64,
    /// Random nonce: makes every registration a distinct client, even with identical metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    j: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SealedState {
    /// Client fingerprint.
    cf: String,
    /// The MCP client's redirect URI.
    ru: String,
    /// The MCP client's own state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    st: Option<String>,
    /// Browser binding: name key of the cookie set on the consent page...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bk: Option<String>,
    /// ...and the fingerprint of its value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bh: Option<String>,
    /// The client's S256 PKCE code_challenge, verified by the gateway at /token.
    cc: String,
    /// The scope requested from the IdP, after the scopesSupported restriction.
    #[serde(default)]
    sc: String,
}

#[derive(Serialize, Deserialize)]
struct SealedCode {
    /// The IdP's authorization code.
    c: String,
    cf: String,
    ru: String,
    /// PKCE code_challenge carried from the authorization request.
    cc: String,
    /// Scope granted at authorization; bounds later refreshes.
    #[serde(default)]
    sc: String,
}

#[derive(Serialize, Deserialize)]
struct SealedRefresh {
    /// The IdP's refresh token.
    r: String,
    cf: String,
    /// Scope granted at authorization; a refresh may only narrow it.
    #[serde(default)]
    sc: String,
}

/// Opens a DCR client_id issued by [`register`].
pub fn open_dcr_client(o: &OAuthSettings, client_id: &str, now: u64) -> Result<ClientInfo, String> {
    if !o.enable_dcr {
        return Err("dynamically registered clients are not accepted".into());
    }
    let client: DcrClient = o
        .sealer
        .open(KIND_CLIENT, client_id, now)
        .map_err(|_| "unknown or expired client_id".to_string())?;
    Ok(ClientInfo {
        client_id: client_id.to_string(),
        redirect_uris: client.ru,
        name: client.n,
    })
}

// ---------------------------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------------------------

pub fn protected_resource_metadata(o: &OAuthSettings) -> Value {
    let mut metadata = json!({
        "resource": o.resource_url,
        "authorization_servers": [o.issuer],
        "bearer_methods_supported": ["header"],
    });
    if !o.scopes_supported.is_empty() {
        metadata["scopes_supported"] = json!(o.scopes_supported);
    }
    metadata
}

pub fn authorization_server_metadata(o: &OAuthSettings) -> Value {
    let mut metadata = json!({
        "issuer": o.issuer,
        "authorization_endpoint": o.authorization_endpoint,
        "token_endpoint": o.token_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": GRANT_TYPES,
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": o.enable_cimd,
    });
    if o.enable_dcr {
        metadata["registration_endpoint"] = json!(o.registration_endpoint);
    }
    if !o.scopes_supported.is_empty() {
        metadata["scopes_supported"] = json!(o.scopes_supported);
    }
    metadata
}

/// `WWW-Authenticate` value with `resource_metadata` (and `scope`, when known and not already
/// present), or `None` if `existing` already has `resource_metadata`.
pub fn challenge_with_metadata(
    existing: Option<&str>,
    prm_url: &str,
    scope: Option<&str>,
) -> Option<String> {
    let mut parameter = format!("resource_metadata=\"{prm_url}\"");
    let has_scope = existing.is_some_and(|value| value.contains("scope="));
    if let Some(scope) = scope.filter(|_| !has_scope) {
        parameter.push_str(&format!(", scope=\"{scope}\""));
    }
    match existing.map(str::trim) {
        Some(value) if value.contains("resource_metadata=") => None,
        Some(value) if value.eq_ignore_ascii_case("bearer") => Some(format!("Bearer {parameter}")),
        Some(value)
            if value.len() > 7
                && value
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("bearer ")) =>
        {
            Some(format!("{value}, {parameter}"))
        }
        _ => Some(format!("Bearer {parameter}")),
    }
}

/// `existing` comma-separated header list with `token` appended, or `None` if it's already
/// there (compared case-insensitively).
pub fn with_list_token(existing: Option<&str>, token: &str) -> Option<String> {
    match existing.map(str::trim).filter(|v| !v.is_empty()) {
        None => Some(token.to_string()),
        Some(value)
            if value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case(token) || item.trim() == "*") =>
        {
            None
        }
        Some(value) => Some(format!("{value}, {token}")),
    }
}

// ---------------------------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------------------------

/// `nonce` should be random per registration; without one, identical registrations made in the
/// same second yield the same client_id.
pub fn register(
    o: &OAuthSettings,
    body: &[u8],
    now: u64,
    nonce: Option<&str>,
) -> Result<Value, OAuthError> {
    if !o.enable_dcr {
        return Err(OAuthError::new(
            404,
            "invalid_request",
            "dynamic client registration is disabled",
        ));
    }
    let request: Value = serde_json::from_slice(body)
        .map_err(|_| invalid_client_metadata("body must be a JSON object"))?;
    let request = request
        .as_object()
        .ok_or_else(|| invalid_client_metadata("body must be a JSON object"))?;

    let redirect_uris = request
        .get("redirect_uris")
        .and_then(Value::as_array)
        .filter(|uris| !uris.is_empty())
        .ok_or_else(|| OAuthError::new(400, "invalid_redirect_uri", "redirect_uris is required"))?;
    if redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(OAuthError::new(
            400,
            "invalid_redirect_uri",
            "too many redirect_uris",
        ));
    }
    let mut accepted = Vec::with_capacity(redirect_uris.len());
    for value in redirect_uris {
        let redirect_uri = value
            .as_str()
            .filter(|u| u.len() <= MAX_REDIRECT_URI_LEN && uri::is_safe_redirect_uri(u))
            .ok_or_else(|| {
                OAuthError::new(
                    400,
                    "invalid_redirect_uri",
                    "redirect_uris must be absolute URIs without fragments or dot segments",
                )
            })?;
        if !o.redirect_policy.allows(redirect_uri) {
            return Err(OAuthError::new(
                400,
                "invalid_redirect_uri",
                format!("redirect_uri '{redirect_uri}' is not allowed by this server"),
            ));
        }
        accepted.push(redirect_uri.to_string());
    }

    let grant_types = string_list(request.get("grant_types"), &GRANT_TYPES, "grant_types")?
        .unwrap_or_else(|| GRANT_TYPES.iter().map(|g| g.to_string()).collect());
    if !grant_types.iter().any(|g| g == "authorization_code") {
        return Err(invalid_client_metadata(
            "grant_types must include authorization_code",
        ));
    }
    string_list(request.get("response_types"), &["code"], "response_types")?;

    let client_name = match request.get("client_name") {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) if name.chars().count() <= MAX_CLIENT_NAME_CHARS => {
            Some(consent::sanitize_name(name)).filter(|n| !n.is_empty())
        }
        Some(_) => {
            return Err(invalid_client_metadata(
                "client_name must be a short string",
            ))
        }
    };

    let client = DcrClient {
        ru: accepted.clone(),
        n: client_name.clone(),
        iat: now,
        j: nonce.map(str::to_string),
    };
    let client_id = o
        .sealer
        .seal(KIND_CLIENT, &client, o.registration_expiry(now))
        .map_err(|_| server_error())?;
    // Never hand out a client_id that /authorize could not open.
    if client_id.len() > seal::MAX_SEALED_LEN {
        return Err(invalid_client_metadata(
            "registration is too large: use fewer or shorter redirect_uris",
        ));
    }

    let mut response = json!({
        "client_id": client_id,
        "client_id_issued_at": now,
        "redirect_uris": accepted,
        "grant_types": grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    if let Some(name) = client_name {
        response["client_name"] = json!(name);
    }
    Ok(response)
}

/// Validates an optional array of strings against an allowed set.
fn string_list(
    value: Option<&Value>,
    allowed: &[&str],
    field: &str,
) -> Result<Option<Vec<String>>, OAuthError> {
    let values = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(values)) => values,
        Some(_) => return Err(invalid_client_metadata(format!("{field} must be an array"))),
    };
    values
        .iter()
        .map(|v| match v.as_str() {
            Some(s) if allowed.contains(&s) => Ok(s.to_string()),
            _ => Err(invalid_client_metadata(format!(
                "{field} may only contain {}",
                allowed.join(", ")
            ))),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

// ---------------------------------------------------------------------------------------------
// Authorization endpoint and IdP callback
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum BrowserOutcome {
    Redirect(String),
    /// A redirect that also expires a binding cookie (location, `Set-Cookie` value).
    RedirectClearingCookie(String, String),
    /// The gateway consent page, shown before the browser goes to the IdP.
    Consent(ConsentPage),
    /// Shown to the user when it is not safe to redirect.
    BadRequest(String),
}

#[derive(Debug, PartialEq)]
pub struct ConsentPage {
    pub html: String,
    /// `Set-Cookie` value binding this sign-in to the browser.
    pub set_cookie: String,
    /// Where "Continue" leads: the IdP authorization URL.
    pub continue_url: String,
    /// Where "Cancel" leads: the client's redirect URI with error=access_denied.
    pub cancel_url: String,
}

pub fn authorize_client_id(params: &Params) -> Result<&str, String> {
    if let Some(name) = params.first_duplicate(&AUTHORIZE_PARAMS) {
        return Err(format!("parameter '{name}' must not be repeated"));
    }
    params
        .get("client_id")
        .ok_or_else(|| "client_id is required".to_string())
}

fn error_redirect(
    redirect_uri: &str,
    error: &str,
    description: Option<&str>,
    state: Option<&str>,
    issuer: &str,
) -> String {
    let mut params = vec![("error", error)];
    if let Some(description) = description {
        params.push(("error_description", description));
    }
    if let Some(state) = state {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    uri::append_query(redirect_uri, &params)
}

fn is_valid_code_challenge(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

/// Validates an authorization request for an already resolved `client`. With `require_consent`,
/// returns the consent page, whose "Continue" link goes to the IdP; otherwise redirects straight
/// to the IdP. `browser` must be fresh random values when consent is required.
pub fn authorize(
    o: &OAuthSettings,
    client: &ClientInfo,
    params: &Params,
    now: u64,
    browser: Option<&BrowserSecret>,
) -> BrowserOutcome {
    let redirect_uri = match params.get("redirect_uri") {
        Some(redirect_uri) => redirect_uri,
        None => return BrowserOutcome::BadRequest("redirect_uri is required".into()),
    };
    if !client
        .redirect_uris
        .iter()
        .any(|registered| uri::redirect_matches(registered, redirect_uri))
    {
        return BrowserOutcome::BadRequest("redirect_uri is not registered for this client".into());
    }

    let state = params.get("state");
    let fail = |error: &str, description: &str| {
        BrowserOutcome::Redirect(error_redirect(
            redirect_uri,
            error,
            Some(description),
            state,
            &o.issuer,
        ))
    };

    if params.get("response_type") != Some("code") {
        return fail("unsupported_response_type", "response_type must be code");
    }
    let code_challenge = match params.get("code_challenge") {
        Some(challenge) if is_valid_code_challenge(challenge) => challenge,
        Some(_) => return fail("invalid_request", "code_challenge is malformed"),
        None => return fail("invalid_request", "PKCE code_challenge is required"),
    };
    if params.get("code_challenge_method") != Some("S256") {
        return fail("invalid_request", "code_challenge_method must be S256");
    }
    if !o.resource_matches(params.get("resource")) {
        return fail("invalid_target", "resource must be this MCP server");
    }
    let scope = match o.effective_scope(params.get("scope")) {
        Ok(scope) => scope,
        Err(description) => return fail("invalid_scope", description.as_str()),
    };

    let browser = if o.require_consent {
        match browser {
            Some(browser) => Some(browser),
            // Fail closed: without a binding the consent page could be bypassed.
            None => return fail("server_error", "internal error"),
        }
    } else {
        None
    };
    let sealed_state = SealedState {
        cf: seal::fingerprint(&client.client_id),
        ru: redirect_uri.to_string(),
        st: state.map(str::to_string),
        bk: browser.map(|b| b.key.clone()),
        bh: browser.map(|b| seal::fingerprint(&b.value)),
        cc: code_challenge.to_string(),
        sc: scope.clone(),
    };
    let sealed_state = match o.sealer.seal(
        KIND_STATE,
        &sealed_state,
        now.saturating_add(STATE_TTL_SECS),
    ) {
        Ok(sealed) => sealed,
        Err(_) => return fail("server_error", "internal error"),
    };

    let mut upstream = vec![
        ("response_type", "code"),
        ("client_id", o.upstream_client_id.as_str()),
        ("redirect_uri", o.callback_url.as_str()),
        ("state", sealed_state.as_str()),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ];
    if !scope.is_empty() {
        upstream.push(("scope", scope.as_str()));
    }
    let continue_url = uri::append_query(&o.upstream_authorize_url, &upstream);

    let browser = match browser {
        Some(browser) => browser,
        None => return BrowserOutcome::Redirect(continue_url),
    };
    let cancel_url = error_redirect(
        redirect_uri,
        "access_denied",
        Some("the user declined the authorization request"),
        state,
        &o.issuer,
    );
    let html = consent::render(&ConsentView {
        client_name: client.name.as_deref(),
        client_host: consent::client_host(&client.client_id),
        redirect_display: consent::redirect_display(redirect_uri),
        loopback: uri::is_loopback_http(redirect_uri),
        insecure_http: consent::is_insecure_http(redirect_uri),
        scopes: scope_tokens(&scope),
        resource: &o.resource_url,
        continue_url: &continue_url,
        cancel_url: &cancel_url,
    });
    BrowserOutcome::Consent(ConsentPage {
        html,
        set_cookie: consent::set_cookie(o.secure_cookies, browser),
        continue_url,
        cancel_url,
    })
}

/// Whether the callback arrived in the browser that saw the consent page.
fn browser_matches(o: &OAuthSettings, state: &SealedState, cookie_header: Option<&str>) -> bool {
    match (&state.bk, &state.bh) {
        (None, None) => !o.require_consent,
        (Some(key), Some(hash)) => {
            let name = consent::cookie_name(o.secure_cookies, key);
            consent::cookie_value(cookie_header, &name)
                .is_some_and(|value| seal::fingerprint(value) == *hash)
        }
        _ => false,
    }
}

fn sanitize_error_code(error: &str) -> &str {
    if !error.is_empty() && error.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        error
    } else {
        "access_denied"
    }
}

/// Handles the IdP's redirect back to the gateway and forwards the result to the MCP client.
/// `cookie_header` is the request's `Cookie` header, checked against the consent binding.
/// `nonce` must be fresh random bytes; it encrypts the wrapped code.
pub fn callback(
    o: &OAuthSettings,
    params: &Params,
    cookie_header: Option<&str>,
    now: u64,
    nonce: &[u8; NONCE_LEN],
) -> BrowserOutcome {
    let state: SealedState = match params
        .get("state")
        .ok_or(())
        .and_then(|s| o.sealer.open(KIND_STATE, s, now).map_err(|_| ()))
    {
        Ok(state) => state,
        Err(()) => {
            return BrowserOutcome::BadRequest(
                "The sign-in request is invalid or has expired. Start the connection again from your MCP client.".into(),
            )
        }
    };
    if !browser_matches(o, &state, cookie_header) {
        return BrowserOutcome::BadRequest(
            "This sign-in was not started in this browser, or it took too long. Start the connection again from your MCP client in this browser.".into(),
        );
    }
    let client_state = state.st.as_deref();
    // The binding has done its job: expire the cookie on every redirect from here on.
    let finish = |location: String| match &state.bk {
        Some(key) => BrowserOutcome::RedirectClearingCookie(
            location,
            consent::clear_cookie(o.secure_cookies, key),
        ),
        None => BrowserOutcome::Redirect(location),
    };

    if let Some(error) = params.get("error") {
        let description: Option<String> = params
            .get("error_description")
            .map(|d| d.chars().take(MAX_ERROR_DESCRIPTION_CHARS).collect());
        return finish(error_redirect(
            &state.ru,
            sanitize_error_code(error),
            description.as_deref(),
            client_state,
            &o.issuer,
        ));
    }

    let server_error = || {
        finish(error_redirect(
            &state.ru,
            "server_error",
            None,
            client_state,
            &o.issuer,
        ))
    };
    let upstream_code = match params.get("code") {
        Some(code) => code,
        None => return server_error(),
    };
    let sealed_code = SealedCode {
        c: upstream_code.to_string(),
        cf: state.cf.clone(),
        ru: state.ru.clone(),
        cc: state.cc.clone(),
        sc: state.sc.clone(),
    };
    let code = match o.sealer.seal_encrypted(
        KIND_CODE,
        &sealed_code,
        now.saturating_add(CODE_TTL_SECS),
        nonce,
    ) {
        Ok(code) => code,
        Err(_) => return server_error(),
    };

    let mut response = vec![("code", code.as_str())];
    if let Some(client_state) = client_state {
        response.push(("state", client_state));
    }
    response.push(("iss", o.issuer.as_str()));
    finish(uri::append_query(&state.ru, &response))
}

// ---------------------------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
pub struct UpstreamTokenRequest {
    /// `application/x-www-form-urlencoded` body for the IdP token endpoint.
    pub form: String,
    /// `Authorization` header value for client_secret_basic.
    pub authorization: Option<String>,
    /// Fingerprint of the MCP client, used to bind the re-sealed refresh token.
    pub client_fingerprint: String,
    /// Scope granted at authorization, carried into the re-sealed refresh token.
    pub granted_scope: String,
}

/// client_id from an HTTP Basic `Authorization` header, if one is present.
fn basic_client_id(authorization: Option<&str>) -> Result<Option<String>, OAuthError> {
    let value = match authorization.map(str::trim) {
        Some(value)
            if value.len() > 6
                && value
                    .get(..6)
                    .is_some_and(|s| s.eq_ignore_ascii_case("basic ")) =>
        {
            value.get(6..).unwrap_or_default().trim()
        }
        _ => return Ok(None),
    };
    let decoded = STANDARD
        .decode(value)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| invalid_client("malformed Basic credentials"))?;
    let user = decoded
        .split_once(':')
        .map(|(user, _)| user)
        .unwrap_or(&decoded);
    let user: String = serde_urlencoded::from_str::<Vec<(String, String)>>(&format!("u={user}"))
        .ok()
        .and_then(|pairs| pairs.into_iter().next())
        .map(|(_, value)| value)
        .unwrap_or_else(|| user.to_string());
    Ok(Some(user).filter(|u| !u.is_empty()))
}

/// Validates an MCP client's token request and builds the request to send to the IdP.
pub fn token_request(
    o: &OAuthSettings,
    body: &[u8],
    authorization: Option<&str>,
    now: u64,
) -> Result<UpstreamTokenRequest, OAuthError> {
    let params = Params::from_form(body)
        .ok_or_else(|| invalid_request("body must be application/x-www-form-urlencoded"))?;
    if let Some(name) = params.first_duplicate(&TOKEN_PARAMS) {
        return Err(invalid_request(format!(
            "parameter '{name}' must not be repeated"
        )));
    }

    let basic = basic_client_id(authorization)?;
    let client_id: String = match (params.get("client_id"), basic) {
        (Some(form), Some(basic)) if form != basic => {
            return Err(invalid_request(
                "client_id in the body and the Authorization header differ",
            ))
        }
        (Some(form), _) => form.to_string(),
        (None, Some(basic)) => basic,
        (None, None) => return Err(invalid_client("client_id is required")),
    };
    if cimd::is_cimd_client_id(&client_id) {
        if !o.enable_cimd {
            return Err(invalid_client(
                "client metadata document clients are not accepted",
            ));
        }
    } else {
        open_dcr_client(o, &client_id, now).map_err(invalid_client)?;
    }
    let client_fingerprint = seal::fingerprint(&client_id);
    if !o.resource_matches(params.get("resource")) {
        return Err(OAuthError::new(
            400,
            "invalid_target",
            "resource must be this MCP server",
        ));
    }

    let require = |name: &str| {
        params
            .get(name)
            .ok_or_else(|| invalid_request(format!("{name} is required")))
    };
    let mut form: Vec<(&str, String)> = Vec::new();
    let granted_scope = match require("grant_type")? {
        "authorization_code" => {
            let code = require("code")?;
            let redirect_uri = require("redirect_uri")?;
            let code_verifier = require("code_verifier")?;
            let sealed: SealedCode = o
                .sealer
                .open_encrypted(KIND_CODE, code, now)
                .map_err(|_| invalid_grant("authorization code is invalid or expired"))?;
            if sealed.cf != client_fingerprint {
                return Err(invalid_grant(
                    "authorization code was issued to another client",
                ));
            }
            if sealed.ru != redirect_uri {
                return Err(invalid_grant(
                    "redirect_uri does not match the authorization request",
                ));
            }
            // PKCE is verified here, not left to the IdP: the gateway adds its own client
            // credentials upstream, so the IdP may not bind the verifier to this client.
            if !seal::is_valid_code_verifier(code_verifier) {
                return Err(invalid_request("code_verifier is malformed"));
            }
            if !seal::pkce_s256_matches(code_verifier, &sealed.cc) {
                return Err(invalid_grant(
                    "code_verifier does not match the code_challenge",
                ));
            }
            form.push(("grant_type", "authorization_code".into()));
            form.push(("code", sealed.c));
            form.push(("redirect_uri", o.callback_url.clone()));
            // Still forwarded, as defense in depth for IdPs that also enforce PKCE.
            form.push(("code_verifier", code_verifier.to_string()));
            sealed.sc
        }
        "refresh_token" => {
            let sealed: SealedRefresh = o
                .sealer
                .open_encrypted(KIND_REFRESH, require("refresh_token")?, now)
                .map_err(|_| invalid_grant("refresh token is invalid or expired"))?;
            if sealed.cf != client_fingerprint {
                return Err(invalid_grant("refresh token was issued to another client"));
            }
            let scope = o
                .refresh_scope(&sealed.sc, params.get("scope"))
                .map_err(|description| OAuthError::new(400, "invalid_scope", description))?;
            form.push(("grant_type", "refresh_token".into()));
            form.push(("refresh_token", sealed.r));
            if let Some(scope) = &scope {
                form.push(("scope", scope.clone()));
            }
            // A narrowed refresh keeps the original grant as the bound for later refreshes.
            sealed.sc
        }
        _ => {
            return Err(OAuthError::new(
                400,
                "unsupported_grant_type",
                "grant_type must be authorization_code or refresh_token",
            ))
        }
    };

    let secret = o.upstream_client_secret.clone().unwrap_or_default();
    let authorization = match o.upstream_auth {
        UpstreamAuth::ClientSecretPost => {
            form.push(("client_id", o.upstream_client_id.clone()));
            form.push(("client_secret", secret));
            None
        }
        UpstreamAuth::None => {
            form.push(("client_id", o.upstream_client_id.clone()));
            None
        }
        UpstreamAuth::ClientSecretBasic => {
            // RFC 6749 section 2.3.1: form-encode each part before joining.
            let id = form_encode(&o.upstream_client_id);
            let secret = form_encode(&secret);
            Some(format!(
                "Basic {}",
                STANDARD.encode(format!("{id}:{secret}"))
            ))
        }
    };

    Ok(UpstreamTokenRequest {
        form: serde_urlencoded::to_string(&form).map_err(|_| server_error())?,
        authorization,
        client_fingerprint,
        granted_scope,
    })
}

fn form_encode(value: &str) -> String {
    serde_urlencoded::to_string([("v", value)])
        .ok()
        .and_then(|encoded| encoded.strip_prefix("v=").map(str::to_string))
        .unwrap_or_default()
}

/// The IdP rejected the gateway's own client credentials. Surfaced as a gateway error: relaying
/// `invalid_client` would make MCP clients think their registration is bad and re-register.
pub fn upstream_auth_failed() -> OAuthError {
    OAuthError::new(
        502,
        "server_error",
        "the gateway could not authenticate to the identity provider",
    )
}

/// Turns the IdP's token response into the response for the MCP client. `nonce` must be fresh
/// random bytes; it encrypts the wrapped refresh token. The IdP's `id_token` is dropped: its
/// issuer is the IdP, not this authorization server.
pub fn token_response(
    o: &OAuthSettings,
    status: u32,
    body: &[u8],
    request: &UpstreamTokenRequest,
    now: u64,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, OAuthError> {
    match status {
        200 => {
            let mut token: Map<String, Value> = match serde_json::from_slice(body) {
                Ok(Value::Object(token)) => token,
                _ => {
                    return Err(OAuthError::new(
                        502,
                        "server_error",
                        "invalid token response from the identity provider",
                    ))
                }
            };
            token.remove("id_token");
            if let Some(Value::String(refresh_token)) = token.get("refresh_token").cloned() {
                let sealed = SealedRefresh {
                    r: refresh_token,
                    cf: request.client_fingerprint.clone(),
                    sc: request.granted_scope.clone(),
                };
                let sealed = o
                    .sealer
                    .seal_encrypted(KIND_REFRESH, &sealed, o.registration_expiry(now), nonce)
                    .map_err(|_| server_error())?;
                token.insert("refresh_token".into(), Value::String(sealed));
            }
            serde_json::to_vec(&token).map_err(|_| server_error())
        }
        401 => Err(upstream_auth_failed()),
        400..=499 => {
            // Pass OAuth errors through, but never relay a non-JSON body from the IdP.
            match serde_json::from_slice::<Value>(body) {
                Ok(Value::Object(error)) if error.get("error").is_some_and(Value::is_string) => {
                    let code = error
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("invalid_grant");
                    if matches!(code, "invalid_client" | "unauthorized_client") {
                        return Err(upstream_auth_failed());
                    }
                    let description = error
                        .get("error_description")
                        .and_then(Value::as_str)
                        .unwrap_or("rejected by the identity provider");
                    Err(OAuthError::new(
                        status,
                        known_token_error(code),
                        description
                            .chars()
                            .take(MAX_ERROR_DESCRIPTION_CHARS)
                            .collect::<String>(),
                    ))
                }
                _ => Err(OAuthError::new(
                    status,
                    "invalid_grant",
                    "rejected by the identity provider",
                )),
            }
        }
        _ => Err(temporarily_unavailable()),
    }
}

fn known_token_error(code: &str) -> &'static str {
    match code {
        "invalid_request" => "invalid_request",
        "unsupported_grant_type" => "unsupported_grant_type",
        "invalid_scope" => "invalid_scope",
        _ => "invalid_grant",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const NONCE: [u8; NONCE_LEN] = [9u8; NONCE_LEN];
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    /// RFC 7636 appendix B: the verifier whose S256 hash is CHALLENGE.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn input() -> OAuthInput {
        OAuthInput {
            public_base_url: "https://gw.example/mcp-server/".into(),
            mcp_resource_path: "/mcp".into(),
            upstream_authorize_url: "https://idp.example/authorize".into(),
            upstream_client_id: "upstream-client".into(),
            upstream_client_secret: Some("upstream-secret".into()),
            upstream_client_auth_method: "client_secret_post".into(),
            upstream_scope: None,
            scopes_supported: vec!["mcp.read".into()],
            signing_secret: "0123456789abcdef0123456789abcdef".into(),
            enable_dcr: true,
            enable_cimd: true,
            allow_loopback_redirects: true,
            allowed_redirect_uris: vec!["https://client.example/oauth/".into()],
            client_registration_ttl_seconds: 3600,
            challenge_unauthenticated: true,
            require_consent: true,
        }
    }

    fn settings() -> OAuthSettings {
        OAuthSettings::build(input()).unwrap()
    }

    fn dummy_request() -> UpstreamTokenRequest {
        UpstreamTokenRequest {
            form: String::new(),
            authorization: None,
            client_fingerprint: "f".into(),
            granted_scope: "mcp.read".into(),
        }
    }

    fn redirect(outcome: BrowserOutcome) -> String {
        match outcome {
            BrowserOutcome::Redirect(location) => location,
            BrowserOutcome::RedirectClearingCookie(location, _) => location,
            other => panic!("expected redirect, got {:?}", other),
        }
    }

    fn query_of(location: &str) -> Params {
        Params::from_query_of(location)
    }

    fn browser() -> BrowserSecret {
        BrowserSecret {
            key: "k1".into(),
            value: "browser-secret".into(),
        }
    }

    fn consent_page(outcome: BrowserOutcome) -> ConsentPage {
        match outcome {
            BrowserOutcome::Consent(page) => page,
            other => panic!("expected consent page, got {:?}", other),
        }
    }

    /// The `name=value` part of a Set-Cookie header, as the browser sends it back.
    fn cookie_of(page: &ConsentPage) -> String {
        page.set_cookie.split(';').next().unwrap().to_string()
    }

    fn without_consent() -> OAuthSettings {
        let mut i = input();
        i.require_consent = false;
        OAuthSettings::build(i).unwrap()
    }

    fn https_client() -> ClientInfo {
        ClientInfo {
            client_id: "c".into(),
            redirect_uris: vec!["https://client.example/cb".into()],
            name: None,
        }
    }

    fn valid_authorize_query(redirect_uri: &str) -> Params {
        Params::from_query_of(&format!(
            "/a?{}",
            serde_urlencoded::to_string([
                ("response_type", "code"),
                ("redirect_uri", redirect_uri),
                ("state", "client-state"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
            .unwrap()
        ))
    }

    /// Simulates the IdP sending the browser back with a code for the state in `continue_url`.
    fn idp_return(continue_url: &str) -> Params {
        let state = query_of(continue_url).get("state").unwrap().to_string();
        Params::from_query_of(&format!(
            "/cb?{}",
            serde_urlencoded::to_string([("code", "idp-code"), ("state", state.as_str())]).unwrap()
        ))
    }

    fn nonce() -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        format!("n{}", COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    fn register_loopback(o: &OAuthSettings) -> String {
        let body = br#"{"redirect_uris":["http://127.0.0.1:5000/cb"],"client_name":"Test"}"#;
        let response = register(o, body, NOW, Some(&nonce())).unwrap();
        response["client_id"].as_str().unwrap().to_string()
    }

    #[test]
    fn identical_registrations_get_distinct_ids() {
        let o = settings();
        assert_ne!(register_loopback(&o), register_loopback(&o));
    }

    /// Runs authorize + callback and returns (client_id, sealed code).
    fn code_for(o: &OAuthSettings) -> (String, String) {
        let client_id = register_loopback(o);
        let client = open_dcr_client(o, &client_id, NOW).unwrap();
        let params = Params::from_query_of(&format!(
            "/a?{}",
            serde_urlencoded::to_string([
                ("response_type", "code"),
                ("client_id", client_id.as_str()),
                ("redirect_uri", "http://127.0.0.1:6000/cb"),
                ("state", "client-state"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
            .unwrap()
        ));
        let page = consent_page(authorize(o, &client, &params, NOW, Some(&browser())));
        let cookie = cookie_of(&page);
        let to_client = redirect(callback(
            o,
            &idp_return(&page.continue_url),
            Some(&cookie),
            NOW,
            &NONCE,
        ));
        assert!(to_client.starts_with("http://127.0.0.1:6000/cb?"));
        let to_client = query_of(&to_client);
        assert_eq!(to_client.get("state"), Some("client-state"));
        assert_eq!(to_client.get("iss"), Some("https://gw.example/mcp-server"));
        (client_id, to_client.get("code").unwrap().to_string())
    }

    #[test]
    fn validates_configuration() {
        assert!(OAuthSettings::build(input()).is_ok());
        type Mutation = Box<dyn Fn(&mut OAuthInput)>;
        let cases: Vec<Mutation> = vec![
            Box::new(|i| i.public_base_url = "http://gw.example/mcp".into()),
            Box::new(|i| i.public_base_url = "https://gw.example/mcp?x=1".into()),
            Box::new(|i| i.mcp_resource_path = "mcp".into()),
            Box::new(|i| i.signing_secret = "short".into()),
            Box::new(|i| i.upstream_client_secret = None),
            Box::new(|i| i.upstream_client_auth_method = "private_key_jwt".into()),
            Box::new(|i| {
                i.enable_dcr = false;
                i.enable_cimd = false;
            }),
            Box::new(|i| {
                i.allow_loopback_redirects = false;
                i.allowed_redirect_uris = vec![];
            }),
            Box::new(|i| i.allowed_redirect_uris = vec!["/relative".into()]),
            Box::new(|i| i.client_registration_ttl_seconds = -1),
        ];
        for (index, mutate) in cases.iter().enumerate() {
            let mut i = input();
            mutate(&mut i);
            assert!(OAuthSettings::build(i).is_err(), "case {}", index);
        }
        let mut local = input();
        local.public_base_url = "http://localhost:8081/mcp".into();
        assert!(OAuthSettings::build(local).is_ok());
    }

    #[test]
    fn routes_requests() {
        let routes = &settings().routes;
        let b = "/mcp-server";
        assert_eq!(
            routes.route("GET", &format!("{b}/.well-known/oauth-protected-resource")),
            Route::ProtectedResourceMetadata
        );
        assert_eq!(
            routes.route(
                "GET",
                &format!("{b}/.well-known/oauth-protected-resource/mcp")
            ),
            Route::ProtectedResourceMetadata
        );
        assert_eq!(
            routes.route(
                "GET",
                "/.well-known/oauth-protected-resource/mcp-server/mcp"
            ),
            Route::ProtectedResourceMetadata
        );
        assert_eq!(
            routes.route("GET", &format!("{b}/.well-known/openid-configuration")),
            Route::AuthorizationServerMetadata
        );
        assert_eq!(
            routes.route("GET", "/.well-known/oauth-authorization-server/mcp-server"),
            Route::AuthorizationServerMetadata
        );
        assert_eq!(
            routes.route("POST", &format!("{b}/oauth/register")),
            Route::Register
        );
        assert_eq!(
            routes.route("GET", &format!("{b}/oauth/authorize?client_id=x")),
            Route::Authorize
        );
        assert_eq!(
            routes.route("GET", &format!("{b}/oauth/callback/")),
            Route::Callback
        );
        assert_eq!(
            routes.route("POST", &format!("{b}/oauth/token")),
            Route::Token
        );
        assert_eq!(
            routes.route("OPTIONS", &format!("{b}/oauth/token")),
            Route::Preflight
        );
        assert_eq!(
            routes.route("GET", &format!("{b}/oauth/token")),
            Route::MethodNotAllowed("POST, OPTIONS")
        );
        assert_eq!(routes.route("POST", &format!("{b}/mcp")), Route::Other);
        assert_eq!(routes.route("OPTIONS", &format!("{b}/mcp")), Route::Other);
    }

    #[test]
    fn serves_metadata() {
        let o = settings();
        let prm = protected_resource_metadata(&o);
        assert_eq!(prm["resource"], "https://gw.example/mcp-server/mcp");
        assert_eq!(
            prm["authorization_servers"][0],
            "https://gw.example/mcp-server"
        );
        let asm = authorization_server_metadata(&o);
        assert_eq!(asm["issuer"], "https://gw.example/mcp-server");
        assert_eq!(
            asm["registration_endpoint"],
            "https://gw.example/mcp-server/oauth/register"
        );
        assert_eq!(asm["client_id_metadata_document_supported"], true);
        assert_eq!(asm["code_challenge_methods_supported"][0], "S256");

        let mut no_dcr = input();
        no_dcr.enable_dcr = false;
        let asm = authorization_server_metadata(&OAuthSettings::build(no_dcr).unwrap());
        assert!(asm.get("registration_endpoint").is_none());
    }

    #[test]
    fn builds_challenges() {
        let prm = "https://gw.example/mcp-server/.well-known/oauth-protected-resource";
        let expected = format!("Bearer resource_metadata=\"{prm}\"");
        assert_eq!(
            challenge_with_metadata(None, prm, None),
            Some(expected.clone())
        );
        assert_eq!(
            challenge_with_metadata(Some("Bearer"), prm, None),
            Some(expected)
        );
        assert_eq!(
            challenge_with_metadata(Some("Bearer realm=\"api\""), prm, None),
            Some(format!("Bearer realm=\"api\", resource_metadata=\"{prm}\""))
        );
        assert_eq!(
            challenge_with_metadata(Some("Bearer resource_metadata=\"x\""), prm, None),
            None
        );
        assert_eq!(
            challenge_with_metadata(None, prm, Some("mcp.read")),
            Some(format!(
                "Bearer resource_metadata=\"{prm}\", scope=\"mcp.read\""
            ))
        );
        // An existing scope parameter is kept, not duplicated.
        assert_eq!(
            challenge_with_metadata(Some("Bearer scope=\"a\""), prm, Some("mcp.read")),
            Some(format!("Bearer scope=\"a\", resource_metadata=\"{prm}\""))
        );
        assert_eq!(settings().challenge_scope().as_deref(), Some("mcp.read"));
    }

    #[test]
    fn appends_list_tokens_without_duplicates() {
        assert_eq!(
            with_list_token(None, "www-authenticate").as_deref(),
            Some("www-authenticate")
        );
        assert_eq!(
            with_list_token(Some("x-request-id"), "www-authenticate").as_deref(),
            Some("x-request-id, www-authenticate")
        );
        assert_eq!(
            with_list_token(Some("X-Id, WWW-Authenticate"), "www-authenticate"),
            None
        );
        assert_eq!(with_list_token(Some("*"), "www-authenticate"), None);
    }

    #[test]
    fn registers_clients() {
        let o = settings();
        let response = register(
            &o,
            br#"{"redirect_uris":["http://localhost:1234/cb","https://client.example/oauth/cb"],"client_name":"My client","token_endpoint_auth_method":"client_secret_basic"}"#,
            NOW,
            None,
        )
        .unwrap();
        assert_eq!(response["token_endpoint_auth_method"], "none");
        assert_eq!(response["client_name"], "My client");
        assert_eq!(response["client_id_issued_at"], NOW);
        let client_id = response["client_id"].as_str().unwrap();
        let client = open_dcr_client(&o, client_id, NOW).unwrap();
        assert_eq!(client.redirect_uris.len(), 2);
        assert!(
            open_dcr_client(&o, client_id, NOW + 3600).is_err(),
            "expires"
        );
    }

    #[test]
    fn rejects_bad_registrations() {
        let o = settings();
        let cases: [&[u8]; 8] = [
            b"not json",
            br#"{}"#,
            br#"{"redirect_uris":[]}"#,
            br#"{"redirect_uris":["https://evil.example/cb"]}"#,
            br#"{"redirect_uris":["https://client.example/oauthx"]}"#,
            br#"{"redirect_uris":["http://localhost/cb#frag"]}"#,
            br#"{"redirect_uris":["http://localhost/cb"],"grant_types":["client_credentials"]}"#,
            br#"{"redirect_uris":["http://localhost/cb"],"response_types":["token"]}"#,
        ];
        for body in cases {
            assert!(
                register(&o, body, NOW, None).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let mut no_dcr = input();
        no_dcr.enable_dcr = false;
        let o = OAuthSettings::build(no_dcr).unwrap();
        assert_eq!(
            register(
                &o,
                br#"{"redirect_uris":["http://localhost/cb"]}"#,
                NOW,
                None
            )
            .unwrap_err()
            .status,
            404
        );
    }

    #[test]
    fn authorize_redirects_to_idp() {
        let o = settings();
        let client = ClientInfo {
            client_id: "https://client.example/m.json".into(),
            redirect_uris: vec!["https://client.example/cb".into()],
            name: Some("Example Client".into()),
        };
        let params = Params::from_query_of(&format!(
            "/a?response_type=code&client_id=x&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_challenge={CHALLENGE}&code_challenge_method=S256&scope=mcp.read&resource=https%3A%2F%2Fgw.example%2Fmcp-server%2Fmcp"
        ));
        let page = consent_page(authorize(&o, &client, &params, NOW, Some(&browser())));
        assert!(page.html.contains("<strong>Example Client</strong>"));
        assert!(page
            .html
            .contains("Identified by <strong>client.example</strong>"));
        assert!(
            !page.html.contains("class=\"warn\""),
            "no localhost warning for https redirects"
        );
        assert!(page
            .set_cookie
            .starts_with("__Host-mcp-auth-k1=browser-secret;"));
        let location = page.continue_url;
        assert!(location.starts_with("https://idp.example/authorize?"));
        let upstream = query_of(&location);
        assert_eq!(upstream.get("client_id"), Some("upstream-client"));
        assert_eq!(
            upstream.get("redirect_uri"),
            Some("https://gw.example/mcp-server/oauth/callback")
        );
        assert_eq!(upstream.get("code_challenge"), Some(CHALLENGE));
        assert_eq!(upstream.get("scope"), Some("mcp.read"));
        assert_eq!(upstream.get("resource"), None);
    }

    #[test]
    fn authorize_errors() {
        let o = settings();
        let client = https_client();
        let b = browser();
        let run = |query: &str| {
            authorize(
                &o,
                &client,
                &Params::from_query_of(&format!("/a?{query}")),
                NOW,
                Some(&b),
            )
        };
        let ok_redirect = "redirect_uri=https%3A%2F%2Fclient.example%2Fcb";

        assert!(matches!(
            run("response_type=code"),
            BrowserOutcome::BadRequest(_)
        ));
        assert!(matches!(
            run("redirect_uri=https%3A%2F%2Fevil.example%2Fcb"),
            BrowserOutcome::BadRequest(_)
        ));

        let location = redirect(run(&format!("{ok_redirect}&response_type=token&state=s")));
        let error = query_of(&location);
        assert_eq!(error.get("error"), Some("unsupported_response_type"));
        assert_eq!(error.get("state"), Some("s"));

        let location = redirect(run(&format!("{ok_redirect}&response_type=code")));
        assert_eq!(query_of(&location).get("error"), Some("invalid_request"));

        let location = redirect(run(&format!(
            "{ok_redirect}&response_type=code&code_challenge={CHALLENGE}&code_challenge_method=plain"
        )));
        assert_eq!(query_of(&location).get("error"), Some("invalid_request"));

        assert!(authorize_client_id(&Params::from_query_of("/a?client_id=a&client_id=b")).is_err());
        assert!(authorize_client_id(&Params::from_query_of("/a?x=1")).is_err());
    }

    #[test]
    fn upstream_scope_overrides_client_scope() {
        let mut i = input();
        i.upstream_scope = Some("api://mcp/.default offline_access".into());
        let o = OAuthSettings::build(i).unwrap();
        let client = https_client();
        let params = Params::from_query_of(&format!(
            "/a?response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_challenge={CHALLENGE}&code_challenge_method=S256&scope=other"
        ));
        let page = consent_page(authorize(&o, &client, &params, NOW, Some(&browser())));
        let upstream = query_of(&page.continue_url);
        assert_eq!(
            upstream.get("scope"),
            Some("api://mcp/.default offline_access")
        );
    }

    #[test]
    fn callback_handles_errors_and_bad_state() {
        let o = without_consent();
        assert!(matches!(
            callback(
                &o,
                &Params::from_query_of("/cb?code=x&state=forged"),
                None,
                NOW,
                &NONCE
            ),
            BrowserOutcome::BadRequest(_)
        ));

        let unbound = SealedState {
            cf: "f".into(),
            ru: "https://client.example/cb".into(),
            st: None,
            bk: None,
            bh: None,
            cc: CHALLENGE.into(),
            sc: String::new(),
        };
        let state = o.sealer.seal(KIND_STATE, &unbound, NOW + 600).unwrap();
        let query = serde_urlencoded::to_string([
            ("error", "access_denied\"><script>"),
            ("state", state.as_str()),
        ])
        .unwrap();
        let location = redirect(callback(
            &o,
            &Params::from_query_of(&format!("/cb?{query}")),
            None,
            NOW,
            &NONCE,
        ));
        let params = query_of(&location);
        assert_eq!(params.get("error"), Some("access_denied"));
        assert_eq!(params.get("state"), None);

        assert!(matches!(
            callback(
                &o,
                &Params::from_query_of(&format!("/cb?{query}")),
                None,
                NOW + 600,
                &NONCE
            ),
            BrowserOutcome::BadRequest(_)
        ));

        // A state minted without a browser binding is refused once consent is required.
        let o = settings();
        let state = o.sealer.seal(KIND_STATE, &unbound, NOW + 600).unwrap();
        let query =
            serde_urlencoded::to_string([("code", "x"), ("state", state.as_str())]).unwrap();
        assert!(matches!(
            callback(
                &o,
                &Params::from_query_of(&format!("/cb?{query}")),
                None,
                NOW,
                &NONCE
            ),
            BrowserOutcome::BadRequest(_)
        ));
    }

    #[test]
    fn consent_page_for_loopback_dcr_client() {
        let o = settings();
        let client_id = register_loopback(&o);
        let client = open_dcr_client(&o, &client_id, NOW).unwrap();
        let page = consent_page(authorize(
            &o,
            &client,
            &valid_authorize_query("http://127.0.0.1:6000/cb"),
            NOW,
            Some(&browser()),
        ));
        assert!(page.html.contains("<strong>Test</strong>"));
        assert!(
            page.html.contains("self-reported"),
            "DCR names are unverified"
        );
        assert!(page
            .html
            .contains("an app on this computer (http://127.0.0.1:6000)"));
        assert!(page.html.contains("https://gw.example/mcp-server/mcp"));

        let cancel = query_of(&page.cancel_url);
        assert!(page.cancel_url.starts_with("http://127.0.0.1:6000/cb?"));
        assert_eq!(cancel.get("error"), Some("access_denied"));
        assert_eq!(cancel.get("state"), Some("client-state"));
        assert_eq!(cancel.get("iss"), Some("https://gw.example/mcp-server"));
    }

    #[test]
    fn callback_requires_the_consenting_browser() {
        let o = settings();
        let page = consent_page(authorize(
            &o,
            &https_client(),
            &valid_authorize_query("https://client.example/cb"),
            NOW,
            Some(&browser()),
        ));
        let back = idp_return(&page.continue_url);
        let rejected = |cookie: Option<&str>| {
            matches!(
                callback(&o, &back, cookie, NOW, &NONCE),
                BrowserOutcome::BadRequest(_)
            )
        };

        // An attacker who sends a victim straight to the IdP link: no cookie in the victim's browser.
        assert!(rejected(None));
        assert!(rejected(Some("other=1")));
        assert!(rejected(Some("__Host-mcp-auth-k1=wrong-value")));
        assert!(rejected(Some("__Host-mcp-auth-k2=browser-secret")));
        assert!(
            rejected(Some("mcp-auth-k1=browser-secret")),
            "non-__Host- name is not accepted over https"
        );

        let cookie = format!("a=b; {}", cookie_of(&page));
        let location = redirect(callback(&o, &back, Some(&cookie), NOW, &NONCE));
        assert!(query_of(&location).get("code").is_some());
    }

    #[test]
    fn consent_fails_closed_without_randomness() {
        let o = settings();
        let location = redirect(authorize(
            &o,
            &https_client(),
            &valid_authorize_query("https://client.example/cb"),
            NOW,
            None,
        ));
        assert_eq!(query_of(&location).get("error"), Some("server_error"));
    }

    #[test]
    fn consent_can_be_disabled() {
        let o = without_consent();
        let location = redirect(authorize(
            &o,
            &https_client(),
            &valid_authorize_query("https://client.example/cb"),
            NOW,
            Some(&browser()),
        ));
        assert!(location.starts_with("https://idp.example/authorize?"));
        assert!(matches!(
            callback(&o, &idp_return(&location), None, NOW, &NONCE),
            BrowserOutcome::Redirect(_)
        ));
    }

    #[test]
    fn plain_http_issuer_uses_non_secure_cookie() {
        let mut i = input();
        i.public_base_url = "http://localhost:8081/mcp-server".into();
        let o = OAuthSettings::build(i).unwrap();
        let page = consent_page(authorize(
            &o,
            &https_client(),
            &valid_authorize_query("https://client.example/cb"),
            NOW,
            Some(&browser()),
        ));
        assert_eq!(
            page.set_cookie,
            "mcp-auth-k1=browser-secret; Path=/; HttpOnly; SameSite=Lax; Max-Age=600"
        );
        assert!(matches!(
            callback(
                &o,
                &idp_return(&page.continue_url),
                Some(&cookie_of(&page)),
                NOW,
                &NONCE
            ),
            BrowserOutcome::RedirectClearingCookie(_, clear)
                if clear == "mcp-auth-k1=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        ));
    }

    #[test]
    fn full_code_exchange() {
        let o = settings();
        let (client_id, code) = code_for(&o);
        let body = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "http://127.0.0.1:6000/cb"),
            ("client_id", client_id.as_str()),
            ("code_verifier", VERIFIER),
        ])
        .unwrap();
        let request = token_request(&o, body.as_bytes(), None, NOW).unwrap();
        assert!(request.authorization.is_none());
        let form = Params::from_form(request.form.as_bytes()).unwrap();
        assert_eq!(form.get("code"), Some("idp-code"));
        assert_eq!(
            form.get("redirect_uri"),
            Some("https://gw.example/mcp-server/oauth/callback")
        );
        assert_eq!(form.get("code_verifier"), Some(VERIFIER));
        assert_eq!(form.get("client_id"), Some("upstream-client"));
        assert_eq!(form.get("client_secret"), Some("upstream-secret"));

        // The IdP's refresh token comes back sealed and bound to the client.
        let idp = br#"{"access_token":"at","token_type":"Bearer","refresh_token":"idp-rt","expires_in":3600}"#;
        let response: Value =
            serde_json::from_slice(&token_response(&o, 200, idp, &request, NOW, &NONCE).unwrap())
                .unwrap();
        assert_eq!(response["access_token"], "at");
        let refresh = response["refresh_token"].as_str().unwrap();
        assert!(refresh.starts_with("v1e."), "refresh tokens are encrypted");
        assert!(!refresh.contains("idp-rt"));
        assert!(code.starts_with("v1e."), "codes are encrypted");

        let body = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id.as_str()),
        ])
        .unwrap();
        let request = token_request(&o, body.as_bytes(), None, NOW).unwrap();
        assert_eq!(
            Params::from_form(request.form.as_bytes())
                .unwrap()
                .get("refresh_token"),
            Some("idp-rt")
        );

        // Another client cannot use it.
        let other = register_loopback(&o);
        let body = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", other.as_str()),
        ])
        .unwrap();
        assert_eq!(
            token_request(&o, body.as_bytes(), None, NOW)
                .unwrap_err()
                .error,
            "invalid_grant"
        );
    }

    #[test]
    fn token_request_binds_code_to_client_and_redirect() {
        let o = settings();
        let (client_id, code) = code_for(&o);
        let other = register_loopback(&o);
        let exchange = |client: &str, redirect_uri: &str| {
            let body = serde_urlencoded::to_string([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", redirect_uri),
                ("client_id", client),
                ("code_verifier", VERIFIER),
            ])
            .unwrap();
            token_request(&o, body.as_bytes(), None, NOW)
        };
        assert_eq!(
            exchange(&other, "http://127.0.0.1:6000/cb")
                .unwrap_err()
                .error,
            "invalid_grant"
        );
        assert_eq!(
            exchange(&client_id, "http://127.0.0.1:7000/cb")
                .unwrap_err()
                .error,
            "invalid_grant"
        );
        assert_eq!(
            exchange("not-a-client", "http://127.0.0.1:6000/cb")
                .unwrap_err()
                .error,
            "invalid_client"
        );
        assert!(exchange(&client_id, "http://127.0.0.1:6000/cb").is_ok());
    }

    #[test]
    fn token_request_errors() {
        let o = settings();
        let client_id = register_loopback(&o);
        let form = |pairs: &[(&str, &str)]| serde_urlencoded::to_string(pairs).unwrap();
        let cid = client_id.as_str();
        assert_eq!(
            token_request(
                &o,
                form(&[("grant_type", "authorization_code")]).as_bytes(),
                None,
                NOW
            )
            .unwrap_err()
            .error,
            "invalid_client"
        );
        assert_eq!(
            token_request(&o, form(&[("client_id", cid)]).as_bytes(), None, NOW)
                .unwrap_err()
                .error,
            "invalid_request"
        );
        assert_eq!(
            token_request(
                &o,
                form(&[("client_id", cid), ("grant_type", "password")]).as_bytes(),
                None,
                NOW
            )
            .unwrap_err()
            .error,
            "unsupported_grant_type"
        );
        assert_eq!(
            token_request(
                &o,
                form(&[
                    ("client_id", cid),
                    ("grant_type", "authorization_code"),
                    ("code", "forged"),
                    ("redirect_uri", "x"),
                    ("code_verifier", VERIFIER)
                ])
                .as_bytes(),
                None,
                NOW
            )
            .unwrap_err()
            .error,
            "invalid_grant"
        );
        assert_eq!(
            token_request(
                &o,
                form(&[("client_id", cid), ("client_id", cid)]).as_bytes(),
                None,
                NOW
            )
            .unwrap_err()
            .error,
            "invalid_request"
        );
    }

    #[test]
    fn basic_client_auth_to_idp() {
        let mut i = input();
        i.upstream_client_auth_method = "client_secret_basic".into();
        i.upstream_client_secret = Some("s3cr:t".into());
        let o = OAuthSettings::build(i).unwrap();
        let (client_id, code) = code_for(&o);
        let body = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "http://127.0.0.1:6000/cb"),
            ("code_verifier", VERIFIER),
        ])
        .unwrap();
        // client_id supplied through Basic, as some clients do.
        let basic = format!("Basic {}", STANDARD.encode(format!("{client_id}:")));
        let request = token_request(&o, body.as_bytes(), Some(&basic), NOW).unwrap();
        assert_eq!(
            request.authorization.as_deref(),
            Some(format!("Basic {}", STANDARD.encode("upstream-client:s3cr%3At")).as_str())
        );
        assert!(Params::from_form(request.form.as_bytes())
            .unwrap()
            .get("client_secret")
            .is_none());
    }

    #[test]
    fn maps_idp_errors() {
        let o = settings();
        let err = token_response(
            &o,
            400,
            br#"{"error":"invalid_grant","error_description":"AADSTS70008: expired"}"#,
            &dummy_request(),
            NOW,
            &NONCE,
        )
        .unwrap_err();
        assert_eq!((err.status, err.error), (400, "invalid_grant"));
        let err = token_response(&o, 401, b"<html>nope</html>", &dummy_request(), NOW, &NONCE)
            .unwrap_err();
        assert_eq!(
            (err.status, err.error),
            (502, "server_error"),
            "IdP 401 = our creds are wrong"
        );
        let body = br#"{"error":"invalid_client","error_description":"bad secret"}"#;
        let err = token_response(&o, 400, body, &dummy_request(), NOW, &NONCE).unwrap_err();
        assert_eq!((err.status, err.error), (502, "server_error"));
        let body = br#"{"error":"unauthorized_client"}"#;
        assert_eq!(
            token_response(&o, 400, body, &dummy_request(), NOW, &NONCE)
                .unwrap_err()
                .status,
            502
        );
        let err = token_response(&o, 500, b"", &dummy_request(), NOW, &NONCE).unwrap_err();
        assert_eq!((err.status, err.error), (503, "temporarily_unavailable"));
        let err = token_response(&o, 200, b"[]", &dummy_request(), NOW, &NONCE).unwrap_err();
        assert_eq!(err.status, 502);
    }

    // ---- P4A review round 1 ------------------------------------------------------------------

    /// Exchanges `code` for `client_id` with the given `code_verifier` (or none).
    fn exchange(
        o: &OAuthSettings,
        client_id: &str,
        code: &str,
        verifier: Option<&str>,
    ) -> Result<UpstreamTokenRequest, OAuthError> {
        let mut pairs = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "http://127.0.0.1:6000/cb"),
            ("client_id", client_id),
        ];
        if let Some(verifier) = verifier {
            pairs.push(("code_verifier", verifier));
        }
        let body = serde_urlencoded::to_string(&pairs).unwrap();
        token_request(o, body.as_bytes(), None, NOW)
    }

    /// Issue #1: the gateway verifies PKCE itself instead of relying on the IdP.
    #[test]
    fn pkce_is_verified_at_the_gateway() {
        let o = settings();
        let (client_id, code) = code_for(&o);

        let wrong = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX";
        let err = exchange(&o, &client_id, &code, Some(wrong)).unwrap_err();
        assert_eq!(
            (err.status, err.error),
            (400, "invalid_grant"),
            "wrong verifier"
        );

        let err = exchange(&o, &client_id, &code, None).unwrap_err();
        assert_eq!(err.error, "invalid_request", "missing verifier");

        let err = exchange(&o, &client_id, &code, Some("too-short")).unwrap_err();
        assert_eq!(err.error, "invalid_request", "malformed verifier");

        let request = exchange(&o, &client_id, &code, Some(VERIFIER)).unwrap();
        let form = Params::from_form(request.form.as_bytes()).unwrap();
        assert_eq!(
            form.get("code_verifier"),
            Some(VERIFIER),
            "still forwarded upstream"
        );
    }

    fn authorize_with_scope(
        o: &OAuthSettings,
        scope: Option<&str>,
        resource: Option<&str>,
    ) -> BrowserOutcome {
        let mut pairs = vec![
            ("response_type", "code"),
            ("redirect_uri", "https://client.example/cb"),
            ("state", "s"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        if let Some(scope) = scope {
            pairs.push(("scope", scope));
        }
        if let Some(resource) = resource {
            pairs.push(("resource", resource));
        }
        let params = Params::from_query_of(&format!(
            "/a?{}",
            serde_urlencoded::to_string(&pairs).unwrap()
        ));
        authorize(o, &https_client(), &params, NOW, Some(&browser()))
    }

    /// Issue #2: client scopes are restricted to scopesSupported and shown on the consent page.
    #[test]
    fn requested_scopes_are_constrained_and_displayed() {
        let o = settings(); // scopesSupported = [mcp.read], no upstreamScope

        // Anything outside scopesSupported is refused, e.g. a Graph scope on the shared app.
        let location = redirect(authorize_with_scope(
            &o,
            Some("mcp.read https://graph.microsoft.com/.default"),
            None,
        ));
        let error = query_of(&location);
        assert_eq!(error.get("error"), Some("invalid_scope"));
        assert_eq!(error.get("state"), Some("s"));

        // Supported scopes (plus offline_access) pass through and are listed on the consent page.
        let page = consent_page(authorize_with_scope(
            &o,
            Some("mcp.read offline_access"),
            None,
        ));
        assert_eq!(
            query_of(&page.continue_url).get("scope"),
            Some("mcp.read offline_access")
        );
        assert!(page.html.contains("<li><code>mcp.read</code></li>"));
        assert!(page.html.contains("<li><code>offline_access</code></li>"));

        // No scope requested: all of scopesSupported.
        let page = consent_page(authorize_with_scope(&o, None, None));
        assert_eq!(query_of(&page.continue_url).get("scope"), Some("mcp.read"));

        // A configured upstreamScope always wins over the client's request.
        let mut fixed = input();
        fixed.upstream_scope = Some("api://mcp/.default offline_access".into());
        let fixed = OAuthSettings::build(fixed).unwrap();
        let page = consent_page(authorize_with_scope(&fixed, Some("anything.else"), None));
        assert_eq!(
            query_of(&page.continue_url).get("scope"),
            Some("api://mcp/.default offline_access")
        );

        // Without either setting, the policy refuses to load.
        let mut open = input();
        open.scopes_supported = vec![];
        assert!(OAuthSettings::build(open).is_err());
    }

    /// Issue #2: RFC 8707 resource must name this MCP server, at /authorize and /token.
    #[test]
    fn resource_must_be_this_server() {
        let o = settings();
        let location = redirect(authorize_with_scope(
            &o,
            None,
            Some("https://other.example/mcp"),
        ));
        assert_eq!(query_of(&location).get("error"), Some("invalid_target"));
        assert!(matches!(
            authorize_with_scope(&o, None, Some("https://gw.example/mcp-server/mcp/")),
            BrowserOutcome::Consent(_)
        ));

        let (client_id, code) = code_for(&o);
        let body = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "http://127.0.0.1:6000/cb"),
            ("client_id", client_id.as_str()),
            ("code_verifier", VERIFIER),
            ("resource", "https://other.example/mcp"),
        ])
        .unwrap();
        assert_eq!(
            token_request(&o, body.as_bytes(), None, NOW)
                .unwrap_err()
                .error,
            "invalid_target"
        );
    }

    /// Issue #2: a refresh may narrow, but never widen, the scope granted at authorization.
    #[test]
    fn refresh_cannot_widen_scope() {
        let o = settings();
        let (client_id, code) = code_for(&o);
        let request = exchange(&o, &client_id, &code, Some(VERIFIER)).unwrap();
        assert_eq!(request.granted_scope, "mcp.read");
        let idp = br#"{"access_token":"at","token_type":"Bearer","refresh_token":"idp-rt"}"#;
        let response: Value =
            serde_json::from_slice(&token_response(&o, 200, idp, &request, NOW, &NONCE).unwrap())
                .unwrap();
        let refresh = response["refresh_token"].as_str().unwrap().to_string();

        let refresh_with = |scope: Option<&str>| {
            let mut pairs = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", client_id.as_str()),
            ];
            if let Some(scope) = scope {
                pairs.push(("scope", scope));
            }
            token_request(
                &o,
                serde_urlencoded::to_string(&pairs).unwrap().as_bytes(),
                None,
                NOW,
            )
        };
        let err = refresh_with(Some("mcp.read admin.write")).unwrap_err();
        assert_eq!((err.status, err.error), (400, "invalid_scope"));
        let request = refresh_with(None).unwrap();
        assert_eq!(
            Params::from_form(request.form.as_bytes())
                .unwrap()
                .get("scope"),
            Some("mcp.read")
        );
        assert!(refresh_with(Some("mcp.read")).is_ok());
    }

    /// Issue #3: prefix entries can't be escaped with dot segments, and can't be too broad.
    #[test]
    fn prefix_redirects_cannot_be_escaped() {
        let o = settings(); // allowedRedirectUris = ["https://client.example/oauth/"]
        for escaped in [
            "https://client.example/oauth/../redirect?to=https://evil.example",
            "https://client.example/oauth/%2e%2e/redirect",
            "https://client.example/oauth/%2E%2E%2Fredirect",
            "https://client.example/oauth/..\\redirect",
        ] {
            let body = serde_json::to_vec(&json!({"redirect_uris": [escaped]})).unwrap();
            let err = register(&o, &body, NOW, None).unwrap_err();
            assert_eq!(err.error, "invalid_redirect_uri", "{}", escaped);
        }
        assert!(register(
            &o,
            br#"{"redirect_uris":["https://client.example/oauth/cb"]}"#,
            NOW,
            None
        )
        .is_ok());

        // A bare scheme would match every redirect URI; custom-scheme or dot-segment prefixes
        // can't be compared safely.
        for bad_prefix in [
            "https://",
            "https:///",
            "myapp://cb/",
            "https://client.example/a/../",
        ] {
            let mut i = input();
            i.allowed_redirect_uris = vec![bad_prefix.to_string()];
            assert!(OAuthSettings::build(i).is_err(), "{}", bad_prefix);
        }
    }

    /// Issue #4: a registration whose client_id would be too long to open is refused up front.
    #[test]
    fn oversized_registrations_are_refused() {
        let o = settings();
        let uris: Vec<String> = (0..10)
            .map(|i| format!("http://127.0.0.1:{}/{}", 1000 + i, "a".repeat(1990)))
            .collect();
        let body = serde_json::to_vec(&json!({ "redirect_uris": uris })).unwrap();
        let err = register(&o, &body, NOW, None).unwrap_err();
        assert_eq!((err.status, err.error), (400, "invalid_client_metadata"));
    }

    /// Issue #5: placeholder and low-entropy signing secrets are rejected.
    #[test]
    fn weak_signing_secrets_are_rejected() {
        for weak in [
            "CHANGE_ME_TO_32_PLUS_RANDOM_CHARACTERS",
            "GENERATE_32_PLUS_RANDOM_CHARACTERS_NOW",
            "LOCAL_TEST_SECRET_AT_LEAST_32_CHARACTERS",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "passwordpasswordpasswordpassword",
            "abababababababababababababababab12",
        ] {
            let mut i = input();
            i.signing_secret = weak.into();
            assert!(OAuthSettings::build(i).is_err(), "{}", weak);
        }
        for strong in [
            "0123456789abcdef0123456789abcdef", // hex, 128 bits
            "q3Vb9Xl2Rk8sT1mZ0wYc7Pd4Hn6Jf5Ga2EoLuNi8Ks3BtWx9Cy1Dv0Az7Mr4Qp6Ue", // base64-like
        ] {
            let mut i = input();
            i.signing_secret = strong.into();
            assert!(OAuthSettings::build(i).is_ok(), "{}", strong);
        }
    }

    /// Issue #7: the IdP's id_token is never relayed (its issuer is the IdP, not this server).
    #[test]
    fn id_token_is_dropped() {
        let o = settings();
        let idp = br#"{"access_token":"at","token_type":"Bearer","id_token":"eyJ.idp.token"}"#;
        let body: Value = serde_json::from_slice(
            &token_response(&o, 200, idp, &dummy_request(), NOW, &NONCE).unwrap(),
        )
        .unwrap();
        assert!(body.get("id_token").is_none());
        assert_eq!(body["access_token"], "at");
    }

    /// Issue #11: the IdP authorize endpoint must be https (http only on loopback).
    #[test]
    fn upstream_authorize_url_must_be_https() {
        let mut i = input();
        i.upstream_authorize_url = "http://idp.example/authorize".into();
        assert!(OAuthSettings::build(i).is_err());
        let mut i = input();
        i.upstream_authorize_url = "http://localhost:9000/authorize".into();
        assert!(OAuthSettings::build(i).is_ok());
    }
}
