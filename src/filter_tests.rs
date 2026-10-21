// Copyright 2026 Salesforce, Inc. All rights reserved.

//! pdk-unit tests: drive the real `configure` entrypoint, request filter and response filter
//! in-process through the PDK 1.10 proxy-wasm host stub.

use std::cell::RefCell;
use std::rc::Rc;

use pdk_unit::{
    TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTest, UnitTestBuilder,
};
use serde_json::{json, Value};

use crate::uri::Params;

const BASE: &str = "/mcp-server";
const PRM_URL: &str = "https://gw.example/mcp-server/.well-known/oauth-protected-resource";
/// Authority of upstreamTokenService; pdk-unit maps it to the same cluster name that
/// `pdk::serde::deserialize_service` derives from the config.
const IDP_AUTHORITY: &str = "idp.example:443";
const REDIRECT_URI: &str = "http://127.0.0.1:33418/callback";
// RFC 7636 appendix B test vector.
const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn config() -> String {
    json!({
        "publicBaseUrl": "https://gw.example/mcp-server",
        "mcpResourcePath": "/mcp",
        "upstreamAuthorizeUrl": "https://idp.example/authorize",
        "upstreamTokenService": "https://idp.example:443/token",
        "upstreamClientId": "upstream-client",
        "upstreamClientSecret": "upstream-secret",
        "upstreamClientAuthMethod": "client_secret_post",
        "scopesSupported": ["mcp.read"],
        "signingSecret": "0123456789abcdef0123456789abcdef",
        "enableDcr": true,
        "enableCimd": false,
        "cimdCacheTtlSeconds": 300,
        "allowLoopbackRedirects": true,
        "clientRegistrationTtlSeconds": 3600,
        "challengeUnauthenticated": true,
        "requireConsent": true
    })
    .to_string()
}

fn json_body(response: &UnitHttpResponse) -> Value {
    serde_json::from_slice(response.body()).expect("response body must be JSON")
}

fn form(pairs: &[(&str, &str)]) -> String {
    serde_urlencoded::to_string(pairs).unwrap()
}

/// Default upstream (the MCP server) records every request that reaches it.
fn tester_with_upstream(upstream: Rc<TraceBackend<UnitHttpResponse>>) -> UnitTest {
    UnitTestBuilder::default()
        .with_config(config())
        .with_backend(upstream)
        .with_entrypoint(crate::configure)
}

fn register(tester: &mut UnitTest) -> String {
    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/oauth/register"))
            .with_header("content-type", "application/json")
            .with_body(
                json!({"redirect_uris": [REDIRECT_URI], "client_name": "Unit Test Client"})
                    .to_string(),
            ),
    );
    assert_eq!(
        response.status_code(),
        201,
        "body: {:?}",
        String::from_utf8_lossy(response.body())
    );
    json_body(&response)["client_id"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---- 1 + 2: configure + discovery early response --------------------------------------

#[test]
fn protected_resource_metadata_is_answered_by_the_policy() {
    let upstream = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = tester_with_upstream(Rc::clone(&upstream));

    let response = tester.request(
        UnitHttpRequest::get().with_path(format!("{BASE}/.well-known/oauth-protected-resource")),
    );

    assert_eq!(response.status_code(), 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    let body = json_body(&response);
    assert_eq!(body["resource"], "https://gw.example/mcp-server/mcp");
    assert_eq!(
        body["authorization_servers"],
        json!(["https://gw.example/mcp-server"])
    );
    assert!(
        upstream.next().is_none(),
        "discovery must not reach the MCP upstream"
    );
}

/// Behind a base path, MCP SDK clients reach the metadata at `{base}/.well-known/openid-configuration`
/// and validate it as OIDC provider metadata.
#[test]
fn openid_configuration_is_valid_oidc_metadata_with_an_empty_jwk_set() {
    let upstream = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = tester_with_upstream(Rc::clone(&upstream));

    let response = tester.request(
        UnitHttpRequest::get().with_path(format!("{BASE}/.well-known/openid-configuration")),
    );
    assert_eq!(response.status_code(), 200);
    let body = json_body(&response);
    assert_eq!(body["issuer"], "https://gw.example/mcp-server");
    assert_eq!(body["jwks_uri"], "https://gw.example/mcp-server/oauth/jwks");
    assert_eq!(body["subject_types_supported"], json!(["public"]));
    assert_eq!(
        body["id_token_signing_alg_values_supported"],
        json!(["RS256"])
    );

    let response = tester.request(UnitHttpRequest::get().with_path(format!("{BASE}/oauth/jwks")));
    assert_eq!(response.status_code(), 200);
    assert_eq!(json_body(&response), json!({ "keys": [] }));
    assert!(
        upstream.next().is_none(),
        "discovery must not reach the MCP upstream"
    );
}

// ---- 3: unauthenticated MCP request is challenged ---------------------------------------

#[test]
fn mcp_request_without_authorization_gets_401_challenge() {
    let upstream = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = tester_with_upstream(Rc::clone(&upstream));

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/mcp"))
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#),
    );

    assert_eq!(response.status_code(), 401);
    let challenge = response.header("www-authenticate").unwrap();
    assert_eq!(
        challenge,
        format!("Bearer resource_metadata=\"{PRM_URL}\", scope=\"mcp.read\"")
    );
    assert!(challenge.contains("resource_metadata"));
    assert_eq!(json_body(&response)["error"], "invalid_token");
    assert!(upstream.next().is_none());
}

// ---- 4: DCR is answered locally ---------------------------------------------------------

#[test]
fn registration_returns_201_and_never_reaches_upstream() {
    let upstream = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = tester_with_upstream(Rc::clone(&upstream));

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/oauth/register"))
            .with_header("content-type", "application/json")
            .with_body(json!({"redirect_uris": [REDIRECT_URI]}).to_string()),
    );

    assert_eq!(response.status_code(), 201);
    let body = json_body(&response);
    assert!(body["client_id"].as_str().is_some_and(|id| !id.is_empty()));
    assert_eq!(body["redirect_uris"], json!([REDIRECT_URI]));
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert!(
        upstream.next().is_none(),
        "registration must not reach the MCP upstream"
    );
}

#[test]
fn registration_body_split_across_chunks_is_buffered() {
    let upstream = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = tester_with_upstream(Rc::clone(&upstream));
    tester.set_chunk_size(7); // default is 30_000; force many RequestBody events

    let client_id = register(&mut tester);

    assert!(!client_id.is_empty());
    assert!(upstream.next().is_none());
}

// ---- 5: response filter decorates an upstream 401 ---------------------------------------

#[test]
fn upstream_401_gets_resource_metadata_added() {
    let upstream = Rc::new(TraceBackend::new(
        UnitHttpResponse::new(401)
            .with_header("www-authenticate", "Bearer error=\"invalid_token\""),
    ));
    let mut tester = tester_with_upstream(Rc::clone(&upstream));

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/mcp"))
            .with_header("authorization", "Bearer expired-token")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
    );

    let forwarded = upstream
        .next()
        .expect("authorized MCP request must be forwarded");
    assert_eq!(forwarded.header(":path"), Some("/mcp-server/mcp"));
    assert_eq!(
        forwarded.header("authorization"),
        Some("Bearer expired-token")
    );

    assert_eq!(response.status_code(), 401);
    assert_eq!(
        response.header("www-authenticate"),
        Some(
            format!(
                "Bearer error=\"invalid_token\", resource_metadata=\"{PRM_URL}\", scope=\"mcp.read\""
            )
            .as_str()
        )
    );
    assert_eq!(
        response.header("access-control-expose-headers"),
        Some("www-authenticate")
    );
}

#[test]
fn upstream_200_passes_through_untouched() {
    let upstream = Rc::new(TraceBackend::new(
        UnitHttpResponse::new(200).with_body("ok"),
    ));
    let mut tester = tester_with_upstream(Rc::clone(&upstream));

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/mcp"))
            .with_header("authorization", "Bearer good-token")
            .with_body("{}"),
    );

    assert!(upstream.next().is_some());
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.body(), b"ok");
    assert!(response.header("www-authenticate").is_none());
}

// ---- 6: full register -> authorize -> callback -> token, IdP mocked ---------------------

#[test]
fn full_authorization_code_flow_with_mocked_idp() {
    let mcp_upstream = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let idp = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| {
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "access_token": "idp-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "idp-refresh-token"
                })
                .to_string(),
            )
    }));
    let mut tester = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&mcp_upstream))
        .with_http_upstream_from_authority(IDP_AUTHORITY, Rc::clone(&idp))
        .with_entrypoint(crate::configure);

    // 1. Register.
    let client_id = register(&mut tester);

    // 2. Authorize: consent page with a browser-binding cookie.
    let query = form(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", REDIRECT_URI),
        ("state", "client-state"),
        ("code_challenge", CODE_CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    let consent =
        tester.request(UnitHttpRequest::get().with_path(format!("{BASE}/oauth/authorize?{query}")));
    assert_eq!(
        consent.status_code(),
        200,
        "{}",
        String::from_utf8_lossy(consent.body())
    );
    assert!(consent
        .header("content-type")
        .unwrap()
        .starts_with("text/html"));
    // https publicBaseUrl => __Host- cookie with Secure.
    let set_cookie = consent.header("set-cookie").unwrap().to_string();
    assert!(set_cookie.starts_with("__Host-mcp-auth-"));
    assert!(set_cookie.contains("; Secure"));
    let cookie = set_cookie.split(';').next().unwrap().to_string();

    let html = String::from_utf8(consent.body().to_vec()).unwrap();
    let continue_url = html
        .split("id=\"continue\" href=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .replace("&amp;", "&");
    assert!(continue_url.starts_with("https://idp.example/authorize?"));
    let idp_params = Params::from_query_of(&continue_url);
    assert_eq!(idp_params.get("client_id"), Some("upstream-client"));
    assert_eq!(
        idp_params.get("redirect_uri"),
        Some("https://gw.example/mcp-server/oauth/callback")
    );
    assert_eq!(idp_params.get("code_challenge"), Some(CODE_CHALLENGE));
    let sealed_state = idp_params.get("state").unwrap().to_string();

    // 3. IdP redirects the browser back to the gateway callback, with the cookie.
    let callback = tester.request(
        UnitHttpRequest::get()
            .with_path(format!(
                "{BASE}/oauth/callback?{}",
                form(&[("code", "idp-code-123"), ("state", &sealed_state)])
            ))
            .with_header("cookie", cookie.as_str()),
    );
    assert_eq!(
        callback.status_code(),
        302,
        "{}",
        String::from_utf8_lossy(callback.body())
    );
    let location = callback.header("location").unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT_URI}?")));
    let client_params = Params::from_query_of(&location);
    assert_eq!(client_params.get("state"), Some("client-state"));
    assert_eq!(
        client_params.get("iss"),
        Some("https://gw.example/mcp-server")
    );
    let wrapped_code = client_params.get("code").unwrap().to_string();
    assert_ne!(
        wrapped_code, "idp-code-123",
        "upstream code must be wrapped"
    );

    // 4. Token exchange.
    let token = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/oauth/token"))
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(form(&[
                ("grant_type", "authorization_code"),
                ("code", &wrapped_code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", CODE_VERIFIER),
                ("client_id", &client_id),
            ])),
    );

    // What the IdP received.
    let idp_request = idp.next().expect("token endpoint must be called");
    assert!(idp.next().is_none());
    assert_eq!(idp_request.header(":method"), Some("POST"));
    assert_eq!(idp_request.header(":path"), Some("/token"));
    assert_eq!(
        idp_request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    let sent = Params::from_form(idp_request.body()).unwrap();
    assert_eq!(sent.get("grant_type"), Some("authorization_code"));
    assert_eq!(sent.get("code"), Some("idp-code-123"));
    assert_eq!(
        sent.get("redirect_uri"),
        Some("https://gw.example/mcp-server/oauth/callback")
    );
    assert_eq!(sent.get("code_verifier"), Some(CODE_VERIFIER));
    assert_eq!(sent.get("client_id"), Some("upstream-client"));
    assert_eq!(sent.get("client_secret"), Some("upstream-secret"));

    // What the MCP client received.
    assert_eq!(
        token.status_code(),
        200,
        "{}",
        String::from_utf8_lossy(token.body())
    );
    assert_eq!(token.header("cache-control"), Some("no-store"));
    let body = json_body(&token);
    assert_eq!(body["access_token"], "idp-access-token");
    assert_eq!(body["token_type"], "Bearer");
    let refresh = body["refresh_token"].as_str().unwrap();
    assert!(
        refresh.starts_with("v1e."),
        "refresh token must be encrypted"
    );
    assert!(!refresh.contains("idp-refresh-token"));

    assert!(
        mcp_upstream.next().is_none(),
        "no OAuth endpoint may reach the MCP upstream"
    );
}

#[test]
fn wrong_pkce_verifier_is_rejected_without_calling_the_idp() {
    let calls = Rc::new(RefCell::new(0u32));
    let seen = Rc::clone(&calls);
    let mut tester = UnitTestBuilder::default()
        .with_config(config())
        .with_http_upstream_from_authority(IDP_AUTHORITY, move |_req: UnitHttpRequest| {
            *seen.borrow_mut() += 1;
            UnitHttpResponse::new(200).with_body("{}")
        })
        .with_entrypoint(crate::configure);
    let client_id = register(&mut tester);
    let wrapped_code = walk_to_wrapped_code(&mut tester, &client_id);

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/oauth/token"))
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(form(&[
                ("grant_type", "authorization_code"),
                ("code", &wrapped_code),
                ("redirect_uri", REDIRECT_URI),
                (
                    "code_verifier",
                    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX",
                ),
                ("client_id", &client_id),
            ])),
    );

    assert_eq!(response.status_code(), 400);
    assert_eq!(json_body(&response)["error"], "invalid_grant");
    assert_eq!(
        *calls.borrow(),
        0,
        "a wrong verifier must not reach the IdP"
    );
}

#[test]
fn invalid_code_is_rejected_without_calling_the_idp() {
    let calls = Rc::new(RefCell::new(0u32));
    let seen = Rc::clone(&calls);
    let mut tester = UnitTestBuilder::default()
        .with_config(config())
        .with_http_upstream_from_authority(IDP_AUTHORITY, move |_req: UnitHttpRequest| {
            *seen.borrow_mut() += 1;
            UnitHttpResponse::new(200).with_body("{}")
        })
        .with_entrypoint(crate::configure);
    let client_id = register(&mut tester);

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/oauth/token"))
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(form(&[
                ("grant_type", "authorization_code"),
                ("code", "not-a-sealed-code"),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", CODE_VERIFIER),
                ("client_id", &client_id),
            ])),
    );

    assert_eq!(response.status_code(), 400);
    assert_eq!(json_body(&response)["error"], "invalid_grant");
    assert_eq!(*calls.borrow(), 0, "an invalid code must not reach the IdP");
}

#[test]
fn idp_rejection_is_relayed_as_oauth_error() {
    // Walk to a valid wrapped code, then have the IdP reject it.
    let idp = Rc::new(TraceBackend::new(
        UnitHttpResponse::new(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"invalid_grant","error_description":"code already used"}"#),
    ));
    let mut tester = UnitTestBuilder::default()
        .with_config(config())
        .with_http_upstream_from_authority(IDP_AUTHORITY, Rc::clone(&idp))
        .with_entrypoint(crate::configure);
    let client_id = register(&mut tester);
    let wrapped_code = walk_to_wrapped_code(&mut tester, &client_id);

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/oauth/token"))
            .with_body(form(&[
                ("grant_type", "authorization_code"),
                ("code", &wrapped_code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", CODE_VERIFIER),
                ("client_id", &client_id),
            ])),
    );

    assert!(idp.next().is_some());
    assert_eq!(response.status_code(), 400);
    let body = json_body(&response);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "code already used");
}

#[test]
fn idp_rejecting_gateway_credentials_is_a_gateway_error() {
    // invalid_client from the IdP means the gateway's own upstream credentials are wrong: the
    // MCP client must not be told its registration is invalid.
    let idp = Rc::new(TraceBackend::new(
        UnitHttpResponse::new(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"invalid_client","error_description":"bad secret"}"#),
    ));
    let mut tester = UnitTestBuilder::default()
        .with_config(config())
        .with_http_upstream_from_authority(IDP_AUTHORITY, Rc::clone(&idp))
        .with_entrypoint(crate::configure);
    let client_id = register(&mut tester);
    let wrapped_code = walk_to_wrapped_code(&mut tester, &client_id);

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/oauth/token"))
            .with_body(form(&[
                ("grant_type", "authorization_code"),
                ("code", &wrapped_code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", CODE_VERIFIER),
                ("client_id", &client_id),
            ])),
    );

    assert!(idp.next().is_some());
    assert_eq!(response.status_code(), 502);
    assert_eq!(json_body(&response)["error"], "server_error");
}

#[test]
fn unregistered_idp_upstream_yields_temporarily_unavailable() {
    // No with_http_upstream_from_authority: the host stub rejects the dispatch
    // (Status::BadArgument), which surfaces to the policy as an HttpClient error.
    let mut tester = UnitTestBuilder::default()
        .with_config(config())
        .with_entrypoint(crate::configure);
    let client_id = register(&mut tester);
    let wrapped_code = walk_to_wrapped_code(&mut tester, &client_id);

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/oauth/token"))
            .with_body(form(&[
                ("grant_type", "authorization_code"),
                ("code", &wrapped_code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", CODE_VERIFIER),
                ("client_id", &client_id),
            ])),
    );

    assert_eq!(
        response.status_code(),
        503,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    assert_eq!(json_body(&response)["error"], "temporarily_unavailable");
}

fn walk_to_wrapped_code(tester: &mut UnitTest, client_id: &str) -> String {
    let query = form(&[
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", CODE_CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    let consent =
        tester.request(UnitHttpRequest::get().with_path(format!("{BASE}/oauth/authorize?{query}")));
    assert_eq!(consent.status_code(), 200);
    let cookie = consent
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let html = String::from_utf8(consent.body().to_vec()).unwrap();
    let continue_url = html
        .split("id=\"continue\" href=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .replace("&amp;", "&");
    let state = Params::from_query_of(&continue_url)
        .get("state")
        .unwrap()
        .to_string();
    let callback = tester.request(
        UnitHttpRequest::get()
            .with_path(format!(
                "{BASE}/oauth/callback?{}",
                form(&[("code", "c"), ("state", &state)])
            ))
            .with_header("cookie", cookie.as_str()),
    );
    assert_eq!(callback.status_code(), 302);
    Params::from_query_of(callback.header("location").unwrap())
        .get("code")
        .unwrap()
        .to_string()
}

#[test]
fn callback_without_binding_cookie_is_rejected() {
    let mut tester = UnitTestBuilder::default()
        .with_config(config())
        .with_entrypoint(crate::configure);
    let client_id = register(&mut tester);
    let query = form(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", CODE_CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    let consent =
        tester.request(UnitHttpRequest::get().with_path(format!("{BASE}/oauth/authorize?{query}")));
    let html = String::from_utf8(consent.body().to_vec()).unwrap();
    let continue_url = html
        .split("id=\"continue\" href=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .replace("&amp;", "&");
    let state = Params::from_query_of(&continue_url)
        .get("state")
        .unwrap()
        .to_string();

    let callback = tester.request(UnitHttpRequest::get().with_path(format!(
        "{BASE}/oauth/callback?{}",
        form(&[("code", "c"), ("state", &state)])
    )));
    assert_eq!(callback.status_code(), 400);
}

// ---- 7: local mode (no control plane) ---------------------------------------------------

#[test]
fn local_mode_still_serves_discovery_and_forwards_authorized_traffic() {
    let upstream = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = UnitTestBuilder::default()
        .local_mode()
        .with_config(config())
        .with_backend(Rc::clone(&upstream))
        .with_entrypoint(crate::configure);

    let prm = tester.request(
        UnitHttpRequest::get().with_path(format!("{BASE}/.well-known/oauth-protected-resource")),
    );
    assert_eq!(prm.status_code(), 200);

    let mcp = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/mcp"))
            .with_header("authorization", "Bearer t")
            .with_body("{}"),
    );
    assert_eq!(mcp.status_code(), 200);
    assert!(upstream.next().is_some());
}

// ---- misc -------------------------------------------------------------------------------

#[test]
fn invalid_config_answers_503_and_never_forwards() {
    // configure() returns Err (signingSecret too short); the PDK runtime then answers every
    // request with 503 ("failed to deploy policy") instead of panicking.
    let mut bad: Value = serde_json::from_str(&config()).unwrap();
    bad["signingSecret"] = json!("short");
    let upstream = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = UnitTestBuilder::default()
        .with_config(bad.to_string())
        .with_backend(Rc::clone(&upstream))
        .with_entrypoint(crate::configure);

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path(format!("{BASE}/mcp"))
            .with_header("authorization", "Bearer t"),
    );

    assert_eq!(response.status_code(), 503);
    assert!(upstream.next().is_none());
}
