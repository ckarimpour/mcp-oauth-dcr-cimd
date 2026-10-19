// Copyright 2026 Salesforce, Inc. All rights reserved.

//! Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document): the client_id is
//! an HTTPS URL, and the document at that URL describes the client.

use serde_json::Value;

use crate::consent;
use crate::oauth::ClientInfo;
use crate::uri;

const MAX_CLIENT_ID_LEN: usize = 2048;
pub(crate) const MAX_DOCUMENT_BYTES: usize = 5 * 1024;
const MAX_REDIRECT_URIS: usize = 20;
const MAX_CLIENT_NAME_CHARS: usize = 200;

/// Where to fetch a metadata document from.
#[derive(Debug, PartialEq)]
pub struct CimdTarget {
    /// Normalised origin, matched against the trusted hosts.
    pub origin: String,
    pub path_and_query: String,
}

pub fn is_cimd_client_id(client_id: &str) -> bool {
    client_id.starts_with("https://")
}

pub fn validate_client_id_url(client_id: &str) -> Result<CimdTarget, &'static str> {
    if client_id.len() > MAX_CLIENT_ID_LEN {
        return Err("client_id URL is too long");
    }
    let parsed = uri::parse(client_id).ok_or("client_id is not a valid URL")?;
    if parsed.scheme != "https" {
        return Err("client_id URL must use https");
    }
    if parsed.has_fragment {
        return Err("client_id URL must not contain a fragment");
    }
    if parsed.has_userinfo {
        return Err("client_id URL must not contain credentials");
    }
    // No query: each distinct query would be a distinct client_id and a distinct fetch,
    // bypassing the document cache.
    if parsed.path_and_query.contains('?') {
        return Err("client_id URL must not contain a query string");
    }
    let path = parsed.path_and_query;
    if path.is_empty() || path == "/" {
        return Err("client_id URL must contain a path");
    }
    if uri::has_path_traversal(client_id) {
        return Err("client_id URL must not contain dot segments or encoded separators");
    }
    Ok(CimdTarget {
        origin: uri::normalize_origin(&parsed.scheme, parsed.authority),
        path_and_query: parsed.path_and_query.to_string(),
    })
}

/// Validates a fetched metadata document for `client_id`.
pub fn parse_document(client_id: &str, body: &[u8]) -> Result<ClientInfo, &'static str> {
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err("client metadata document is too large");
    }
    let document: Value =
        serde_json::from_slice(body).map_err(|_| "client metadata document is not JSON")?;
    let document = document
        .as_object()
        .ok_or("client metadata document is not a JSON object")?;

    if document.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err("client metadata document client_id does not match its URL");
    }
    if document.contains_key("client_secret") || document.contains_key("client_secret_expires_at") {
        return Err("client metadata document must not contain a client secret");
    }
    match document
        .get("token_endpoint_auth_method")
        .map(Value::as_str)
    {
        None | Some(Some("none")) => {}
        _ => return Err("only token_endpoint_auth_method \"none\" is supported"),
    }

    let redirect_uris = document
        .get("redirect_uris")
        .and_then(Value::as_array)
        .ok_or("client metadata document has no redirect_uris")?;
    if redirect_uris.is_empty() || redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err("client metadata document has an invalid number of redirect_uris");
    }
    let redirect_uris = redirect_uris
        .iter()
        .map(|value| match value.as_str() {
            Some(uri) if uri::is_safe_redirect_uri(uri) => Ok(uri.to_string()),
            _ => Err("client metadata document has an invalid redirect_uri"),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let name = document
        .get("client_name")
        .and_then(Value::as_str)
        .map(consent::sanitize_name)
        .filter(|name| !name.is_empty())
        .map(|name| name.chars().take(MAX_CLIENT_NAME_CHARS).collect());

    Ok(ClientInfo {
        client_id: client_id.to_string(),
        redirect_uris,
        name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "https://client.example/oauth/metadata.json";

    #[test]
    fn validates_client_id_urls() {
        assert_eq!(
            validate_client_id_url("https://Client.Example:443/oauth/metadata.json").unwrap(),
            CimdTarget {
                origin: "https://client.example".to_string(),
                path_and_query: "/oauth/metadata.json".to_string(),
            }
        );
        for bad in [
            "http://client.example/m.json",
            "https://client.example",
            "https://client.example/",
            "https://client.example/m.json#x",
            "https://user@client.example/m.json",
            "https://client.example/a/../m.json",
            "https://client.example/./m.json",
            "https://client.example/a/%2e%2e/m.json",
            "https://client.example/a/%2E/m.json",
            "https://client.example/a%2fm.json",
            "https://client.example/a\\m.json",
            "https://client.example/m.json?v=1",
        ] {
            assert!(validate_client_id_url(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn accepts_valid_document() {
        let body = format!(
            r#"{{"client_id":"{ID}","client_name":"Example","redirect_uris":["https://client.example/cb","http://127.0.0.1/cb"],"token_endpoint_auth_method":"none"}}"#
        );
        let info = parse_document(ID, body.as_bytes()).unwrap();
        assert_eq!(info.client_id, ID);
        assert_eq!(info.redirect_uris.len(), 2);
        assert_eq!(info.name.as_deref(), Some("Example"));

        let spoofed = format!(
            r#"{{"client_id":"{ID}","client_name":"Exa\u202emple","redirect_uris":["https://client.example/cb"]}}"#
        );
        assert_eq!(
            parse_document(ID, spoofed.as_bytes())
                .unwrap()
                .name
                .as_deref(),
            Some("Example")
        );
        let traversal =
            format!(r#"{{"client_id":"{ID}","redirect_uris":["https://client.example/a/../cb"]}}"#);
        assert!(parse_document(ID, traversal.as_bytes()).is_err());
    }

    #[test]
    fn rejects_bad_documents() {
        let cases = [
            r#"{"client_id":"https://other.example/m.json","redirect_uris":["https://c.example/cb"]}"#.to_string(),
            format!(r#"{{"client_id":"{ID}"}}"#),
            format!(r#"{{"client_id":"{ID}","redirect_uris":[]}}"#),
            format!(r#"{{"client_id":"{ID}","redirect_uris":["https://c.example/cb#f"]}}"#),
            format!(r#"{{"client_id":"{ID}","redirect_uris":["https://c.example/cb"],"client_secret":"s"}}"#),
            format!(
                r#"{{"client_id":"{ID}","redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}}"#
            ),
            "[1,2]".to_string(),
            "not json".to_string(),
        ];
        for body in cases {
            assert!(parse_document(ID, body.as_bytes()).is_err(), "{}", body);
        }
        let huge = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        assert!(parse_document(ID, &huge).is_err());
    }
}
