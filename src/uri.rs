// Copyright 2026 Salesforce, Inc. All rights reserved.

//! Minimal URI handling: just enough to validate redirect URIs and CIMD URLs and to build
//! redirects. Deliberately strict: anything it cannot parse is rejected by the callers.

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "[::1]", "localhost"];
/// Schemes that can execute script or embed content; never acceptable as redirect URIs.
const BLOCKED_SCHEMES: [&str; 4] = ["javascript", "data", "vbscript", "file"];

#[derive(Debug, PartialEq)]
pub struct ParsedUri<'a> {
    /// Lowercased scheme.
    pub scheme: String,
    /// Raw authority (may include userinfo and port).
    pub authority: &'a str,
    /// Lowercased host; IPv6 literals keep their brackets.
    pub host: String,
    pub port: Option<&'a str>,
    pub has_userinfo: bool,
    /// Path plus query, without the fragment. Empty when the URI has no path.
    pub path_and_query: &'a str,
    pub has_fragment: bool,
}

/// Parses `scheme://authority[path][?query][#fragment]`.
pub fn parse(value: &str) -> Option<ParsedUri<'_>> {
    let (scheme, rest) = value.split_once("://")?;
    if scheme.is_empty() || !is_scheme(scheme) {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end)?;
    let after = rest.get(authority_end..)?;
    let (path_and_query, has_fragment) = match after.split_once('#') {
        Some((before, _)) => (before, true),
        None => (after, false),
    };

    let (has_userinfo, host_port) = match authority.rsplit_once('@') {
        Some((_, host_port)) => (true, host_port),
        None => (false, authority),
    };
    let (host, port) = split_host_port(host_port)?;
    if host.is_empty() {
        return None;
    }

    Some(ParsedUri {
        scheme: scheme.to_ascii_lowercase(),
        authority,
        host: host.to_ascii_lowercase(),
        port,
        has_userinfo,
        path_and_query,
        has_fragment,
    })
}

fn split_host_port(host_port: &str) -> Option<(&str, Option<&str>)> {
    if host_port.starts_with('[') {
        let close = host_port.find(']')?;
        let host = host_port.get(..=close)?;
        let rest = host_port.get(close + 1..)?;
        return match rest.strip_prefix(':') {
            Some(port) => Some((host, Some(port))),
            None if rest.is_empty() => Some((host, None)),
            None => None,
        };
    }
    match host_port.rsplit_once(':') {
        Some((host, port)) => Some((host, Some(port))),
        None => Some((host_port, None)),
    }
}

fn is_scheme(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Control characters, space or DEL. Never valid in a URI; in a redirect URI they would end up in
/// a `Location` header (header injection) or in logs (log forging).
fn has_unsafe_chars(value: &str) -> bool {
    value.bytes().any(|b| b <= 0x20 || b == 0x7f)
}

/// True for an absolute URI (`scheme:rest`) with no fragment, no control characters and a scheme
/// that cannot run script. Accepts private-use schemes such as `com.example.app:/callback` used by
/// native clients.
pub fn is_absolute_without_fragment(value: &str) -> bool {
    if has_unsafe_chars(value) || value.contains('#') {
        return false;
    }
    match value.split_once(':') {
        Some((scheme, rest)) => {
            is_scheme(scheme)
                && !rest.is_empty()
                && !BLOCKED_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str())
        }
        None => false,
    }
}

/// `http://127.0.0.1`, `http://[::1]` or `http://localhost`, any port, no userinfo.
pub fn is_loopback_http(value: &str) -> bool {
    if has_unsafe_chars(value) {
        return false;
    }
    match parse(value) {
        Some(uri) => {
            uri.scheme == "http"
                && !uri.has_userinfo
                && !uri.has_fragment
                && LOOPBACK_HOSTS.contains(&uri.host.as_str())
        }
        None => false,
    }
}

/// Whether a redirect URI presented at /authorize matches a registered one. Exact match, except
/// that loopback redirect URIs match on any port (RFC 8252 section 7.3).
pub fn redirect_matches(registered: &str, presented: &str) -> bool {
    if has_unsafe_chars(registered) || has_unsafe_chars(presented) {
        return false;
    }
    if registered == presented {
        return true;
    }
    if !(is_loopback_http(registered) && is_loopback_http(presented)) {
        return false;
    }
    match (parse(registered), parse(presented)) {
        (Some(a), Some(b)) => a.host == b.host && a.path_and_query == b.path_and_query,
        _ => false,
    }
}

/// `scheme://host[:port]`, lowercased, with the scheme's default port removed.
pub fn normalize_origin(scheme: &str, authority: &str) -> String {
    let scheme = scheme.to_ascii_lowercase();
    let authority = authority.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    let authority = match default_port {
        Some(port) => authority
            .strip_suffix(port)
            .unwrap_or(&authority)
            .to_string(),
        None => authority,
    };
    format!("{scheme}://{authority}")
}

/// Appends URL-encoded query parameters to `base`, which may already have a query.
pub fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let query = serde_urlencoded::to_string(params).unwrap_or_default();
    if query.is_empty() {
        return base.to_string();
    }
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}{query}")
}

/// Request path without query string and trailing slash ("/" stays "/").
pub fn route_path(path: &str) -> &str {
    let path = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    match path.strip_suffix('/') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => path,
    }
}

/// Decoded query or form parameters, in order.
pub struct Params(Vec<(String, String)>);

impl Params {
    pub fn from_query_of(path: &str) -> Self {
        let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        Self(serde_urlencoded::from_str(query).unwrap_or_default())
    }

    pub fn from_form(body: &[u8]) -> Option<Self> {
        serde_urlencoded::from_bytes(body).ok().map(Self)
    }

    /// First value of `name`. Empty values count as absent (RFC 6749 section 3.1).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, value)| key == name && !value.is_empty())
            .map(|(_, value)| value.as_str())
    }

    /// The first of `names` that appears more than once (RFC 6749 forbids repeated parameters).
    pub fn first_duplicate<'n>(&self, names: &[&'n str]) -> Option<&'n str> {
        names.iter().copied().find(|name| {
            self.0
                .iter()
                .filter(|(key, _)| key.as_str() == *name)
                .count()
                > 1
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_shapes() {
        let uri = parse("https://User@Example.COM:8443/a/b?c=d#frag").unwrap();
        assert_eq!(uri.scheme, "https");
        assert_eq!(uri.host, "example.com");
        assert_eq!(uri.port, Some("8443"));
        assert!(uri.has_userinfo);
        assert_eq!(uri.path_and_query, "/a/b?c=d");
        assert!(uri.has_fragment);

        let uri = parse("http://[::1]:3000/cb").unwrap();
        assert_eq!(uri.host, "[::1]");
        assert_eq!(uri.port, Some("3000"));

        assert!(parse("example.com/no-scheme").is_none());
        assert!(parse("https:///no-host").is_none());
        assert!(parse("1http://bad-scheme").is_none());
    }

    #[test]
    fn detects_loopback() {
        assert!(is_loopback_http("http://127.0.0.1:33418/callback"));
        assert!(is_loopback_http("http://localhost/cb"));
        assert!(is_loopback_http("http://[::1]:80/cb"));
        assert!(!is_loopback_http("https://127.0.0.1/cb"));
        assert!(!is_loopback_http("http://127.0.0.1@evil.example/cb"));
        assert!(!is_loopback_http("http://127.0.0.1.evil.example/cb"));
        assert!(!is_loopback_http("http://localhost/cb#x"));
    }

    #[test]
    fn matches_redirects() {
        assert!(redirect_matches(
            "https://a.example/cb",
            "https://a.example/cb"
        ));
        assert!(!redirect_matches(
            "https://a.example/cb",
            "https://a.example/cb2"
        ));
        assert!(!redirect_matches(
            "https://a.example/cb",
            "https://a.example:444/cb"
        ));
        assert!(redirect_matches(
            "http://127.0.0.1:1111/callback",
            "http://127.0.0.1:2222/callback"
        ));
        assert!(redirect_matches(
            "http://localhost/callback",
            "http://localhost:5000/callback"
        ));
        assert!(!redirect_matches(
            "http://127.0.0.1:1111/callback",
            "http://127.0.0.1:1111/other"
        ));
        assert!(!redirect_matches(
            "http://localhost/callback",
            "http://127.0.0.1/callback"
        ));
    }

    #[test]
    fn absolute_uris() {
        assert!(is_absolute_without_fragment("https://a.example/cb"));
        assert!(is_absolute_without_fragment("com.example.app:/callback"));
        assert!(!is_absolute_without_fragment("/relative"));
        assert!(!is_absolute_without_fragment("https://a.example/cb#frag"));
        assert!(!is_absolute_without_fragment("https:"));
        assert!(!is_absolute_without_fragment("javascript:alert(1)"));
        assert!(!is_absolute_without_fragment("JavaScript:alert(1)"));
        assert!(!is_absolute_without_fragment("data:text/html,x"));
        assert!(!is_absolute_without_fragment(
            "https://a.example/cb\r\nX-Injected: 1"
        ));
        assert!(!is_absolute_without_fragment("https://a.example/c b"));
    }

    #[test]
    fn rejects_header_injection_in_redirects() {
        let injected = "http://127.0.0.1:5000/cb\r\nSet-Cookie: x=y";
        assert!(!is_loopback_http(injected));
        assert!(!redirect_matches("http://127.0.0.1:5000/cb", injected));
        // Port-ignoring loopback match must not let junk through the authority either.
        assert!(!redirect_matches(
            "http://127.0.0.1:5000/cb",
            "http://127.0.0.1:5000\r\nX: y/cb"
        ));
    }

    #[test]
    fn normalizes_origins() {
        assert_eq!(
            normalize_origin("HTTPS", "Client.Example:443"),
            "https://client.example"
        );
        assert_eq!(
            normalize_origin("https", "client.example:8443"),
            "https://client.example:8443"
        );
        assert_eq!(
            normalize_origin("http", "client.example:80"),
            "http://client.example"
        );
    }

    #[test]
    fn appends_queries() {
        assert_eq!(
            append_query("https://a.example/cb", &[("code", "x y"), ("state", "s&t")]),
            "https://a.example/cb?code=x+y&state=s%26t"
        );
        assert_eq!(
            append_query("https://a.example/cb?k=v", &[("code", "c")]),
            "https://a.example/cb?k=v&code=c"
        );
    }

    #[test]
    fn route_paths() {
        assert_eq!(route_path("/base/oauth/token/"), "/base/oauth/token");
        assert_eq!(
            route_path("/base/oauth/authorize?x=1"),
            "/base/oauth/authorize"
        );
        assert_eq!(route_path("/"), "/");
    }

    #[test]
    fn params() {
        let params = Params::from_query_of("/p?a=1&b=&a=2&c=x%20y");
        assert_eq!(params.get("a"), Some("1"));
        assert_eq!(params.get("b"), None);
        assert_eq!(params.get("c"), Some("x y"));
        assert_eq!(params.first_duplicate(&["c", "a"]), Some("a"));
        assert_eq!(params.first_duplicate(&["c"]), None);
        assert!(Params::from_form(b"grant_type=authorization_code").is_some());
    }
}
