// Copyright 2026 Salesforce, Inc. All rights reserved.

//! Gateway consent page and browser binding.
//!
//! Every MCP client reaches the IdP as the same pre-registered app, so the IdP's own consent screen
//! cannot tell users which client they are authorizing. The MCP spec therefore requires a proxy
//! with a static client ID to get consent for each dynamically registered client. This page shows
//! who is asking and where access will be sent before the browser goes to the IdP.
//!
//! The browser binding stops consent from being skipped: the page sets a random cookie, the
//! sealed `state` carries its fingerprint, and the callback only proceeds in a browser that has
//! the cookie. A link to the IdP lifted from an attacker's own consent page fails in a victim's
//! browser.

use crate::uri;

/// Lifetime of the binding cookie; matches the sealed state's lifetime.
pub(crate) const COOKIE_MAX_AGE_SECS: u64 = 600;
const MAX_DISPLAY_CHARS: usize = 120;

/// Random values minted per authorization request: `key` names the cookie (so concurrent sign-ins
/// in one browser do not overwrite each other) and `value` is the secret it holds.
pub struct BrowserSecret {
    pub key: String,
    pub value: String,
}

/// `__Host-` cookies must be `Secure`; over plain http (local playground only) a plain name is used.
pub fn cookie_name(secure: bool, key: &str) -> String {
    if secure {
        format!("__Host-mcp-auth-{key}")
    } else {
        format!("mcp-auth-{key}")
    }
}

pub fn set_cookie(secure: bool, secret: &BrowserSecret) -> String {
    let secure_attribute = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        cookie_name(secure, &secret.key),
        secret.value,
        COOKIE_MAX_AGE_SECS,
        secure_attribute
    )
}

/// `Set-Cookie` value that expires the binding cookie once the callback has used it.
pub fn clear_cookie(secure: bool, key: &str) -> String {
    let secure_attribute = if secure { "; Secure" } else { "" };
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        cookie_name(secure, key),
        secure_attribute
    )
}

/// Value of cookie `name` in a `Cookie` header. Accepts `;` and `,` separators, since proxies may
/// join several Cookie headers either way.
pub fn cookie_value<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    header?
        .split([';', ','])
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.trim())
}

/// Human-readable destination of a redirect URI: `scheme://host[:port]` for http(s), so plain
/// http is visible; otherwise the scheme alone, for private-use schemes such as
/// `com.example.app:/callback` or `myapp://callback`, whose "host" is not a real host.
pub fn redirect_display(redirect_uri: &str) -> String {
    match uri::parse(redirect_uri) {
        Some(parsed) if parsed.scheme == "https" || parsed.scheme == "http" => match parsed.port {
            Some(port) => format!("{}://{}:{}", parsed.scheme, parsed.host, port),
            None => format!("{}://{}", parsed.scheme, parsed.host),
        },
        _ => redirect_uri
            .split_once(':')
            .map(|(scheme, _)| format!("{}: (an app on this device)", scheme.to_ascii_lowercase()))
            .unwrap_or_else(|| redirect_uri.to_string()),
    }
}

/// A plain-http destination that is not on this computer: access would travel unencrypted.
pub fn is_insecure_http(redirect_uri: &str) -> bool {
    uri::parse(redirect_uri).is_some_and(|parsed| parsed.scheme == "http")
        && !uri::is_loopback_http(redirect_uri)
}

/// Removes control, bidi-override and zero-width characters from a client-supplied name, so it
/// can't visually impersonate another client on the consent page.
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_formatting(*c))
        .collect();
    cleaned.trim().to_string()
}

fn is_invisible_formatting(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Host of a CIMD client_id, which the gateway fetched from a trusted host and can vouch for.
pub fn client_host(client_id: &str) -> Option<String> {
    if !client_id.starts_with("https://") {
        return None;
    }
    uri::parse(client_id).map(|parsed| parsed.host)
}

pub struct ConsentView<'a> {
    /// Name supplied by the client (DCR) or its metadata document (CIMD).
    pub client_name: Option<&'a str>,
    /// Set for CIMD clients: the host that published the client's metadata.
    pub client_host: Option<String>,
    pub redirect_display: String,
    pub loopback: bool,
    /// Destination uses plain http on another machine.
    pub insecure_http: bool,
    /// The scopes that will be requested from the identity provider.
    pub scopes: Vec<&'a str>,
    /// The MCP server being authorized.
    pub resource: &'a str,
    pub continue_url: &'a str,
    pub cancel_url: &'a str,
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn truncate(value: &str) -> String {
    if value.chars().count() <= MAX_DISPLAY_CHARS {
        value.to_string()
    } else {
        let mut cut: String = value.chars().take(MAX_DISPLAY_CHARS).collect();
        cut.push('…');
        cut
    }
}

pub fn render(view: &ConsentView) -> String {
    let name = view
        .client_name
        .map(sanitize_name)
        .filter(|n| !n.is_empty())
        .map(|n| format!("<strong>{}</strong>", escape(&truncate(&n))))
        .unwrap_or_else(|| "<strong>An unnamed application</strong>".to_string());
    let identity = match &view.client_host {
        Some(host) => format!(
            "<p>Identified by <strong>{}</strong>, which publishes this app's registration.</p>",
            escape(host)
        ),
        None => "<p class=\"muted\">This app registered itself. Its name is self-reported and has not been verified.</p>".to_string(),
    };
    let warning = if view.loopback {
        format!(
            "<div class=\"warn\"><strong>Access will be sent to an app on this computer ({}).</strong> \
             Only continue if you just started connecting an app on this device. If you did not, cancel.</div>",
            escape(&view.redirect_display)
        )
    } else if view.insecure_http {
        format!(
            "<div class=\"warn\"><strong>Access will be sent over an unencrypted http connection \
             ({}).</strong> Only continue if you trust this destination.</div>",
            escape(&view.redirect_display)
        )
    } else {
        String::new()
    };
    let permissions = if view.scopes.is_empty() {
        String::new()
    } else {
        let items: String = view
            .scopes
            .iter()
            .map(|scope| format!("<li><code>{}</code></li>", escape(&truncate(scope))))
            .collect();
        format!("<p>It is asking for these permissions:</p>\n<ul class=\"scopes\">{items}</ul>")
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access</title>
<style>
body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #f4f5f7; color: #1d1f23; margin: 0; }}
main {{ max-width: 30rem; margin: 3rem auto; background: #fff; border-radius: 12px; padding: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,.12); }}
h1 {{ font-size: 1.25rem; margin: 0 0 1rem; }}
.muted {{ color: #5c616b; font-size: .9rem; }}
.dest {{ background: #f4f5f7; border-radius: 8px; padding: .75rem 1rem; word-break: break-all; }}
.warn {{ background: #fff4e5; border: 1px solid #f0b357; border-radius: 8px; padding: .75rem 1rem; margin: 1rem 0; }}
.scopes {{ margin: .25rem 0 1rem; padding-left: 1.25rem; }}
.actions {{ display: flex; gap: .75rem; margin-top: 1.5rem; }}
a.button {{ flex: 1; text-align: center; padding: .7rem 1rem; border-radius: 8px; text-decoration: none; font-weight: 600; }}
a.primary {{ background: #0b5cad; color: #fff; }}
a.secondary {{ background: #e8eaee; color: #1d1f23; }}
</style>
</head>
<body>
<main>
<h1>Authorize access</h1>
<p>{name} wants to access <strong>{resource}</strong> on your behalf.</p>
{identity}
{permissions}
<p>After you sign in, access will be sent to:</p>
<p class="dest"><strong>{destination}</strong></p>
{warning}
<p class="muted">You will sign in with your organization's identity provider next.</p>
<div class="actions">
<a class="button secondary" id="cancel" href="{cancel}">Cancel</a>
<a class="button primary" id="continue" href="{continue_url}">Continue</a>
</div>
</main>
</body>
</html>
"#,
        name = name,
        resource = escape(&truncate(view.resource)),
        identity = identity,
        permissions = permissions,
        destination = escape(&view.redirect_display),
        warning = warning,
        cancel = escape(view.cancel_url),
        continue_url = escape(view.continue_url),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view<'a>(name: Option<&'a str>, loopback: bool) -> ConsentView<'a> {
        ConsentView {
            client_name: name,
            client_host: None,
            redirect_display: if loopback {
                "http://127.0.0.1:5000".into()
            } else {
                "https://client.example".into()
            },
            loopback,
            insecure_http: false,
            scopes: vec!["mcp.read"],
            resource: "https://gw.example/mcp-server/mcp",
            continue_url: "https://idp.example/authorize?a=1&b=2",
            cancel_url: "https://client.example/cb?error=access_denied",
        }
    }

    #[test]
    fn escapes_untrusted_values() {
        let html = render(&view(Some("<script>alert(1)</script>\"x"), false));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;x"));
        assert!(html.contains("href=\"https://idp.example/authorize?a=1&amp;b=2\""));
    }

    #[test]
    fn warns_only_for_loopback() {
        assert!(render(&view(Some("App"), true))
            .contains("an app on this computer (http://127.0.0.1:5000)"));
        assert!(!render(&view(Some("App"), false)).contains("class=\"warn\""));
    }

    #[test]
    fn shows_scopes_and_warns_on_plain_http() {
        let html = render(&view(Some("App"), false));
        assert!(html.contains("<li><code>mcp.read</code></li>"));
        let mut no_scopes = view(Some("App"), false);
        no_scopes.scopes = vec![];
        assert!(!render(&no_scopes).contains("these permissions"));

        let mut http = view(Some("App"), false);
        http.redirect_display = "http://client.example".into();
        http.insecure_http = true;
        assert!(render(&http).contains("unencrypted http connection (http://client.example)"));
        assert!(is_insecure_http("http://client.example/cb"));
        assert!(!is_insecure_http("http://127.0.0.1:5000/cb"));
        assert!(!is_insecure_http("https://client.example/cb"));
    }

    #[test]
    fn strips_spoofing_characters_from_names() {
        assert_eq!(sanitize_name("Clau\u{202E}edoc"), "Clauedoc");
        assert_eq!(sanitize_name(" Good\u{200B}App\u{0007} "), "GoodApp");
        assert_eq!(sanitize_name("\u{2066}\u{2069}"), "");
        let html = render(&view(Some("\u{202E}evil"), false));
        assert!(!html.contains('\u{202E}'));
        assert!(render(&view(Some("\u{200B}"), false)).contains("An unnamed application"));
    }

    #[test]
    fn labels_unverified_and_cimd_clients() {
        let html = render(&view(None, false));
        assert!(html.contains("An unnamed application"));
        assert!(html.contains("self-reported"));
        let mut cimd = view(Some("App"), false);
        cimd.client_host = Some("client.example".into());
        let html = render(&cimd);
        assert!(html.contains("Identified by <strong>client.example</strong>"));
        assert!(!html.contains("self-reported"));
    }

    #[test]
    fn truncates_long_names() {
        let long = "a".repeat(500);
        let html = render(&view(Some(&long), false));
        assert!(html.contains(&format!("{}…", "a".repeat(MAX_DISPLAY_CHARS))));
        assert!(!html.contains(&"a".repeat(MAX_DISPLAY_CHARS + 1)));
    }

    #[test]
    fn builds_and_reads_cookies() {
        let secret = BrowserSecret {
            key: "k1".into(),
            value: "v1".into(),
        };
        let header = set_cookie(true, &secret);
        assert_eq!(
            header,
            "__Host-mcp-auth-k1=v1; Path=/; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
        );
        assert_eq!(
            set_cookie(false, &secret),
            "mcp-auth-k1=v1; Path=/; HttpOnly; SameSite=Lax; Max-Age=600"
        );
        let name = cookie_name(true, "k1");
        assert_eq!(
            cookie_value(Some("a=b; __Host-mcp-auth-k1=v1; c=d"), &name),
            Some("v1")
        );
        assert_eq!(
            cookie_value(Some("a=b, __Host-mcp-auth-k1=v1"), &name),
            Some("v1")
        );
        assert_eq!(cookie_value(Some("__Host-mcp-auth-k2=v1"), &name), None);
        assert_eq!(cookie_value(None, &name), None);
        assert_eq!(
            clear_cookie(true, "k1"),
            "__Host-mcp-auth-k1=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure"
        );
        assert_eq!(
            clear_cookie(false, "k1"),
            "mcp-auth-k1=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        );
    }

    #[test]
    fn displays_destinations() {
        assert_eq!(
            redirect_display("http://127.0.0.1:5000/cb"),
            "http://127.0.0.1:5000"
        );
        assert_eq!(
            redirect_display("https://Client.Example/oauth/cb?x=1"),
            "https://client.example"
        );
        assert_eq!(
            redirect_display("com.example.app:/callback"),
            "com.example.app: (an app on this device)"
        );
        // A private-use scheme's "host" is not a real host and must not be shown as one.
        assert_eq!(
            redirect_display("myapp://callback"),
            "myapp: (an app on this device)"
        );
        assert_eq!(
            client_host("https://client.example/m.json"),
            Some("client.example".to_string())
        );
        assert_eq!(client_host("v1.abc.def"), None);
    }
}
