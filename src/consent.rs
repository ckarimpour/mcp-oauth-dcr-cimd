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

/// Value of cookie `name` in a `Cookie` header. Accepts `;` and `,` separators, since proxies may
/// join several Cookie headers either way.
pub fn cookie_value<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    header?
        .split([';', ','])
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.trim())
}

/// Human-readable destination of a redirect URI: `host[:port]`, or the scheme for private-use
/// schemes such as `com.example.app:/callback`.
pub fn redirect_display(redirect_uri: &str) -> String {
    match uri::parse(redirect_uri) {
        Some(parsed) => match parsed.port {
            Some(port) => format!("{}:{}", parsed.host, port),
            None => parsed.host,
        },
        None => redirect_uri
            .split_once(':')
            .map(|(scheme, _)| format!("{scheme}: (an app on this device)"))
            .unwrap_or_else(|| redirect_uri.to_string()),
    }
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
        .map(|n| format!("<strong>{}</strong>", escape(&truncate(n))))
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
    } else {
        String::new()
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
                "127.0.0.1:5000".into()
            } else {
                "client.example".into()
            },
            loopback,
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
        assert!(
            render(&view(Some("App"), true)).contains("an app on this computer (127.0.0.1:5000)")
        );
        assert!(!render(&view(Some("App"), false)).contains("class=\"warn\""));
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
    }

    #[test]
    fn displays_destinations() {
        assert_eq!(
            redirect_display("http://127.0.0.1:5000/cb"),
            "127.0.0.1:5000"
        );
        assert_eq!(
            redirect_display("https://Client.Example/oauth/cb?x=1"),
            "client.example"
        );
        assert_eq!(
            redirect_display("com.example.app:/callback"),
            "com.example.app: (an app on this device)"
        );
        assert_eq!(
            client_host("https://client.example/m.json"),
            Some("client.example".to_string())
        );
        assert_eq!(client_host("v1.abc.def"), None);
    }
}
