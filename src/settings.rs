// Copyright 2026 Salesforce, Inc. All rights reserved.

//! Validated runtime settings built from the generated `Config`.

use std::time::Duration;

use pdk::hl::Service;

use crate::generated::config::Config;
use crate::oauth::{OAuthInput, OAuthSettings};
use crate::uri;

pub struct Settings {
    pub oauth: OAuthSettings,
    pub token_service: Service,
    /// (normalised origin, service) for every trusted CIMD host.
    pub cimd_hosts: Vec<(String, Service)>,
    /// Zero disables caching of metadata documents.
    pub cimd_cache_ttl: Duration,
}

impl Settings {
    pub fn from_config(config: Config) -> Result<Self, String> {
        let cimd_hosts = config
            .cimd_trusted_hosts
            .unwrap_or_default()
            .into_iter()
            .map(|service| {
                let origin = service.uri();
                if origin.scheme() != "https" {
                    return Err(format!(
                        "cimdTrustedHosts entry '{}' must use https",
                        service.uri()
                    ));
                }
                Ok((
                    uri::normalize_origin(origin.scheme(), origin.authority()),
                    service,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if config.enable_cimd && cimd_hosts.is_empty() {
            return Err("enableCimd requires at least one cimdTrustedHosts entry".into());
        }
        if config.cimd_cache_ttl_seconds < 0 {
            return Err("cimdCacheTtlSeconds must not be negative".into());
        }

        let oauth = OAuthSettings::build(OAuthInput {
            public_base_url: config.public_base_url,
            mcp_resource_path: config.mcp_resource_path,
            upstream_authorize_url: config.upstream_authorize_url,
            upstream_client_id: config.upstream_client_id,
            upstream_client_secret: config.upstream_client_secret,
            upstream_client_auth_method: config.upstream_client_auth_method,
            upstream_scope: config.upstream_scope,
            scopes_supported: config.scopes_supported.unwrap_or_default(),
            signing_secret: config.signing_secret,
            enable_dcr: config.enable_dcr,
            enable_cimd: config.enable_cimd,
            allow_loopback_redirects: config.allow_loopback_redirects,
            allowed_redirect_uris: config.allowed_redirect_uris.unwrap_or_default(),
            client_registration_ttl_seconds: config.client_registration_ttl_seconds,
            challenge_unauthenticated: config.challenge_unauthenticated,
            require_consent: config.require_consent,
        })?;

        Ok(Self {
            oauth,
            token_service: config.upstream_token_service,
            cimd_hosts,
            cimd_cache_ttl: Duration::from_secs(config.cimd_cache_ttl_seconds as u64),
        })
    }

    pub fn cimd_service(&self, origin: &str) -> Option<&Service> {
        self.cimd_hosts
            .iter()
            .find(|(trusted, _)| trusted == origin)
            .map(|(_, service)| service)
    }
}
