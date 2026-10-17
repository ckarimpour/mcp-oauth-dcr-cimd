use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "allowLoopbackRedirects")]
    pub allow_loopback_redirects: bool,
    #[serde(alias = "allowedRedirectUris")]
    pub allowed_redirect_uris: Option<Vec<String>>,
    #[serde(alias = "challengeUnauthenticated")]
    pub challenge_unauthenticated: bool,
    #[serde(alias = "cimdCacheTtlSeconds")]
    pub cimd_cache_ttl_seconds: i64,
    #[serde(
        alias = "cimdTrustedHosts",
        default,
        deserialize_with = "pdk::serde::deserialize_service_opt_vec"
    )]
    pub cimd_trusted_hosts: Option<Vec<pdk::hl::Service>>,
    #[serde(alias = "clientRegistrationTtlSeconds")]
    pub client_registration_ttl_seconds: i64,
    #[serde(alias = "enableCimd")]
    pub enable_cimd: bool,
    #[serde(alias = "enableDcr")]
    pub enable_dcr: bool,
    #[serde(alias = "mcpResourcePath")]
    pub mcp_resource_path: String,
    #[serde(alias = "publicBaseUrl")]
    pub public_base_url: String,
    #[serde(alias = "requireConsent")]
    pub require_consent: bool,
    #[serde(alias = "scopesSupported")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(alias = "signingSecret")]
    pub signing_secret: String,
    #[serde(alias = "upstreamAuthorizeUrl")]
    pub upstream_authorize_url: String,
    #[serde(alias = "upstreamClientAuthMethod")]
    pub upstream_client_auth_method: String,
    #[serde(alias = "upstreamClientId")]
    pub upstream_client_id: String,
    #[serde(alias = "upstreamClientSecret")]
    pub upstream_client_secret: Option<String>,
    #[serde(alias = "upstreamScope")]
    pub upstream_scope: Option<String>,
    #[serde(
        alias = "upstreamTokenService",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub upstream_token_service: pdk::hl::Service,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    if config.cimd_trusted_hosts.is_some() {
        let services = config.cimd_trusted_hosts.unwrap();
        for service in services {
            abi.service_create(service)?;
        }
    }
    abi.service_create(config.upstream_token_service)?;
    abi.setup()?;
    Ok(())
}
