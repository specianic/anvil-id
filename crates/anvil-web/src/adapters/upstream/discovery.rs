//! OIDC discovery (OpenID Connect Discovery 1.0 §4) with a one-hour cache per issuer.
//!
//! The document is fetched from `{issuer}/.well-known/openid-configuration` (a trailing slash
//! on the issuer is not doubled). It is accepted only when its `issuer` equals the requested
//! issuer exactly (§4.3) and every endpoint is a URL the guarded outbound client would send to:
//! https, or plain http only where the outbound policy allows it (development mode, allow-listed
//! destination). Failures are never cached.

use std::sync::Arc;
use std::time::Duration;

use anvil_core::ports::{ProviderMetadata, UpstreamError};
use moka::sync::Cache;
use reqwest::header::{ACCEPT, HeaderValue};
use serde::Deserialize;

use crate::adapters::outbound::{LIMIT_DOCUMENT, OutboundClient};

/// How long an accepted discovery document is reused.
pub const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const MAX_ENTRIES: u64 = 10_000;

#[derive(Deserialize)]
struct RawMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
}

/// Discovery documents keyed by issuer.
#[derive(Clone)]
pub struct DiscoveryCache {
    cache: Cache<String, Arc<ProviderMetadata>>,
}

impl Default for DiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(MAX_ENTRIES)
                .time_to_live(DISCOVERY_TTL)
                .build(),
        }
    }

    /// The (cached) metadata of `issuer`.
    pub async fn get(
        &self,
        outbound: &OutboundClient,
        issuer: &str,
    ) -> Result<ProviderMetadata, UpstreamError> {
        if let Some(md) = self.cache.get(issuer) {
            return Ok((*md).clone());
        }
        let md = fetch(outbound, issuer).await?;
        self.cache.insert(issuer.to_owned(), Arc::new(md.clone()));
        Ok(md)
    }
}

/// `{issuer}/.well-known/openid-configuration`, without doubling a trailing slash.
pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// Fetches and checks the discovery document of `issuer` (uncached).
pub async fn fetch(
    outbound: &OutboundClient,
    issuer: &str,
) -> Result<ProviderMetadata, UpstreamError> {
    let parsed = url::Url::parse(issuer).map_err(|_| UpstreamError::Blocked)?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(UpstreamError::InvalidResponse("invalid issuer"));
    }
    let url = discovery_url(issuer);
    tracing::debug!(host = %super::log_host(&url), "fetching upstream discovery document");
    let body = outbound
        .get(&url)?
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .fetch(LIMIT_DOCUMENT)
        .await?;
    let raw: RawMetadata = serde_json::from_slice(&body)
        .map_err(|_| UpstreamError::InvalidResponse("malformed discovery document"))?;
    if raw.issuer != issuer {
        return Err(UpstreamError::InvalidResponse("issuer mismatch"));
    }
    for endpoint in [
        Some(&raw.authorization_endpoint),
        Some(&raw.token_endpoint),
        Some(&raw.jwks_uri),
        raw.userinfo_endpoint.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        check_endpoint(outbound, endpoint)?;
    }
    Ok(ProviderMetadata {
        issuer: raw.issuer,
        authorization_endpoint: raw.authorization_endpoint,
        token_endpoint: raw.token_endpoint,
        userinfo_endpoint: raw.userinfo_endpoint,
        jwks_uri: raw.jwks_uri,
        id_token_signing_alg_values_supported: raw.id_token_signing_alg_values_supported,
        authorization_response_iss_parameter_supported: raw
            .authorization_response_iss_parameter_supported,
        code_challenge_methods_supported: raw.code_challenge_methods_supported,
    })
}

/// An endpoint must be a URL the outbound client would send to (https, or allowed http).
fn check_endpoint(outbound: &OutboundClient, endpoint: &str) -> Result<(), UpstreamError> {
    let url = url::Url::parse(endpoint)
        .map_err(|_| UpstreamError::InvalidResponse("invalid endpoint URL"))?;
    outbound
        .check_url(&url)
        .map_err(|_| UpstreamError::InvalidResponse("endpoint not allowed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_url_join_is_trailing_slash_safe() {
        assert_eq!(
            discovery_url("https://idp.example"),
            "https://idp.example/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://idp.example/tenant/"),
            "https://idp.example/tenant/.well-known/openid-configuration"
        );
    }
}
