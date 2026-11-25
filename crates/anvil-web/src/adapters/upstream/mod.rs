//! Upstream identity-provider HTTP adapter (AUTH-07). Owner: plan 04-14.
//!
//! [`UpstreamHttp`] implements the core [`UpstreamClient`] port: OIDC discovery
//! ([`discovery`]), cached JWK Sets ([`jwks`]), the authorization-code exchange ([`token`]) and
//! bearer API calls such as userinfo or the GitHub REST API ([`api`]). Every request goes
//! through the single SSRF-guarded [`OutboundClient`] (no other HTTP client exists), with its
//! timeouts and the body limits [`LIMIT_DOCUMENT`](crate::adapters::outbound::LIMIT_DOCUMENT)
//! (documents) and [`LIMIT_TOKEN`](crate::adapters::outbound::LIMIT_TOKEN) (token responses).
//!
//! The adapter only moves bytes and checks response shape (exact discovery issuer, endpoint
//! schemes, public-only JWKS, token-response fields). ID-token validation is pure core logic
//! (`anvil_core::upstream::claims`). Logging is at debug level and names the URL host only;
//! codes, secrets and tokens are never logged.

pub mod api;
pub mod discovery;
pub mod jwks;
pub mod token;

use std::sync::Arc;

use anvil_core::ports::{
    ApiProfile, CodeExchange, ProviderMetadata, TokenSet, UpstreamClient, UpstreamError,
};
use anvil_jose::Jwks;
use secrecy::SecretString;

use crate::adapters::outbound::OutboundClient;

/// The upstream adapter handle held by [`crate::state::AppState`]. Cheap to clone; clones share
/// the discovery and JWKS caches.
#[derive(Clone)]
pub struct UpstreamHttp {
    outbound: Arc<OutboundClient>,
    discovery: discovery::DiscoveryCache,
    jwks: jwks::JwksCache,
}

impl std::fmt::Debug for UpstreamHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamHttp")
            .field("outbound", &self.outbound)
            .finish_non_exhaustive()
    }
}

impl UpstreamHttp {
    pub fn new(outbound: Arc<OutboundClient>) -> Self {
        Self {
            outbound,
            discovery: discovery::DiscoveryCache::new(),
            jwks: jwks::JwksCache::new(),
        }
    }

    /// The guarded client every upstream request goes through.
    pub fn outbound(&self) -> &OutboundClient {
        &self.outbound
    }
}

#[async_trait::async_trait]
impl UpstreamClient for UpstreamHttp {
    async fn metadata(&self, issuer: &str) -> Result<ProviderMetadata, UpstreamError> {
        self.discovery.get(&self.outbound, issuer).await
    }

    async fn jwks(&self, jwks_uri: &str, force_refresh: bool) -> Result<Jwks, UpstreamError> {
        self.jwks
            .get(&self.outbound, jwks_uri, force_refresh)
            .await
            .map(|set| (*set).clone())
    }

    async fn exchange_code(&self, exchange: &CodeExchange) -> Result<TokenSet, UpstreamError> {
        token::exchange_code(&self.outbound, exchange).await
    }

    async fn get_json(
        &self,
        url: &str,
        bearer: &SecretString,
        profile: ApiProfile,
    ) -> Result<serde_json::Value, UpstreamError> {
        api::get_json(&self.outbound, url, bearer, profile).await
    }
}

/// The host of `url` for debug logs (never the path or query, which may carry codes).
pub(crate) fn log_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<invalid>".to_owned())
}
