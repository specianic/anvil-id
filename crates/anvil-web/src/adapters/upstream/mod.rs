//! Upstream identity-provider HTTP adapter (AUTH-07). Owner: plan 04-14.
//!
//! Discovery, JWKS, token and userinfo requests to social / generic OIDC / OAuth2 providers.
//! Every request goes through the single SSRF-guarded [`OutboundClient`]; the provider methods,
//! the discovery/JWKS caches and the core port implementation arrive in 04-14.

use std::sync::Arc;

use crate::adapters::outbound::OutboundClient;

/// The upstream adapter handle held by [`crate::state::AppState`].
#[derive(Debug, Clone)]
pub struct UpstreamHttp {
    outbound: Arc<OutboundClient>,
}

impl UpstreamHttp {
    pub fn new(outbound: Arc<OutboundClient>) -> Self {
        Self { outbound }
    }

    /// The guarded client every upstream request goes through.
    pub fn outbound(&self) -> &OutboundClient {
        &self.outbound
    }
}
