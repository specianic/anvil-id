//! HTTP layer: axum router, handlers and embedded assets. Depends on storage only through ports.

mod assets;
mod discovery;
mod not_implemented;

use axum::Router;
use axum::routing::{get, post};

/// Configuration for the HTTP surface.
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// The OpenID Provider issuer. Endpoint URLs are derived from it. Must not contain a query or fragment
    /// (the binary rejects such values before building the router).
    pub issuer: url::Url,
}

/// Builds the complete HTTP router.
pub fn router(cfg: WebConfig) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/.well-known/openid-configuration", get(discovery::handler))
        .route("/authorize", get(not_implemented::authorize))
        .route("/token", post(not_implemented::token))
        .route("/jwks", get(not_implemented::jwks))
        .route("/assets/{*path}", get(assets::handler))
        .with_state(discovery::Discovery::new(&cfg.issuer))
}

async fn healthz() -> &'static str {
    "ok"
}
