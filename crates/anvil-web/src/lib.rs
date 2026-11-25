//! HTTP layer: axum router, handlers and embedded assets. Depends on storage only through ports.
//!
//! [`app`] builds the release 0.1 application. The release 0.0 [`router`] stays in use by the
//! binary until plan 02-18 switches over.

pub mod admin;
mod assets;
pub mod config;
pub mod cookies;
mod discovery;
pub mod errors;
mod health;
pub mod layers;
mod not_implemented;
pub mod protocol;
pub mod render;
pub mod state;
pub mod tenant;
pub mod ui;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

pub use config::AppConfig;
pub use errors::WebError;
pub use state::{AppDeps, AppState};
pub use tenant::ResolvedTenant;

/// Maximum request body size (forms and token requests are small).
pub const BODY_LIMIT: usize = 64 * 1024;

/// Builds the complete release 0.1 application.
///
/// The tenant layer wraps the inner router as a service (the outer router's fallback), so it runs
/// before routing and can rewrite `/t/{slug}/…` paths. Protocol, UI and admin modules contribute
/// their routes through their own `routes()` functions.
pub fn app(config: AppConfig, deps: AppDeps) -> Result<Router, WebError> {
    let state = AppState::new(config, deps)?;
    let inner = Router::new()
        .merge(protocol::routes())
        .merge(ui::routes())
        .merge(admin::routes())
        .merge(health::routes())
        .route("/assets/{*path}", get(assets::handler))
        .fallback(not_found)
        .with_state(state.clone());
    let tenant_routed = ServiceBuilder::new()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            tenant::resolve,
        ))
        .service(inner);
    let headers = layers::security_headers::SecurityHeaders {
        hsts: state.config().is_https(),
    };
    Ok(Router::new()
        .fallback_service(tenant_routed)
        .layer(axum::middleware::map_response_with_state(
            headers,
            layers::security_headers::security_headers,
        ))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid)))
}

async fn not_found(State(state): State<AppState>, tenant: Option<ResolvedTenant>) -> Response {
    errors::error_page(
        &state,
        tenant.as_ref(),
        StatusCode::NOT_FOUND,
        "not_found",
        "",
    )
}

/// Configuration for the release 0.0 HTTP surface.
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// The OpenID Provider issuer. Endpoint URLs are derived from it. Must not contain a query or fragment
    /// (the binary rejects such values before building the router).
    pub issuer: url::Url,
}

/// Builds the release 0.0 HTTP router (removed by plan 02-18).
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
