//! HTTP layer: axum router, handlers and embedded assets. Depends on storage only through ports.
//!
//! [`app`] builds the application the binary serves.

pub mod adapters;
pub mod admin;
mod assets;
pub mod client_ip;
pub mod config;
pub mod console;
pub mod cookies;
pub mod errors;
mod health;
mod http_cache;
pub mod i18n;
pub mod layers;
pub mod protocol;
pub mod render;
pub mod request_context;
pub mod state;
pub mod tenant;
mod theme;
pub mod ui;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
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
        .merge(theme::routes())
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
        // After tenant resolution: paths are tenant-relative and `ResolvedTenant` is set.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            layers::ratelimit::layer,
        ))
        .service(inner);
    let headers = layers::security_headers::SecurityHeaders {
        hsts: state.config().is_https(),
    };
    Ok(Router::new()
        // Installation-wide, outside tenant resolution: `/t/{slug}/console/` is not the console.
        .merge(console::routes())
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
