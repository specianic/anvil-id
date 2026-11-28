//! HTTP layer: axum router, handlers and embedded assets. Depends on storage only through ports.
//!
//! [`app`] builds the application the binary serves.

pub mod adapters;
pub mod admin;
// Phase 7 (pre-declared by plan 07-04; plans 07-10 and 07-18 fill it in)
pub mod api_flows;
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
pub mod observability;
pub mod protocol;
pub mod render;
pub mod request_context;
// Phase 7.1 (plan 07.1-08): tenant root pages and the setup guidance page.
mod root;
pub mod state;
pub mod tenant;
mod theme;
pub mod ui;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

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
    Ok(router(AppState::new(config, deps)?))
}

/// [`app`] over an existing state, for callers that also need the state (the binary hands
/// [`AppState::logout_wake`] and [`AppState::outbound_arc`] to the back-channel logout worker).
pub fn router(state: AppState) -> Router {
    let inner = Router::new()
        .merge(protocol::routes())
        .merge(ui::routes())
        // Headless flow API: outside ui's Fetch-Metadata layer and outside `public_cors()`
        // (it brings its own origin and CORS layers).
        .merge(api_flows::routes())
        .merge(theme::routes())
        .merge(root::routes())
        .merge(admin::routes())
        .route("/assets/{*path}", get(assets::handler))
        // Hands the matched (tenant-relative) route template to the request layer.
        .route_layer(axum::middleware::from_fn(observability::record_route))
        .fallback(not_found)
        .with_state(state.clone());
    let tenant_routed = ServiceBuilder::new()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            tenant::resolve,
        ))
        // Records the tenant on the request span and the route class for the metrics.
        .layer(axum::middleware::from_fn(observability::tenant_context))
        // After tenant resolution: paths are tenant-relative and `ResolvedTenant` is set.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            layers::ratelimit::layer,
        ))
        .service(inner);
    let headers = layers::security_headers::SecurityHeaders {
        hsts: state.config().is_https(),
    };
    let mut outer = Router::new()
        // Installation-wide, outside tenant resolution: `/t/{slug}/console/` is not the console.
        .merge(console::routes().with_state(state.clone()))
        // Probes never depend on tenant lookups and are never rate limited.
        .merge(health::routes().with_state(state.clone()));
    // `metrics_on_main_port`: the same /metrics route as the separate listener, outside tenant
    // resolution and rate limiting. Absent otherwise (404).
    if let Some(metrics) = state.config().metrics.clone() {
        outer = outer.merge(observability::metrics_router(metrics));
    }
    outer
        .route_layer(axum::middleware::from_fn(observability::record_route))
        .fallback_service(tenant_routed)
        .layer(axum::middleware::map_response_with_state(
            headers,
            layers::security_headers::security_headers,
        ))
        // BODY_LIMIT everywhere; only the admin logo upload gets its larger limit (UI-03).
        .layer(axum::middleware::from_fn(admin::branding::body_limit))
        // The one request span/log/metrics layer (route templates only, never the raw URI).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            observability::observe,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

/// The router fallback: the 404 page in the request's language, with the signed-in or signed-out
/// way forward.
async fn not_found(
    State(state): State<AppState>,
    tenant: Option<ResolvedTenant>,
    i18n::RequestLocale(loc, _): i18n::RequestLocale,
    jar: axum_extra::extract::cookie::CookieJar,
) -> Response {
    errors::error_page_for(
        &state,
        tenant.as_ref(),
        &loc,
        &jar,
        errors::ErrorPage {
            status: StatusCode::NOT_FOUND,
            error_key: "not_found",
            detail: "",
        },
    )
    .await
}
