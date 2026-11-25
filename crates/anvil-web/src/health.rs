//! Health endpoints. They never need a tenant.
//!
//! - `/health/live`: the process serves HTTP.
//! - `/health/ready`: storage answers (`SetupRepo::is_installed`); 503 otherwise.
//! - `/healthz`: kept from release 0.0 (liveness).

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

use crate::state::AppState;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/healthz", get(live))
}

async fn live() -> &'static str {
    "ok"
}

async fn ready(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match state.storage().setup().is_installed().await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(e) => {
            tracing::warn!(error = %e, "readiness check: storage unavailable");
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}
