//! Health endpoints. They never need a tenant: they are routed outside tenant resolution and
//! the rate limiter.
//!
//! - `/health/live`, `/healthz`: the process serves HTTP (liveness).
//! - `/health/ready`, `/readyz`: one handler. 200 when the node is ready
//!   ([`AppState::is_ready`], cleared on shutdown for the drain delay) and storage answers
//!   (`SetupRepo::is_installed`); 503 otherwise.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

use crate::state::AppState;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/health/live", get(live))
        .route("/healthz", get(live))
        .route("/health/ready", get(ready))
        .route("/readyz", get(ready))
}

async fn live() -> &'static str {
    "ok"
}

async fn ready(State(state): State<AppState>) -> (StatusCode, &'static str) {
    if !state.is_ready() {
        return (StatusCode::SERVICE_UNAVAILABLE, "draining");
    }
    match state.storage().setup().is_installed().await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(e) => {
            tracing::warn!(error = %e, "readiness check: storage unavailable");
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}
