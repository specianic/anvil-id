//! RFC 7591 dynamic client registration and RFC 7592 client configuration endpoints (AUTH-14).
//!
//! Pre-declared by plan 05-02 with no routes (the path stays a 404); owner: plan 05-21.

use axum::Router;

use crate::state::AppState;

/// The routes of this module (tenant-relative paths), merged by the parent module.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
