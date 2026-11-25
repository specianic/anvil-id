//! Account connected-apps page: list and revoke consents and grants.
//!
//! Owned by plan 03-17. Until it lands this router has no routes, so the endpoints do not exist
//! (404), rather than answering with a placeholder.

use axum::Router;

use crate::state::AppState;

/// The routes of this module (tenant-relative paths).
pub fn routes() -> Router<AppState> {
    Router::new()
}
