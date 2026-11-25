//! Management API (`/api/admin/v1`). Owner: plan 02-16, which replaces this file.

use axum::Router;

use crate::state::AppState;

/// Management API routes. None yet.
pub fn routes() -> Router<AppState> {
    Router::new()
}
