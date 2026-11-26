//! Account page for the user's editable custom attributes (ADM-06).
//!
//! Pre-declared by plan 05-02 with no routes (the path stays a 404); owner: plan 05-19.

use axum::Router;

use crate::state::AppState;

/// The routes of this module (tenant-relative paths), merged by the parent module.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
