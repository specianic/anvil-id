//! Live theme preview for the console editor (UI-03). Owner: plan 04-18.
//!
//! Registered (and merged) ahead of time so the owning plan edits only this file. No route exists
//! until 04-18 adds it: requests answer 404, never a placeholder success.

use axum::Router;

use crate::state::AppState;

/// Theme preview routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
