//! Account profile page: name, email change with re-verification (AUTH-13). Owner: plan 04-15.
//!
//! Registered (and merged) ahead of time so the owning plan edits only this file. No route exists
//! until 04-15 adds it: requests answer 404, never a placeholder success.

use axum::Router;

use crate::state::AppState;

/// Account profile routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
