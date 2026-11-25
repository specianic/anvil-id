//! Account chooser for `prompt=select_account` (OIDC-14). Owner: plan 04-20.
//!
//! Registered (and merged) ahead of time so the owning plan edits only this file. No route exists
//! until 04-20 adds it: requests answer 404, never a placeholder success.

use axum::Router;

use crate::state::AppState;

/// Account chooser routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
