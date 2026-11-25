//! Logout confirmation and post-logout pages (OIDC-12). Owner: plan 04-13.
//!
//! Registered (and merged) ahead of time so the owning plan edits only this file. No route exists
//! until 04-13 adds it: requests answer 404, never a placeholder success.

use axum::Router;

use crate::state::AppState;

/// Logout UI routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
