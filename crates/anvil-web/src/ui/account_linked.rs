//! Linked upstream identities on the account page and link confirmation (AUTH-11). Owner: plan 04-25.
//!
//! Registered (and merged) ahead of time so the owning plan edits only this file. No route exists
//! until 04-25 adds it: requests answer 404, never a placeholder success.

use axum::Router;

use crate::state::AppState;

/// Linked-identity routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
