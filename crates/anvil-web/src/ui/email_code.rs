//! Email OTP and magic-link sign-in (AUTH-06). Owner: plan 04-24.
//!
//! Registered (and merged) ahead of time so the owning plan edits only this file. No route exists
//! until 04-24 adds it: requests answer 404, never a placeholder success.

use axum::Router;

use crate::state::AppState;

/// Email code routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
