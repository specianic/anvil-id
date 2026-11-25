//! MFA challenge and enrolment pages (TOTP, recovery codes, passkey step-up).
//!
//! Owned by plan 03-20. Until it lands this router has no routes, so the endpoints do not exist
//! (404), rather than answering with a placeholder.

use axum::Router;

use crate::state::AppState;

/// The routes of this module (tenant-relative paths).
pub fn routes() -> Router<AppState> {
    Router::new()
}
