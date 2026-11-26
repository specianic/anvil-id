//! `/ui/invitation`: accepting an organization invitation. Owned by plan 06-20; pre-declared by
//! 06-04 with an empty router (404), so no later plan edits `ui/mod.rs`.

use axum::Router;

use crate::state::AppState;

/// Invitation routes, behind the Fetch-Metadata layer (none yet).
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
