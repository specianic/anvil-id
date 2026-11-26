//! `/ui/select-organization`: the organization switcher on the user-bound flow. Owned by plan
//! 06-19; pre-declared by 06-04 with an empty router (404), so no later plan edits `ui/mod.rs`.

use axum::Router;

use crate::state::AppState;

/// Switcher routes, behind the Fetch-Metadata layer (none yet).
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
