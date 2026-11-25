//! Login flow pages. Owner: plan 02-15. No routes yet (requests fall through to the 404 page).

use axum::Router;

use crate::state::AppState;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
}
