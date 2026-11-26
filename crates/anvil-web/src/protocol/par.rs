//! `POST /par`: pushed authorization requests (RFC 9126, OIDC-18). Client-authenticated like
//! `/token` (rate-limit class `Token`, no CORS, no Fetch-Metadata). Owned by plan 07-13;
//! pre-declared by 07-04 with an empty router (the path answers 404), so no later plan edits
//! `protocol/mod.rs`.

use axum::Router;

use crate::state::AppState;

/// The pushed authorization request route (none yet).
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
}
