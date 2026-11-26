//! User export API of a tenant: single user, bulk and GDPR bundle (ADM-09). Owned by plan 07-17;
//! pre-declared by 07-04 with an empty router (unknown paths answer 404), so no later plan edits
//! `admin/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of this resource (none yet).
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
