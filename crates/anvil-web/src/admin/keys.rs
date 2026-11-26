//! Signing keys API of a tenant: list and rotate (tag `keys`). Owned by plan 06-11;
//! pre-declared by 06-04 with an empty router (unknown paths answer 404), so no later plan edits
//! `admin/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The signing key routes (none yet).
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
