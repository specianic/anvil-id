//! Organization administration API: organizations, members, org roles, invitations, domains and
//! enterprise connections of a tenant (tag `organizations`). Owned by plan 06-12 (domains and
//! connections by 06-17); pre-declared by 06-04 with an empty router (unknown paths answer 404),
//! so no later plan edits `admin/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The organization routes (none yet).
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
