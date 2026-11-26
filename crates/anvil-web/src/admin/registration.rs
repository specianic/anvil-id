//! Dynamic client registration and CIMD policy, and initial access tokens of a tenant (AUTH-14, OIDC-17).
//!
//! Pre-declared by plan 05-02 with no routes (an unknown path stays a 404 problem); owner:
//! plan 05-23.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
