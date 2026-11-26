//! Webhook endpoints, secret rotation, test sends and the delivery log of a tenant (AGT-01).
//!
//! Pre-declared by plan 05-02 with no routes (an unknown path stays a 404 problem); owner:
//! plan 05-23.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
