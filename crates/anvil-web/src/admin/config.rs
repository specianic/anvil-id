//! Declarative tenant configuration: export, plan and apply (ADM-07).
//!
//! Pre-declared by plan 05-02 with no routes (an unknown path stays a 404 problem); owner:
//! plan 05-20.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
