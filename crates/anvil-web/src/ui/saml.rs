//! SAML 2.0 SP sign-in pages: start (`/ui/login/saml/{slug}`), the assertion consumer service
//! (`POST /ui/login/saml/{slug}/acs`) and the continue step. Owned by plan 06-18; pre-declared by
//! 06-04 with empty routers (404), so no later plan edits `ui/mod.rs`.
//!
//! Two routers, like [`super::upstream`]:
//!
//! - [`routes`] (start, continue) sits behind the Fetch-Metadata CSRF layer;
//! - [`callback_routes`] (the ACS) is merged **after** that layer: the IdP's HTTP-POST binding is
//!   a cross-site form post that the layer would refuse, and it carries no cookies. The ACS is
//!   protected instead by RelayState, `InResponseTo`, the verified signature and the assertion id
//!   replay cache, and the browser continues on a same-site GET bound to the binding cookie.

use axum::Router;

use crate::state::AppState;

/// SAML start and continue routes, behind the Fetch-Metadata layer (none yet).
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}

/// SAML ACS routes, outside the Fetch-Metadata layer (module docs; none yet).
pub(super) fn callback_routes() -> Router<AppState> {
    Router::new()
}
