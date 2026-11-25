//! Upstream (social / generic OIDC / OAuth2) sign-in: start and callback (AUTH-07). Owner: plan
//! 04-21.
//!
//! Registered (and merged) ahead of time so the owning plan edits only this file. No route exists
//! until 04-21 adds it: requests answer 404, never a placeholder success.
//!
//! Two routers:
//! - [`routes`] (the start POST) is merged inside the Fetch-Metadata CSRF layer like every UI route.
//! - [`callback_routes`] is merged in [`super::routes`] *after* `.layer(fetch_metadata_layer())`:
//!   Apple returns with a cross-site `form_post`, which the Fetch-Metadata check would reject.
//!   The callback's protection is the single-use `state`, the browser-binding cookie and the ID
//!   token `nonce` (tested in 04-21).

use axum::Router;

use crate::state::AppState;

/// Upstream start routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
}

/// Upstream callback routes, outside the Fetch-Metadata layer (see the module docs).
pub(super) fn callback_routes() -> Router<AppState> {
    Router::new()
}
