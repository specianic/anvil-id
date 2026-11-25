//! OAuth 2.0 / OpenID Connect protocol endpoints. Each submodule owns its routes.

mod authorize;
mod discovery;
mod introspect;
mod jwks;
mod logout;
mod revoke;
mod token;
mod userinfo;

use axum::Router;

use crate::state::AppState;

/// All protocol routes (tenant-relative paths).
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(discovery::routes())
        .merge(jwks::routes())
        .merge(authorize::routes())
        .merge(token::routes())
        .merge(userinfo::routes())
        .merge(introspect::routes())
        .merge(revoke::routes())
        .merge(logout::routes())
}
