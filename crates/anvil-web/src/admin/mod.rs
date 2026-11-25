//! Management API (`/api/admin/v1`): tenants, clients and users, authenticated with AnvilID's own
//! OAuth access tokens (system tenant, admin scopes). Errors are RFC 9457 problem JSON.

mod auth;
mod clients;
pub mod dto;
mod tenants;
mod users;

use anvil_core::error::CoreError;
use axum::Router;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::state::AppState;

/// Path prefix of the management API.
pub const BASE_PATH: &str = "/api/admin/v1";

/// The documented routes, shared by [`routes`] and [`openapi`].
fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(tenants::list_tenants, tenants::create_tenant))
        .routes(routes!(
            tenants::get_tenant,
            tenants::update_tenant,
            tenants::delete_tenant
        ))
        .routes(routes!(clients::list_clients, clients::create_client))
        .routes(routes!(
            clients::get_client,
            clients::update_client,
            clients::delete_client
        ))
        .routes(routes!(clients::rotate_client_secret))
        .routes(routes!(users::list_users, users::create_user))
        .routes(routes!(
            users::get_user,
            users::update_user,
            users::delete_user
        ))
}

/// Management API routes.
pub fn routes() -> Router<AppState> {
    let (router, _) = api_router().split_for_parts();
    router.route(&format!("{BASE_PATH}/{{*rest}}"), any(unknown_route))
}

/// The OpenAPI document of the management API.
pub fn openapi() -> utoipa::openapi::OpenApi {
    api_router().split_for_parts().1
}

/// Unknown paths below the API prefix answer with a problem, not the HTML 404 page.
async fn unknown_route(parts: Parts) -> Response {
    if let Err(e) = auth::installation_level(&parts) {
        return e.into_response();
    }
    auth::AdminError::Core(CoreError::NotFound).into_response()
}
