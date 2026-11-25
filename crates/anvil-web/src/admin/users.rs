//! `/api/admin/v1/tenants/{slug}/users`: user management (password or invitation, claims,
//! block, delete).

use anvil_core::error::CoreError;
use anvil_core::model::{Tenant, UserId};
use anvil_core::service::admin_scope::{Access, Resource};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use super::auth::{
    AdminAuth, AdminJson, AdminQuery, AdminResult, created, json, no_content, page_request,
};
use super::dto::{CreateUser, ListQuery, Problem, UpdateUser, UserList, UserView};
use crate::state::AppState;

/// Checks the scope for `access` and resolves the tenant.
async fn authorize(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Users, access)?;
    Ok(state.admin_tenants().get(slug).await?)
}

/// A user id from the path; anything that is not a UUID cannot name a user (404).
fn user_id(raw: &str) -> AdminResult<UserId> {
    uuid::Uuid::parse_str(raw)
        .map(UserId)
        .map_err(|_| CoreError::NotFound.into())
}

/// List the users of a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/users",
    tag = "users",
    operation_id = "listUsers",
    params(("slug" = String, Path, description = "Tenant slug"), ListQuery),
    responses(
        (status = 200, description = "One page of users", body = UserList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:read"]),
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_users(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let page = state
        .admin_users()
        .list(tenant.id, page_request(q)?)
        .await?;
    Ok(json(StatusCode::OK, &UserList::from(page)))
}

/// Create a user with a password, or invite them by email.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/users",
    tag = "users",
    operation_id = "createUser",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = CreateUser,
    responses(
        (status = 201, description = "Created", body = UserView, headers(("Location" = String, description = "URL of the new user"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Email or username already in use", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_user(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<CreateUser>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let issuer = state.admin_issuer_of(&tenant);
    let user = state
        .admin_users()
        .create(&tenant, &issuer, body.into())
        .await?;
    let location = format!("/api/admin/v1/tenants/{}/users/{}", tenant.slug, user.id);
    Ok(created(&location, &UserView::from(user)))
}

/// Get a user.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}",
    tag = "users",
    operation_id = "getUser",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 200, description = "The user", body = UserView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or user", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:read"]),
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_user(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let user = state.admin_users().get(tenant.id, user_id(&id)?).await?;
    Ok(json(StatusCode::OK, &UserView::from(user)))
}

/// Update a user (email, verification flag, username, claims, status).
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}",
    tag = "users",
    operation_id = "updateUser",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    request_body = UpdateUser,
    responses(
        (status = 200, description = "The updated user", body = UserView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or user", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Email or username already in use", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_user(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
    AdminJson(body): AdminJson<UpdateUser>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let user = state
        .admin_users()
        .update(tenant.id, user_id(&id)?, body.into())
        .await?;
    Ok(json(StatusCode::OK, &UserView::from(user)))
}

/// Delete a user with their credentials and sessions, and revoke their tokens.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}",
    tag = "users",
    operation_id = "deleteUser",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or user", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_user(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    state.admin_users().delete(tenant.id, user_id(&id)?).await?;
    Ok(no_content())
}
