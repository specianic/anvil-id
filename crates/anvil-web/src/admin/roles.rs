//! Roles, permissions and role assignments of a tenant (ORG-05):
//!
//! - `GET|POST …/tenants/{slug}/roles`: list (name order) and create;
//! - `GET|PATCH|DELETE …/roles/{name}`: view, update (rename, description, permissions), delete
//!   (its assignments go with it);
//! - `GET …/roles/{name}/users`: the users holding a role (cursor pagination);
//! - `GET …/users/{user_id}/roles`: the roles of a user;
//! - `PUT|DELETE …/users/{user_id}/roles/{name}`: assign (idempotent) and unassign.
//!
//! Scopes: role definitions use `admin:settings:{read,write}`, assignments
//! `admin:users:{read,write}` (or `admin:read` / `admin:write`). In the system tenant roles are
//! admin API scopes (decision Q3), so:
//! - changing a role definition needs `admin:write` (like the system tenant's clients);
//! - assigning or unassigning a role is refused (403) when the role carries admin scopes the
//!   caller's token does not hold (no escalation through assignment);
//! - removing the last active holder of `admin:write` is refused with 409 on every path.
//!
//! A role or user of another tenant is a 404. Every change is audited by `RoleService` in the
//! role's tenant.

use anvil_core::error::CoreError;
use anvil_core::model::{Role, RoleUpdate, SYSTEM_TENANT_SLUG, Tenant, UserId};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::role::{RoleInput, RoleService};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::auth::{
    AdminAuth, AdminJson, AdminQuery, AdminResult, created, json, no_content, page_request,
};
use super::dto::{ListQuery, Problem, UserList, ts};
use crate::request_context::AuditContext;
use crate::state::AppState;

impl AppState {
    fn admin_roles(&self) -> RoleService {
        RoleService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_roles, create_role))
        .routes(routes!(get_role, update_role, delete_role))
        .routes(routes!(list_role_users))
        .routes(routes!(list_user_roles))
        .routes(routes!(assign_role, unassign_role))
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// A role.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleDto {
    pub id: Uuid,
    /// Unique in the tenant: 1-64 characters of a-z, 0-9, '_', '.' or '-'.
    pub name: String,
    pub description: String,
    /// Sorted, de-duplicated permission strings. In the system tenant, admin scopes here
    /// (`admin:write`, `admin:users:read`, ...) are what the role's holders may obtain.
    pub permissions: Vec<String>,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
}

impl From<Role> for RoleDto {
    fn from(r: Role) -> Self {
        Self {
            id: r.id.0,
            name: r.name,
            description: r.description,
            permissions: r.permissions,
            created_at: ts(r.created_at),
            updated_at: ts(r.updated_at),
        }
    }
}

/// Roles, in name order.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleList {
    pub items: Vec<RoleDto>,
}

impl From<Vec<Role>> for RoleList {
    fn from(v: Vec<Role>) -> Self {
        Self {
            items: v.into_iter().map(Into::into).collect(),
        }
    }
}

/// Body of `POST /tenants/{slug}/roles`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewRoleDto {
    /// 1-64 characters of a-z, 0-9, '_', '.' or '-', starting with a letter or digit.
    pub name: String,
    /// At most 500 characters.
    #[serde(default)]
    pub description: String,
    /// At most 100 permissions of 1-128 characters (A-Z, a-z, 0-9, ':', '.', '_', '/', '-').
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Body of `PATCH /tenants/{slug}/roles/{name}`. Absent fields stay unchanged; `permissions`
/// replaces the whole set.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RolePatchDto {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
}

/// A role assignment.
#[derive(Debug, Serialize, ToSchema)]
pub struct AssignmentDto {
    pub user_id: Uuid,
    pub role: RoleDto,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// Role definitions: the settings scope; writes in the system tenant need `admin:write`.
async fn authorize_definitions(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Settings, access)?;
    if access == Access::Write && slug == SYSTEM_TENANT_SLUG {
        auth.require_full_admin()?;
    }
    Ok(state.admin_tenants().get(slug).await?)
}

/// Assignments: the users scope (the escalation guard runs in `RoleService`).
async fn authorize_assignments(
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
    Uuid::parse_str(raw)
        .map(UserId)
        .map_err(|_| CoreError::NotFound.into())
}

// ---------------------------------------------------------------------------------------------
// Role definitions
// ---------------------------------------------------------------------------------------------

/// List the roles of a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/roles",
    tag = "roles",
    operation_id = "listRoles",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Every role of the tenant, in name order", body = RoleList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_roles(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize_definitions(&state, &auth, &slug, Access::Read).await?;
    let roles = state.admin_roles().list(tenant.id).await?;
    Ok(json(StatusCode::OK, &RoleList::from(roles)))
}

/// Create a role. In the system tenant this needs `admin:write`.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/roles",
    tag = "roles",
    operation_id = "createRole",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = NewRoleDto,
    responses(
        (status = 201, description = "Created", body = RoleDto, headers(("Location" = String, description = "URL of the new role"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or the role carries admin scopes the caller lacks", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A role with this name already exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_role(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<NewRoleDto>,
) -> AdminResult<Response> {
    let tenant = authorize_definitions(&state, &auth, &slug, Access::Write).await?;
    let role = state
        .admin_roles()
        .create(
            &tenant,
            RoleInput {
                name: body.name,
                description: body.description,
                permissions: body.permissions,
            },
            &auth.claims.scope,
            auth.actor(),
            &ctx,
        )
        .await?;
    let location = format!("/api/admin/v1/tenants/{}/roles/{}", tenant.slug, role.name);
    Ok(created(&location, &RoleDto::from(role)))
}

/// Get a role.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/roles/{name}",
    tag = "roles",
    operation_id = "getRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("name" = String, Path, description = "Role name"),
    ),
    responses(
        (status = 200, description = "The role", body = RoleDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or role", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_role(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, name)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize_definitions(&state, &auth, &slug, Access::Read).await?;
    let role = state.admin_roles().get(tenant.id, &name).await?;
    Ok(json(StatusCode::OK, &RoleDto::from(role)))
}

/// Update a role. In the system tenant this needs `admin:write`, and removing `admin:write` from
/// the role must leave another active administrator (409 otherwise).
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/roles/{name}",
    tag = "roles",
    operation_id = "updateRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("name" = String, Path, description = "Role name"),
    ),
    request_body = RolePatchDto,
    responses(
        (status = 200, description = "The updated role", body = RoleDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or the role carries admin scopes the caller lacks", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or role", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Name already in use, or the change would remove the last administrator", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_role(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, name)): Path<(String, String)>,
    AdminJson(body): AdminJson<RolePatchDto>,
) -> AdminResult<Response> {
    let tenant = authorize_definitions(&state, &auth, &slug, Access::Write).await?;
    let role = state
        .admin_roles()
        .update(
            &tenant,
            &name,
            RoleUpdate {
                name: body.name,
                description: body.description,
                permissions: body.permissions,
            },
            &auth.claims.scope,
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(json(StatusCode::OK, &RoleDto::from(role)))
}

/// Delete a role and its assignments. In the system tenant this needs `admin:write`, and
/// deleting an `admin:write` role must leave another active administrator (409 otherwise).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/roles/{name}",
    tag = "roles",
    operation_id = "deleteRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("name" = String, Path, description = "Role name"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or role", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The deletion would remove the last administrator", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_role(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, name)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize_definitions(&state, &auth, &slug, Access::Write).await?;
    state
        .admin_roles()
        .delete(&tenant, &name, &auth.claims.scope, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------------------------

/// List the users holding a role.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/roles/{name}/users",
    tag = "roles",
    operation_id = "listRoleUsers",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("name" = String, Path, description = "Role name"),
        ListQuery,
    ),
    responses(
        (status = 200, description = "One page of users holding the role", body = UserList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or role", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:read"]),
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_role_users(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, name)): Path<(String, String)>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    let tenant = authorize_assignments(&state, &auth, &slug, Access::Read).await?;
    let page = state
        .admin_roles()
        .users_with_role(tenant.id, &name, page_request(q)?)
        .await?;
    Ok(json(StatusCode::OK, &UserList::from(page)))
}

/// List the roles of a user.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}/roles",
    tag = "roles",
    operation_id = "listUserRoles",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 200, description = "The user's roles, in name order", body = RoleList),
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
pub(crate) async fn list_user_roles(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize_assignments(&state, &auth, &slug, Access::Read).await?;
    let roles = state
        .admin_roles()
        .roles_for_user(tenant.id, user_id(&id)?)
        .await?;
    Ok(json(StatusCode::OK, &RoleList::from(roles)))
}

/// Assign a role to a user (idempotent). In the system tenant the caller's token must hold
/// every admin scope the role carries.
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}/roles/{name}",
    tag = "roles",
    operation_id = "assignRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
        ("name" = String, Path, description = "Role name"),
    ),
    responses(
        (status = 200, description = "The user holds the role", body = AssignmentDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or the role carries admin scopes the caller lacks", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, user or role", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn assign_role(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id, name)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize_assignments(&state, &auth, &slug, Access::Write).await?;
    let user = user_id(&id)?;
    let role = state
        .admin_roles()
        .assign(&tenant, &name, user, &auth.claims.scope, auth.actor(), &ctx)
        .await?;
    Ok(json(
        StatusCode::OK,
        &AssignmentDto {
            user_id: user.0,
            role: role.into(),
        },
    ))
}

/// Remove a role from a user. In the system tenant the caller's token must hold every admin
/// scope the role carries, and removing the last active administrator is refused (409).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}/roles/{name}",
    tag = "roles",
    operation_id = "unassignRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
        ("name" = String, Path, description = "Role name"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or the role carries admin scopes the caller lacks", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or role, or the user does not hold it", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The change would remove the last administrator", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn unassign_role(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id, name)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize_assignments(&state, &auth, &slug, Access::Write).await?;
    state
        .admin_roles()
        .unassign(
            &tenant,
            &name,
            user_id(&id)?,
            &auth.claims.scope,
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(no_content())
}
