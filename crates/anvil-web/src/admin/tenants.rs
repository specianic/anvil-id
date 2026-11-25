//! `/api/admin/v1/tenants`: installation-wide tenant management.

use anvil_core::service::admin_scope::{Access, Resource};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use super::auth::{
    AdminAuth, AdminJson, AdminQuery, AdminResult, created, json, no_content, page_request,
};
use super::dto::{CreateTenant, ListQuery, Problem, TenantList, TenantView, UpdateTenant};
use crate::request_context::AuditContext;
use crate::state::AppState;

/// List tenants.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants",
    tag = "tenants",
    operation_id = "listTenants",
    params(ListQuery),
    responses(
        (status = 200, description = "One page of tenants", body = TenantList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:read"]),
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_tenants(
    auth: AdminAuth,
    State(state): State<AppState>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Read)?;
    let page = state.admin_tenants().list(page_request(q)?).await?;
    Ok(json(StatusCode::OK, &TenantList::from(page)))
}

/// Create a tenant (with its first signing key).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants",
    tag = "tenants",
    operation_id = "createTenant",
    request_body = CreateTenant,
    responses(
        (status = 201, description = "Created", body = TenantView, headers(("Location" = String, description = "URL of the new tenant"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Slug or host already in use", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_tenant(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    AdminJson(body): AdminJson<CreateTenant>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Write)?;
    let tenant = state
        .admin_tenants()
        .create(body.into(), auth.actor(), &ctx)
        .await?;
    let location = format!("/api/admin/v1/tenants/{}", tenant.slug);
    Ok(created(&location, &TenantView::from(tenant)))
}

/// Get a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}",
    tag = "tenants",
    operation_id = "getTenant",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "The tenant", body = TenantView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:read"]),
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_tenant(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Read)?;
    let tenant = state.admin_tenants().get(&slug).await?;
    Ok(json(StatusCode::OK, &TenantView::from(tenant)))
}

/// Update a tenant (the slug is immutable).
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}",
    tag = "tenants",
    operation_id = "updateTenant",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = UpdateTenant,
    responses(
        (status = 200, description = "The updated tenant", body = TenantView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Host already in use", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_tenant(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<UpdateTenant>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Write)?;
    // CAPTCHA changes get a wire field in 03-23.
    let tenant = state
        .admin_tenants()
        .update(&slug, body.into(), None, auth.actor(), &ctx)
        .await?;
    Ok(json(StatusCode::OK, &TenantView::from(tenant)))
}

/// Delete a tenant with all its data. `system` and `default` cannot be deleted (403).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}",
    tag = "tenants",
    operation_id = "deleteTenant",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or a protected tenant", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_tenant(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Write)?;
    state
        .admin_tenants()
        .delete(&slug, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}
