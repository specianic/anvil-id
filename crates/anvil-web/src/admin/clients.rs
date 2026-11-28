//! `/api/admin/v1/tenants/{slug}/clients`: OAuth client registration.
//!
//! Registration rules (C1 PKCE rule, redirect URI validation, auth method consistency) live in
//! `ClientService`; this module only maps HTTP to it. Changes to the system tenant's clients
//! need `admin:write` (see [`AdminAuth::require_full_admin`]).
//!
//! The list includes dynamically registered (`registration_source = dynamic`, RFC 7591) and
//! metadata-document clients (`cimd`, with `metadata_expires_at`), so administrators can see and
//! delete them. Deleting a CIMD client removes its materialised row only: the next request with
//! that URL client id fetches the document again if the tenant's CIMD policy allows it. To block
//! a document host, use the `allow_listed` CIMD policy without that host (or `disabled`); both
//! take effect at once, also for already materialised rows.

use anvil_core::model::{SYSTEM_TENANT_SLUG, Tenant};
use anvil_core::service::admin_scope::{Access, Resource};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use secrecy::ExposeSecret as _;

use super::auth::{
    AdminAuth, AdminJson, AdminQuery, AdminResult, created, json, no_content, page_request,
};
use super::dto::{
    ClientList, ClientSecretView, ClientView, CreateClient, ListQuery, Problem, UpdateClient,
};
use crate::request_context::AuditContext;
use crate::state::AppState;

/// Checks the scope for `access` and resolves the tenant.
async fn authorize(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Clients, access)?;
    if access == Access::Write && slug == SYSTEM_TENANT_SLUG {
        auth.require_full_admin()?;
    }
    Ok(state.admin_tenants().get(slug).await?)
}

/// List the clients of a tenant: static, dynamically registered and CIMD clients
/// (`registration_source`).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/clients",
    tag = "clients",
    operation_id = "listClients",
    params(("slug" = String, Path, description = "Tenant slug"), ListQuery),
    responses(
        (status = 200, description = "One page of clients", body = ClientList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:read"]),
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_clients(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let page = state
        .admin_clients()
        .list(tenant.id, page_request(q)?)
        .await?;
    Ok(json(StatusCode::OK, &ClientList::from(page)))
}

/// Register a client. Secret-based clients get their `client_secret` in this response only.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/clients",
    tag = "clients",
    operation_id = "createClient",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = CreateClient,
    responses(
        (status = 201, description = "Created; includes client_secret for secret-based clients", body = ClientView, headers(("Location" = String, description = "URL of the new client"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_client(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<CreateClient>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let (input, options) = body.into_parts();
    let created_client = state
        .admin_clients()
        .create(&tenant, input, options, auth.actor(), &ctx)
        .await?;
    let mut view = ClientView::from(created_client.client);
    view.client_secret = created_client
        .client_secret
        .map(|s| s.expose_secret().to_owned());
    let location = format!(
        "/api/admin/v1/tenants/{}/clients/{}",
        tenant.slug, view.client_id
    );
    Ok(created(&location, &view))
}

/// Get a client (never includes the secret).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}",
    tag = "clients",
    operation_id = "getClient",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "OAuth client_id"),
    ),
    responses(
        (status = 200, description = "The client", body = ClientView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:read"]),
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_client(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, client_id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let client = state.admin_clients().get(tenant.id, &client_id).await?;
    Ok(json(StatusCode::OK, &ClientView::from(client)))
}

/// Update a client. The merged registration (including the ID-token algorithm against the
/// tenant's enabled algorithms) is validated again.
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}",
    tag = "clients",
    operation_id = "updateClient",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "OAuth client_id"),
    ),
    request_body = UpdateClient,
    responses(
        (status = 200, description = "The updated client", body = ClientView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_client(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, client_id)): Path<(String, String)>,
    AdminJson(body): AdminJson<UpdateClient>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let (patch, options) = body.into_parts();
    let client = state
        .admin_clients()
        .update(&tenant, &client_id, patch, options, auth.actor(), &ctx)
        .await?;
    Ok(json(StatusCode::OK, &ClientView::from(client)))
}

/// Delete a client and revoke its tokens. A deleted CIMD client (URL client id, percent-encoded
/// in the path) is fetched again on its next use if the tenant's CIMD policy still allows its
/// host; block a host with the `allow_listed` CIMD policy instead. The built-in console client
/// (`anvil-console` of the system tenant) cannot be deleted (409).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}",
    tag = "clients",
    operation_id = "deleteClient",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "OAuth client_id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The built-in console client cannot be deleted", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_client(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, client_id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    state
        .admin_clients()
        .delete(tenant.id, &client_id, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

/// Rotate the client secret. The new secret is returned once; the old one stops working.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}/secret",
    tag = "clients",
    operation_id = "rotateClientSecret",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "OAuth client_id"),
    ),
    responses(
        (status = 200, description = "The new secret", body = ClientSecretView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "The client does not use a secret", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn rotate_client_secret(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, client_id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let secret = state
        .admin_clients()
        .rotate_secret(tenant.id, &client_id, auth.actor(), &ctx)
        .await?;
    Ok(json(
        StatusCode::OK,
        &ClientSecretView {
            client_id,
            client_secret: secret.expose_secret().to_owned(),
        },
    ))
}
