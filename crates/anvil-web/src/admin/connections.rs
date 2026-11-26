//! Admin API for upstream connections (social / OIDC / OAuth2 providers, AUTH-07, SEC-03):
//!
//! - `GET|POST …/tenants/{slug}/connections`: list (slug order) and create;
//! - `GET|PATCH|DELETE …/connections/{id}`: view, update (slug and kind are fixed), delete (the
//!   identity links go with it);
//! - `PUT …/connections/{id}/secret`: set (`{"secret": "…"}`) or remove (`{"secret": null}`)
//!   the client secret (Apple: the `.p8` private key PEM).
//!
//! The secret is write-only: `ConnectionService` validates and seals it with the KEK before it
//! reaches storage; views only report `secret_configured`. `redirect_uri` is the callback URL
//! admins register at the provider.
//!
//! The list also shows the tenant's organization connections (field `organization`), read-only:
//! changing one here answers 409, it is managed under `…/organizations/{org}/connections`. SAML
//! connections exist only per organization: creating one here answers 422.
//!
//! Scope: `admin:settings:{read,write}` (or `admin:read` / `admin:write`), the scope family that
//! guards the other tenant settings managed apart from the tenant record (SMTP, email
//! templates). Changing the system tenant's connections needs `admin:write`, like its clients
//! (they decide who can sign in to the console). All mutations are audited by the service in the
//! connection's tenant.

use anvil_core::error::CoreError;
use anvil_core::model::{ConnectionId, SYSTEM_TENANT_SLUG, Tenant};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::connection::ConnectionService;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use secrecy::SecretString;

use super::auth::{AdminAuth, AdminJson, AdminResult, created, json, no_content};
use super::dto::{
    ConnectionList, ConnectionView, CreateConnection, Problem, PutConnectionSecret,
    UpdateConnection,
};
use crate::request_context::AuditContext;
use crate::state::AppState;

impl AppState {
    pub(crate) fn admin_connections(&self) -> ConnectionService {
        ConnectionService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
            saml_enabled: self.config().saml_experimental,
            saml_xml: Some(self.saml_xml()),
        }
    }
}

/// Checks the settings scope for `access` and resolves the tenant. Writes to the system tenant
/// need full administration.
async fn authorize(
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

/// A connection id from the path; anything that is not a UUID is an unknown connection.
fn connection_id(raw: &str) -> AdminResult<ConnectionId> {
    uuid::Uuid::parse_str(raw)
        .map(ConnectionId)
        .map_err(|_| CoreError::NotFound.into())
}

fn view(state: &AppState, tenant: &Tenant, c: anvil_core::model::Connection) -> ConnectionView {
    ConnectionView::new(c, &state.admin_issuer_of(tenant))
}

/// List the upstream connections of a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/connections",
    tag = "connections",
    operation_id = "listConnections",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Every connection of the tenant, in slug order", body = ConnectionList),
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
pub(crate) async fn list_connections(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let items = state
        .admin_connections()
        .list(tenant.id)
        .await?
        .into_iter()
        .map(|c| view(&state, &tenant, c))
        .collect();
    Ok(json(StatusCode::OK, &ConnectionList { items }))
}

/// Create an upstream connection. The secret (Apple: the `.p8` key PEM) is sealed and never
/// returned.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/connections",
    tag = "connections",
    operation_id = "createConnection",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = CreateConnection,
    responses(
        (status = 201, description = "Created", body = ConnectionView, headers(("Location" = String, description = "URL of the new connection"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Slug already in use in this tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed (also: a SAML connection, which belongs to an organization)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_connection(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<CreateConnection>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let conn = state
        .admin_connections()
        .create(tenant.id, body.into(), auth.actor(), &ctx)
        .await?;
    let location = format!(
        "/api/admin/v1/tenants/{}/connections/{}",
        tenant.slug, conn.id
    );
    Ok(created(&location, &view(&state, &tenant, conn)))
}

/// Get an upstream connection (never includes the secret).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/connections/{id}",
    tag = "connections",
    operation_id = "getConnection",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Connection id"),
    ),
    responses(
        (status = 200, description = "The connection", body = ConnectionView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or connection", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_connection(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let conn = state
        .admin_connections()
        .get(tenant.id, connection_id(&id)?)
        .await?;
    Ok(json(StatusCode::OK, &view(&state, &tenant, conn)))
}

/// Update an upstream connection. Absent fields stay unchanged; the slug is immutable and a new
/// `config` must keep the kind. Trusting Microsoft-asserted email needs
/// `accept_email_trust_risk`.
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/connections/{id}",
    tag = "connections",
    operation_id = "updateConnection",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Connection id"),
    ),
    request_body = UpdateConnection,
    responses(
        (status = 200, description = "The updated connection", body = ConnectionView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or connection", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The connection belongs to an organization", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_connection(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
    AdminJson(body): AdminJson<UpdateConnection>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let conn = state
        .admin_connections()
        .update(
            tenant.id,
            connection_id(&id)?,
            body.into(),
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(json(StatusCode::OK, &view(&state, &tenant, conn)))
}

/// Delete an upstream connection and every identity link made through it.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/connections/{id}",
    tag = "connections",
    operation_id = "deleteConnection",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Connection id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or connection", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The connection belongs to an organization", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_connection(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    state
        .admin_connections()
        .delete(tenant.id, connection_id(&id)?, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

/// Set or remove the client secret of a connection (Apple: the `.p8` private key PEM, which
/// must be an ES256 PKCS#8 key). Write-only: the response reports `secret_configured`.
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/connections/{id}/secret",
    tag = "connections",
    operation_id = "putConnectionSecret",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Connection id"),
    ),
    request_body = PutConnectionSecret,
    responses(
        (status = 200, description = "The connection", body = ConnectionView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or connection", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The connection belongs to an organization", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_connection_secret(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
    AdminJson(body): AdminJson<PutConnectionSecret>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let id = connection_id(&id)?;
    let secret = body.secret.ok_or_else(|| CoreError::Validation {
        field: "secret",
        message: "is required (null removes the secret)".to_owned(),
    })?;
    let conn = state
        .admin_connections()
        .set_secret(
            tenant.id,
            id,
            secret.map(SecretString::from),
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(json(StatusCode::OK, &view(&state, &tenant, conn)))
}
