//! `/api/admin/v1/tenants/{slug}/sessions` and `…/users/{user_id}/sessions`: list and revoke
//! browser sessions. Revoking a session also revokes the token families issued under it
//! (`SessionService`), and every revocation is audited with the admin actor.

use anvil_core::error::CoreError;
use anvil_core::model::{SessionId, Tenant, UserId};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::session::SessionService;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use super::auth::{AdminAuth, AdminQuery, AdminResult, json, no_content, page_request};
use super::dto::{ListQuery, Problem, RevokedSessions, SessionList};
use crate::request_context::AuditContext;
use crate::state::AppState;

impl AppState {
    fn admin_sessions(&self) -> SessionService {
        SessionService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// Checks the sessions scope for `access` and resolves the tenant.
async fn authorize(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Sessions, access)?;
    Ok(state.admin_tenants().get(slug).await?)
}

/// A UUID path segment; anything else cannot name a session or user (404).
fn uuid_of(raw: &str) -> AdminResult<uuid::Uuid> {
    uuid::Uuid::parse_str(raw).map_err(|_| CoreError::NotFound.into())
}

/// List the active sessions of a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/sessions",
    tag = "sessions",
    operation_id = "listSessions",
    params(("slug" = String, Path, description = "Tenant slug"), ListQuery),
    responses(
        (status = 200, description = "One page of active sessions", body = SessionList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:sessions:read"]),
        ("oauth2" = ["admin:sessions:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_sessions(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let page = state
        .admin_sessions()
        .admin_list_tenant(tenant.id, page_request(q)?)
        .await?;
    Ok(json(StatusCode::OK, &SessionList::from(page)))
}

/// Revoke one session (and the tokens issued under it).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/sessions/{session_id}",
    tag = "sessions",
    operation_id = "revokeSession",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("session_id" = uuid::Uuid, Path, description = "Session id"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, or no such active session", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:sessions:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn revoke_session(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let id = SessionId(uuid_of(&id)?);
    state
        .admin_sessions()
        .admin_revoke(tenant.id, id, &auth.claims.sub, &ctx)
        .await?;
    Ok(no_content())
}

/// List a user's active sessions, newest first.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}/sessions",
    tag = "sessions",
    operation_id = "listUserSessions",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 200, description = "The user's active sessions (one page)", body = SessionList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or user", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:sessions:read"]),
        ("oauth2" = ["admin:sessions:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_user_sessions(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, user)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let sessions = state
        .admin_sessions()
        .admin_list_user(tenant.id, UserId(uuid_of(&user)?))
        .await?;
    Ok(json(StatusCode::OK, &SessionList::from(sessions)))
}

/// Revoke every session of a user (and the tokens issued under them).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}/sessions",
    tag = "sessions",
    operation_id = "revokeUserSessions",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 200, description = "Number of revoked sessions", body = RevokedSessions),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or user", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:sessions:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn revoke_user_sessions(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, user)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let revoked = state
        .admin_sessions()
        .admin_revoke_all(tenant.id, UserId(uuid_of(&user)?), &auth.claims.sub, &ctx)
        .await?;
    Ok(json(StatusCode::OK, &RevokedSessions { revoked }))
}
