//! User export API of a tenant: single user, bulk and GDPR bundle (ADM-09).
//!
//! - `GET /api/admin/v1/tenants/{slug}/users/{user_id}/export`: one user as JSON (the
//!   `UserExportRecord` of docs/IMPORT-EXPORT.md).
//! - `GET …/users/{user_id}/export?profile=gdpr`: the user's GDPR data-subject bundle (other
//!   people appear only as role labels; `operator_statement` is always `null`).
//! - `GET …/users/export`: every user of the tenant as NDJSON (`application/x-ndjson`, one
//!   record per line, user id order), streamed page by page over [`BulkExport`], never loaded at
//!   once. If reading fails mid-stream, a last line `{"error":"export_failed"}` is written and
//!   the stream ends (the response status is already sent).
//!
//! Scope: `admin:users:export` or the `admin:write` umbrella only
//! ([`export_scope_satisfied`]); `admin:read`, `admin:users:read` and `admin:users:write` get 403.
//!
//! No HTTP path can export password hashes: the service is used through
//! [`UserExportService::export_user`], [`UserExportService::gdpr_bundle`] and
//! [`UserExportService::bulk_without_hashes`], none of which take export options, and the
//! queries refuse unknown parameters (such as `include_password_hashes`) with a 422. Password
//! hashes are exported only by `anvilid users export --include-password-hashes`.
//!
//! Every request is audited as `user_exported` by the service (mode `single`, `gdpr` or `bulk`,
//! the count, `include_password_hashes: false`). A bulk export that ends early (a read error or
//! the client going away) is recorded with outcome `failure` and the count sent so far.

use anvil_core::error::CoreError;
use anvil_core::model::{AuditActor, RequestContext, Tenant, UserId};
use anvil_core::service::admin_scope::export_scope_satisfied;
use anvil_core::service::user_export::{BulkExport, UserExportRecord, UserExportService};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::auth::{AdminAuth, AdminQuery, AdminResult, json};
use super::dto::Problem;
use super::user_import::NDJSON;
use crate::request_context::AuditContext;
use crate::state::AppState;

impl AppState {
    /// The user export service. It has no options: the HTTP layer can only reach the export
    /// methods without password hashes.
    fn admin_user_export(&self) -> UserExportService {
        UserExportService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// The routes of this resource.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(export_user))
        .routes(routes!(export_users))
}

/// Query of `GET …/users/{user_id}/export`. Unknown parameters are refused (422).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ExportUserQuery {
    /// `gdpr` for the data-subject bundle; absent for the plain user export.
    #[serde(default)]
    pub profile: Option<String>,
}

/// Query of `GET …/users/export`: no parameters; any parameter is refused (422).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ExportUsersQuery {}

/// A user export document: the `UserExportRecord` (single export, each bulk NDJSON line) or the
/// GDPR bundle (`profile=gdpr`); the field lists are in docs/IMPORT-EXPORT.md. Never carries a
/// password hash, TOTP seed, recovery code, token hash or other secret.
#[derive(Debug, ToSchema)]
#[schema(value_type = Object)]
pub struct UserExportDocument(#[allow(dead_code)] serde_json::Value);

/// Demands `admin:users:export` (or `admin:write`) and resolves the tenant.
async fn authorize(state: &AppState, auth: &AdminAuth, slug: &str) -> AdminResult<Tenant> {
    auth.require_system_admin()?;
    if !export_scope_satisfied(&auth.claims.scope) {
        return Err(CoreError::InsufficientScope(
            "this operation requires admin:users:export".to_owned(),
        )
        .into());
    }
    Ok(state.admin_tenants().get(slug).await?)
}

/// A user id from the path; anything that is not a UUID cannot name a user (404).
fn user_id(raw: &str) -> AdminResult<UserId> {
    uuid::Uuid::parse_str(raw)
        .map(UserId)
        .map_err(|_| CoreError::NotFound.into())
}

/// Export one user as JSON, or their GDPR data-subject bundle (`profile=gdpr`).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}/export",
    tag = "users",
    operation_id = "exportUser",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
        ExportUserQuery,
    ),
    responses(
        (status = 200, description = "The user export, or the GDPR bundle with `profile=gdpr`", body = UserExportDocument),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope (requires admin:users:export or admin:write)", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or user", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Unknown profile or query parameter", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:export"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn export_user(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
    AdminQuery(q): AdminQuery<ExportUserQuery>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug).await?;
    let gdpr = match q.profile.as_deref() {
        None => false,
        Some("gdpr") => true,
        Some(_) => {
            return Err(CoreError::Validation {
                field: "profile",
                message: "must be gdpr".to_owned(),
            }
            .into());
        }
    };
    let user = user_id(&id)?;
    let service = state.admin_user_export();
    let actor = auth.actor();
    if gdpr {
        let bundle = service.gdpr_bundle(tenant.id, user, &actor, &ctx).await?;
        Ok(json(StatusCode::OK, &bundle))
    } else {
        let record = service.export_user(tenant.id, user, &actor, &ctx).await?;
        Ok(json(StatusCode::OK, &record))
    }
}

/// The NDJSON lines of one page.
fn ndjson_lines(records: &[UserExportRecord]) -> Result<Bytes, CoreError> {
    let mut out = Vec::new();
    for r in records {
        serde_json::to_writer(&mut out, r)
            .map_err(|e| CoreError::Internal(format!("serialising an export record: {e}")))?;
        out.push(b'\n');
    }
    Ok(Bytes::from(out))
}

/// The trailing line of a bulk export that failed mid-stream.
const FAILED_LINE: &[u8] = b"{\"error\":\"export_failed\"}\n";

/// A bulk export being streamed. Audits exactly once: [`BulkStream::finish`] at the end of the
/// stream, or, when the response body is dropped before (the client went away), [`Drop`] records
/// the export as failed with the count sent so far.
struct BulkStream {
    export: Option<BulkExport>,
    actor: AuditActor,
    ctx: RequestContext,
}

impl BulkStream {
    async fn finish(&mut self) {
        if let Some(export) = self.export.take()
            && let Err(e) = export.finish(&self.actor, &self.ctx).await
        {
            tracing::error!(error = %e, "auditing a bulk user export failed");
        }
    }

    /// The next chunk of the body, or `None` when the stream is over (audited by then).
    async fn next_chunk(&mut self) -> Option<Bytes> {
        let export = self.export.as_mut()?;
        let failed = match export.next_page().await {
            Ok(Some(page)) => match ndjson_lines(&page) {
                Ok(bytes) => return Some(bytes),
                Err(e) => {
                    export.mark_failed();
                    e
                }
            },
            Ok(None) => {
                self.finish().await;
                return None;
            }
            Err(e) => e,
        };
        tracing::error!(error = %failed, "bulk user export ended early");
        self.finish().await;
        Some(Bytes::from_static(FAILED_LINE))
    }
}

impl Drop for BulkStream {
    fn drop(&mut self) {
        let Some(mut export) = self.export.take() else {
            return;
        };
        export.mark_failed();
        let (actor, ctx) = (self.actor.clone(), self.ctx.clone());
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = export.finish(&actor, &ctx).await {
                    tracing::error!(error = %e, "auditing an interrupted bulk user export failed");
                }
            });
        }
    }
}

/// Export every user of the tenant as NDJSON (streamed; never includes password hashes).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/users/export",
    tag = "users",
    operation_id = "exportUsers",
    params(("slug" = String, Path, description = "Tenant slug"), ExportUsersQuery),
    responses(
        (status = 200, description = "One `UserExportRecord` JSON object per line, in user id order. If the export fails mid-stream, the last line is `{\"error\":\"export_failed\"}`.", body = String, content_type = "application/x-ndjson"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope (requires admin:users:export or admin:write)", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Unknown query parameter", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:export"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn export_users(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminQuery(_q): AdminQuery<ExportUsersQuery>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug).await?;
    let stream = BulkStream {
        export: Some(state.admin_user_export().bulk_without_hashes(tenant.id)),
        actor: auth.actor(),
        ctx,
    };
    let body = futures_util::stream::unfold(stream, |mut s| async move {
        s.next_chunk()
            .await
            .map(|chunk| (Ok::<_, std::convert::Infallible>(chunk), s))
    });
    let mut resp = (StatusCode::OK, Body::from_stream(body)).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(NDJSON));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}
