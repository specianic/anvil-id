//! User import API of a tenant (ADM-08).
//!
//! `POST /api/admin/v1/tenants/{slug}/users/import[?dry_run=true][&update=true][&source=LABEL]`
//! with an NDJSON body (`Content-Type: application/x-ndjson`, one user record per line, the format
//! of docs/IMPORT-EXPORT.md) runs one batch through [`UserImportService`], the same service as
//! `anvilid users import`, and returns its report as JSON.
//!
//! - Scope `admin:users:write` (or `admin:write`).
//! - At most [`IMPORT_BATCH_MAX`] records per request (non-blank lines); more is a 413 problem and
//!   nothing is imported. The body may be up to [`super::branding::IMPORT_BODY_LIMIT`] (1 MiB, a
//!   branch of the single body-limit middleware for this exact path only). Larger files go
//!   through the CLI, which batches.
//! - A line that is not valid UTF-8 or not a valid record is reported as `rejected` /
//!   `invalid_record` with its line number. The report never echoes a line, a hash or a parse
//!   error (which could quote input).
//! - The service audits each call as `users_imported` (counts, `dry_run`, `source`).

use anvil_core::error::CoreError;
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::user_import::{
    IMPORT_BATCH_MAX, ImportReport, ImportRequest, Outcome, RawRecord, UserImportService,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::auth::{AdminAuth, AdminError, AdminQuery, AdminResult, json};
use super::dto::Problem;
use crate::adapters::attribute_schema::JsonSchemaCheck;
use crate::request_context::AuditContext;
use crate::state::AppState;

/// The media type of the import body.
pub(crate) const NDJSON: &str = "application/x-ndjson";

impl AppState {
    /// The user import service (same wiring as the CLI).
    fn admin_user_import(&self) -> UserImportService {
        UserImportService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            check: Arc::new(JsonSchemaCheck::new()),
        }
    }
}

/// The routes of this resource.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(import_users))
}

/// Query of `POST …/users/import`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ImportQuery {
    /// Validate and report without writing users (default false). The audit event is still
    /// recorded, with `dry_run: true`.
    #[serde(default)]
    pub dry_run: Option<bool>,
    /// Overwrite existing users (matched by email) whose data differs, instead of reporting
    /// `conflict` (default false).
    #[serde(default)]
    pub update: Option<bool>,
    /// Label of the source system for the audit event (1-64 characters).
    #[serde(default)]
    pub source: Option<String>,
}

/// Counts per outcome; `weak` counts accepted records whose hash is below the recommended
/// parameters.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportCountsView {
    pub created: u64,
    pub unchanged: u64,
    pub conflict: u64,
    pub updated: u64,
    pub rejected: u64,
    pub weak: u64,
}

/// The outcome of one record (by line number of the body).
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportRecordView {
    /// 1-based line number in the request body.
    pub line: usize,
    /// `created`, `unchanged`, `conflict`, `updated` or `rejected`.
    pub outcome: String,
    /// Why the record was rejected: `invalid_email`, `invalid_record`, `unknown_scheme`,
    /// `weak_parameters`, `over_cap`, `refused_variant`, `unknown_profile` or `id_conflict`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The created, updated or matching user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<uuid::Uuid>,
    /// The imported hash is accepted but below the recommended parameters (it is replaced by an
    /// Argon2id hash at the user's first sign-in).
    pub weak: bool,
}

/// The report of one import request. Carries no password hash material.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportReportView {
    pub dry_run: bool,
    pub counts: ImportCountsView,
    pub records: Vec<ImportRecordView>,
}

fn outcome_str(o: Outcome) -> &'static str {
    match o {
        Outcome::Created => "created",
        Outcome::Unchanged => "unchanged",
        Outcome::Conflict => "conflict",
        Outcome::Updated => "updated",
        Outcome::Rejected => "rejected",
    }
}

impl From<ImportReport> for ImportReportView {
    fn from(r: ImportReport) -> Self {
        Self {
            dry_run: r.dry_run,
            counts: ImportCountsView {
                created: r.counts.created,
                unchanged: r.counts.unchanged,
                conflict: r.counts.conflict,
                updated: r.counts.updated,
                rejected: r.counts.rejected,
                weak: r.counts.weak,
            },
            records: r
                .records
                .into_iter()
                .map(|o| ImportRecordView {
                    line: o.line,
                    outcome: outcome_str(o.outcome).to_owned(),
                    reason: o.reason.map(|r| r.as_str().to_owned()),
                    user_id: o.user_id,
                    weak: o.weak,
                })
                .collect(),
        }
    }
}

/// Splits an NDJSON body into records, skipping blank lines; line numbers are those of the body.
/// A line that is not valid UTF-8 becomes an empty record, which the service rejects as
/// `invalid_record` (its bytes are never decoded lossily, so they cannot turn into a valid
/// record).
fn split_records(body: &[u8]) -> Vec<RawRecord> {
    body.split(|b| *b == b'\n')
        .enumerate()
        .filter_map(|(i, raw)| {
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            if raw.iter().all(u8::is_ascii_whitespace) {
                return None;
            }
            let text = std::str::from_utf8(raw)
                .map(str::to_owned)
                .unwrap_or_default();
            Some(RawRecord { line: i + 1, text })
        })
        .collect()
}

/// Whether the request declares the NDJSON media type (parameters such as `charset` allowed).
fn is_ndjson(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case(NDJSON))
}

/// Import users with their existing password hashes (one batch of NDJSON records).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/users/import",
    tag = "users",
    operation_id = "importUsers",
    params(("slug" = String, Path, description = "Tenant slug"), ImportQuery),
    request_body(
        content = String,
        content_type = "application/x-ndjson",
        description = "One user record per line (docs/IMPORT-EXPORT.md); at most 1,000 records and 1 MiB"
    ),
    responses(
        (status = 200, description = "The import report (also for a dry run)", body = ImportReportView),
        (status = 400, description = "Missing `Content-Type: application/x-ndjson` or unreadable body", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "More than 1,000 records or more than 1 MiB; nothing was imported", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query (for example the source label)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn import_users(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminQuery(q): AdminQuery<ImportQuery>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> AdminResult<Response> {
    auth.require(Resource::Users, Access::Write)?;
    let tenant = state.admin_tenants().get(&slug).await?;
    let body = match body {
        Ok(b) => b,
        Err(e) if crate::ui::rejection_is_too_large(&e) => {
            return Err(AdminError::PayloadTooLarge(format!(
                "the import body is limited to {} bytes; use `anvilid users import` for larger files",
                super::branding::IMPORT_BODY_LIMIT
            )));
        }
        Err(e) => return Err(CoreError::InvalidRequest(e.body_text()).into()),
    };
    if !is_ndjson(&headers) {
        return Err(CoreError::InvalidRequest(format!(
            "the import body must be sent as Content-Type: {NDJSON}"
        ))
        .into());
    }
    let records = split_records(&body);
    if records.len() > IMPORT_BATCH_MAX {
        return Err(AdminError::PayloadTooLarge(format!(
            "at most {IMPORT_BATCH_MAX} records per request; use `anvilid users import` for larger files"
        )));
    }
    let report = state
        .admin_user_import()
        .import(
            tenant.id,
            ImportRequest {
                records,
                dry_run: q.dry_run.unwrap_or(false),
                update: q.update.unwrap_or(false),
                source: q.source.as_deref(),
                actor: auth.actor(),
                ctx: &ctx,
            },
        )
        .await?;
    Ok(json(StatusCode::OK, &ImportReportView::from(report)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keeps_line_numbers_and_refuses_bad_utf8() {
        let body = b"{\"a\":1}\r\n\n  \n\xff\xfe{\"email\":\"x@example.com\"}\n{\"b\":2}";
        let r = split_records(body);
        assert_eq!(r.len(), 3);
        assert_eq!((r[0].line, r[0].text.as_str()), (1, "{\"a\":1}"));
        assert_eq!((r[1].line, r[1].text.as_str()), (4, ""));
        assert_eq!((r[2].line, r[2].text.as_str()), (5, "{\"b\":2}"));
    }

    #[test]
    fn ndjson_media_type() {
        let mut h = HeaderMap::new();
        assert!(!is_ndjson(&h));
        h.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(!is_ndjson(&h));
        h.insert(
            header::CONTENT_TYPE,
            "Application/X-NDJSON; charset=utf-8".parse().unwrap(),
        );
        assert!(is_ndjson(&h));
    }
}
