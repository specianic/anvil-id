//! `GET /api/admin/v1/tenants/{slug}/audit-events`: query a tenant's audit log, newest first,
//! with filters and cursor pagination (`cursor` = the last event id of the previous page).
//!
//! Tenant lifecycle events (`tenant_created`/`updated`/`deleted`) are recorded in the system
//! tenant, so they are listed under `/tenants/system/audit-events`.

use anvil_core::error::CoreError;
use anvil_core::model::{AuditAction, AuditEventId, AuditOutcome, AuditQuery};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::audit::AuditService;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::auth::{AdminAuth, AdminQuery, AdminResult, json};
use super::dto::{AuditEventList, AuditQueryParams, Problem};
use crate::state::AppState;

/// Longest accepted actor or target filter.
const MAX_FILTER_LEN: usize = 256;

impl AppState {
    fn admin_audit(&self) -> AuditService {
        AuditService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

fn invalid(field: &'static str, message: &str) -> CoreError {
    CoreError::Validation {
        field,
        message: message.to_owned(),
    }
}

fn time_param(field: &'static str, raw: Option<&str>) -> Result<Option<OffsetDateTime>, CoreError> {
    raw.map(|v| {
        OffsetDateTime::parse(v, &Rfc3339)
            .map_err(|_| invalid(field, "must be an RFC 3339 date-time"))
    })
    .transpose()
}

fn text_param(field: &'static str, raw: Option<String>) -> Result<Option<String>, CoreError> {
    match raw {
        Some(v) if v.is_empty() || v.chars().count() > MAX_FILTER_LEN => {
            Err(invalid(field, "must be 1-256 characters"))
        }
        other => Ok(other),
    }
}

/// Validates the query parameters into a storage query.
fn audit_query(q: AuditQueryParams) -> Result<AuditQuery, CoreError> {
    let from = time_param("from", q.from.as_deref())?;
    let to = time_param("to", q.to.as_deref())?;
    if let (Some(f), Some(t)) = (from, to)
        && f >= t
    {
        return Err(invalid("to", "must be after from"));
    }
    let action = q
        .action
        .as_deref()
        .map(|a| AuditAction::parse(a).ok_or_else(|| invalid("action", "unknown action")))
        .transpose()?;
    let outcome = q
        .outcome
        .as_deref()
        .map(|o| {
            AuditOutcome::parse(o).ok_or_else(|| invalid("outcome", "must be success or failure"))
        })
        .transpose()?;
    let limit = match q.limit {
        None => 0,
        Some(l @ 1..=200) => l,
        Some(_) => return Err(invalid("limit", "must be between 1 and 200")),
    };
    Ok(AuditQuery {
        from,
        to,
        actor_id: text_param("actor", q.actor)?,
        action,
        outcome,
        target: text_param("target", q.target)?,
        before: q.cursor.map(AuditEventId),
        limit,
    })
}

/// Query the audit log of a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/audit-events",
    tag = "audit",
    operation_id = "listAuditEvents",
    params(("slug" = String, Path, description = "Tenant slug"), AuditQueryParams),
    responses(
        (status = 200, description = "One page of events, newest first", body = AuditEventList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:audit:read"]),
        ("oauth2" = ["admin:audit:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_audit_events(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    AdminQuery(q): AdminQuery<AuditQueryParams>,
) -> AdminResult<Response> {
    auth.require(Resource::Audit, Access::Read)?;
    let tenant = state.admin_tenants().get(&slug).await?;
    let page = state
        .admin_audit()
        .query(tenant.id, audit_query(q)?)
        .await?;
    Ok(json(StatusCode::OK, &AuditEventList::from(page)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> AuditQueryParams {
        AuditQueryParams {
            from: None,
            to: None,
            actor: None,
            action: None,
            outcome: None,
            target: None,
            cursor: None,
            limit: None,
        }
    }

    fn field_of(e: CoreError) -> &'static str {
        match e {
            CoreError::Validation { field, .. } => field,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn valid_filters_map_to_the_storage_query() {
        let q = audit_query(AuditQueryParams {
            from: Some("2026-01-01T00:00:00Z".into()),
            to: Some("2026-02-01T00:00:00+01:00".into()),
            actor: Some("adm-1".into()),
            action: Some("client_created".into()),
            outcome: Some("failure".into()),
            target: Some("web".into()),
            cursor: Some(uuid::Uuid::nil()),
            limit: Some(10),
        })
        .unwrap();
        assert!(q.from.is_some() && q.to.is_some());
        assert_eq!(q.action, Some(AuditAction::ClientCreated));
        assert_eq!(q.outcome, Some(AuditOutcome::Failure));
        assert_eq!(q.actor_id.as_deref(), Some("adm-1"));
        assert_eq!(q.before, Some(AuditEventId(uuid::Uuid::nil())));
        assert_eq!(q.limit, 10);
        assert_eq!(audit_query(params()).unwrap().limit, 0);
    }

    #[test]
    fn invalid_filters_name_their_field() {
        let cases: Vec<(AuditQueryParams, &str)> = vec![
            (
                AuditQueryParams {
                    from: Some("yesterday".into()),
                    ..params()
                },
                "from",
            ),
            (
                AuditQueryParams {
                    to: Some("2026-13-01T00:00:00Z".into()),
                    ..params()
                },
                "to",
            ),
            (
                AuditQueryParams {
                    from: Some("2026-02-01T00:00:00Z".into()),
                    to: Some("2026-01-01T00:00:00Z".into()),
                    ..params()
                },
                "to",
            ),
            (
                AuditQueryParams {
                    action: Some("drop_table".into()),
                    ..params()
                },
                "action",
            ),
            (
                AuditQueryParams {
                    outcome: Some("maybe".into()),
                    ..params()
                },
                "outcome",
            ),
            (
                AuditQueryParams {
                    actor: Some(String::new()),
                    ..params()
                },
                "actor",
            ),
            (
                AuditQueryParams {
                    target: Some("x".repeat(257)),
                    ..params()
                },
                "target",
            ),
            (
                AuditQueryParams {
                    limit: Some(0),
                    ..params()
                },
                "limit",
            ),
            (
                AuditQueryParams {
                    limit: Some(201),
                    ..params()
                },
                "limit",
            ),
        ];
        for (q, field) in cases {
            assert_eq!(field_of(audit_query(q).unwrap_err()), field);
        }
    }
}
