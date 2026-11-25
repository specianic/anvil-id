//! `AuditRepo` on Postgres: append-only events, newest-first keyset queries, retention.

use std::net::IpAddr;

use anvil_core::model::{
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditEvent, AuditEventId, AuditOutcome,
    AuditQuery, NewAuditEvent, Page, RequestContext, TenantId,
};
use anvil_core::ports::{AuditRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::PURGE_BATCH;
use crate::convert::{enum_from, fetch_limit, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgAudit {
    pub(crate) pool: PgPool,
}

struct AuditRow {
    id: Uuid,
    tenant_id: Uuid,
    at: OffsetDateTime,
    actor_kind: String,
    actor_id: Option<String>,
    action: String,
    target: Option<String>,
    outcome: String,
    ip: Option<String>,
    user_agent: Option<String>,
    trace_id: Option<String>,
    details: serde_json::Value,
}

impl AuditRow {
    fn into_model(self) -> Result<AuditEvent, StorageError> {
        let ip = self
            .ip
            .as_deref()
            .map(|ip| {
                ip.parse::<IpAddr>()
                    .map_err(|_| StorageError::Corrupt(format!("audit_event.ip: {ip:?}")))
            })
            .transpose()?;
        let serde_json::Value::Object(details) = self.details else {
            return Err(StorageError::Corrupt(
                "audit_event.details: not an object".to_owned(),
            ));
        };
        Ok(AuditEvent {
            id: AuditEventId(self.id),
            tenant_id: TenantId(self.tenant_id),
            at: self.at,
            actor: AuditActor {
                kind: enum_from("audit_event.actor_kind", &self.actor_kind, ActorKind::parse)?,
                id: self.actor_id,
            },
            action: enum_from("audit_event.action", &self.action, AuditAction::parse)?,
            target: self.target,
            outcome: enum_from("audit_event.outcome", &self.outcome, AuditOutcome::parse)?,
            // Stored as written: the user agent was truncated by `RequestContext::new`.
            ctx: RequestContext {
                ip,
                user_agent: self.user_agent,
                trace_id: self.trace_id,
            },
            details: AuditDetails::from_stored(details),
        })
    }
}

#[async_trait::async_trait]
impl AuditRepo for PgAudit {
    async fn append(&self, tenant: TenantId, e: &NewAuditEvent) -> Result<(), StorageError> {
        let details = serde_json::Value::Object(e.details.as_map().clone());
        sqlx::query!(
            "INSERT INTO audit_event
                 (id, tenant_id, at, actor_kind, actor_id, action, target, outcome, ip,
                  user_agent, trace_id, details)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            e.id.0,
            tenant.0,
            e.at,
            e.actor.kind.as_str(),
            e.actor.id,
            e.action.as_str(),
            e.target,
            e.outcome.as_str(),
            e.ctx.ip.map(|ip| ip.to_string()),
            e.ctx.user_agent,
            e.ctx.trace_id,
            details,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn query(
        &self,
        tenant: TenantId,
        q: &AuditQuery,
    ) -> Result<Page<AuditEvent>, StorageError> {
        // A fixed set of optional predicates keeps the query compile-time checked.
        let rows = sqlx::query_as!(
            AuditRow,
            "SELECT id, tenant_id, at, actor_kind, actor_id, action, target, outcome, ip,
                    user_agent, trace_id, details
               FROM audit_event
              WHERE tenant_id = $1
                AND ($2::timestamptz IS NULL OR at >= $2)
                AND ($3::timestamptz IS NULL OR at < $3)
                AND ($4::text IS NULL OR actor_id = $4)
                AND ($5::text IS NULL OR action = $5)
                AND ($6::text IS NULL OR outcome = $6)
                AND ($7::text IS NULL OR target = $7)
                AND ($8::uuid IS NULL OR id < $8)
              ORDER BY id DESC
              LIMIT $9",
            tenant.0,
            q.from,
            q.to,
            q.actor_id,
            q.action.map(|a| a.as_str()),
            q.outcome.map(|o| o.as_str()),
            q.target,
            q.before.map(|b| b.0),
            fetch_limit(q.limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let mut items = rows
            .into_iter()
            .map(AuditRow::into_model)
            .collect::<Result<Vec<_>, _>>()?;
        let limit = q.limit as usize;
        let more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = if more {
            items.last().map(|e| e.id.0)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    async fn purge_before(&self, cutoff: OffsetDateTime) -> Result<u64, StorageError> {
        // Batched like `purge_expired`, so a large backlog never holds long locks.
        let mut deleted = 0u64;
        loop {
            let done = sqlx::query!(
                "DELETE FROM audit_event WHERE ctid IN
                   (SELECT ctid FROM audit_event WHERE at < $1 LIMIT $2)",
                cutoff,
                PURGE_BATCH,
            )
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
            deleted += done.rows_affected();
            if done.rows_affected() < PURGE_BATCH as u64 {
                return Ok(deleted);
            }
        }
    }
}
