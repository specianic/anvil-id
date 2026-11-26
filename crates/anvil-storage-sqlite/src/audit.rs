//! `AuditRepo` on SQLite (append-only; deleted only by retention).

use std::net::IpAddr;

use anvil_core::model::{
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditEvent, AuditEventId, AuditOutcome,
    AuditQuery, NewAuditEvent, Page, RequestContext, TenantId,
};
use anvil_core::ports::{AuditRepo, StorageError};
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::convert::{
    from_json, into_page, map_err, ms_to_odt, odt_to_ms, opt_odt_to_ms, parse_enum, to_json,
};
use crate::webhooks::enqueue_for_event;

#[derive(Debug, Clone)]
pub(crate) struct SqliteAudit {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct AuditRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    at: i64,
    actor_kind: String,
    actor_id: Option<String>,
    action: String,
    target: Option<String>,
    outcome: String,
    ip: Option<String>,
    user_agent: Option<String>,
    trace_id: Option<String>,
    details: String,
}

impl TryFrom<AuditRow> for AuditEvent {
    type Error = StorageError;

    fn try_from(r: AuditRow) -> Result<Self, StorageError> {
        let ip =
            r.ip.as_deref()
                .map(|s| {
                    s.parse::<IpAddr>()
                        .map_err(|_| StorageError::Corrupt(format!("audit_event.ip {s:?}")))
                })
                .transpose()?;
        Ok(AuditEvent {
            id: AuditEventId(r.id),
            tenant_id: TenantId(r.tenant_id),
            at: ms_to_odt(r.at)?,
            actor: AuditActor {
                kind: parse_enum(&r.actor_kind, ActorKind::parse, "audit actor kind")?,
                id: r.actor_id,
            },
            action: parse_enum(&r.action, AuditAction::parse, "audit action")?,
            target: r.target,
            outcome: parse_enum(&r.outcome, AuditOutcome::parse, "audit outcome")?,
            // Stored values were truncated on the way in; no re-truncation on read.
            ctx: RequestContext {
                ip,
                user_agent: r.user_agent,
                trace_id: r.trace_id,
            },
            details: AuditDetails::from_stored(from_json(&r.details, "audit_event.details")?),
        })
    }
}

#[async_trait::async_trait]
impl AuditRepo for SqliteAudit {
    async fn append(&self, tenant: TenantId, event: &NewAuditEvent) -> Result<(), StorageError> {
        let at = odt_to_ms(event.at);
        let actor_kind = event.actor.kind.as_str();
        let action = event.action.as_str();
        let outcome = event.outcome.as_str();
        let ip = event.ctx.ip.map(|ip| ip.to_string());
        let details = to_json(event.details.as_map(), "audit_event.details")?;
        // The event and its webhook deliveries are one transaction: a rejected append (e.g. a
        // duplicate id) enqueues nothing, and no delivery exists without its audit row.
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        sqlx::query!(
            "INSERT INTO audit_event
                 (id, tenant_id, at, actor_kind, actor_id, action, target, outcome, ip,
                  user_agent, trace_id, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            event.id.0,
            tenant.0,
            at,
            actor_kind,
            event.actor.id,
            action,
            event.target,
            outcome,
            ip,
            event.ctx.user_agent,
            event.ctx.trace_id,
            details,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if let Some(webhook) = &event.webhook {
            enqueue_for_event(&mut tx, tenant, webhook, event.at).await?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }

    async fn query(
        &self,
        tenant: TenantId,
        query: &AuditQuery,
    ) -> Result<Page<AuditEvent>, StorageError> {
        let from = opt_odt_to_ms(query.from);
        let to = opt_odt_to_ms(query.to);
        let action = query.action.map(|a| a.as_str());
        let outcome = query.outcome.map(|o| o.as_str());
        let before = query.before.map(|b| b.0);
        let fetch = i64::from(query.limit) + 1;
        // A fixed set of optional predicates keeps the statement compile-time checked; keyset
        // pagination on id descending (UUIDv7 ids sort by time).
        let rows = sqlx::query_as!(
            AuditRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      at AS "at!", actor_kind AS "actor_kind!", actor_id AS "actor_id?",
                      action AS "action!", target AS "target?", outcome AS "outcome!",
                      ip AS "ip?", user_agent AS "user_agent?", trace_id AS "trace_id?",
                      details AS "details!"
                 FROM audit_event
                WHERE tenant_id = ?1
                  AND (?2 IS NULL OR at >= ?2)
                  AND (?3 IS NULL OR at < ?3)
                  AND (?4 IS NULL OR actor_id = ?4)
                  AND (?5 IS NULL OR action = ?5)
                  AND (?6 IS NULL OR outcome = ?6)
                  AND (?7 IS NULL OR target = ?7)
                  AND (?8 IS NULL OR id < ?8)
                ORDER BY id DESC
                LIMIT ?9"#,
            tenant.0,
            from,
            to,
            query.actor_id,
            action,
            outcome,
            query.target,
            before,
            fetch,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(AuditEvent::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, query.limit, |e| e.id.0))
    }

    /// Also applies the audit retention to the webhook delivery log: delivered and failed
    /// deliveries completed before `cutoff` are deleted (pending ones never are). The returned
    /// count is the number of audit events deleted.
    async fn purge_before(&self, cutoff: OffsetDateTime) -> Result<u64, StorageError> {
        let cutoff = odt_to_ms(cutoff);
        let done = sqlx::query!("DELETE FROM audit_event WHERE at < ?1", cutoff)
            .execute(&self.writer)
            .await
            .map_err(map_err)?;
        sqlx::query!(
            "DELETE FROM webhook_delivery
              WHERE status IN ('delivered', 'failed') AND completed_at < ?1",
            cutoff,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected())
    }
}
