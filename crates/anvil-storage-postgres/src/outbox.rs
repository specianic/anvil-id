//! `OutboxRepo` on Postgres.

use std::collections::BTreeMap;
use std::time::Duration;

use anvil_core::model::{NewEmail, OutboxEmail, OutboxId, TenantId};
use anvil_core::ports::{OutboxRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{from_json, map_err, to_json, to_u32};

#[derive(Debug, Clone)]
pub(crate) struct PgOutbox {
    pub(crate) pool: PgPool,
}

struct EmailRow {
    id: Uuid,
    tenant_id: Uuid,
    recipient: String,
    template: String,
    payload: serde_json::Value,
    attempts: i32,
    next_attempt_at: OffsetDateTime,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    sent_at: Option<OffsetDateTime>,
    last_error: Option<String>,
}

impl EmailRow {
    fn into_model(self) -> Result<OutboxEmail, StorageError> {
        let payload: BTreeMap<String, String> = from_json("email_outbox.payload", self.payload)?;
        Ok(OutboxEmail {
            id: OutboxId(self.id),
            tenant_id: TenantId(self.tenant_id),
            to: self.recipient,
            template: self.template,
            payload,
            attempts: to_u32("email_outbox.attempts", self.attempts)?,
            next_attempt_at: self.next_attempt_at,
            created_at: self.created_at,
            expires_at: self.expires_at,
            sent_at: self.sent_at,
            last_error: self.last_error,
        })
    }
}

/// Enqueues an email on any executor (so other intent methods can enqueue inside their
/// transaction).
pub(crate) async fn enqueue_email<'e, E>(
    exec: E,
    tenant: TenantId,
    email: &NewEmail,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let payload = to_json("email_outbox.payload", &email.payload)?;
    sqlx::query!(
        "INSERT INTO email_outbox
             (id, tenant_id, recipient, template, payload, attempts, next_attempt_at, created_at,
              expires_at)
         VALUES ($1, $2, $3, $4, $5, 0, $6, $6, $7)",
        email.id.0,
        tenant.0,
        email.to,
        email.template,
        payload,
        email.created_at,
        email.expires_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl OutboxRepo for PgOutbox {
    async fn enqueue(&self, tenant: TenantId, email: &NewEmail) -> Result<(), StorageError> {
        enqueue_email(&self.pool, tenant, email).await
    }

    async fn claim_due(
        &self,
        now: OffsetDateTime,
        limit: u32,
        lease: Duration,
    ) -> Result<Vec<OutboxEmail>, StorageError> {
        let lease_until = now + lease;
        // FOR UPDATE SKIP LOCKED: concurrent workers lock disjoint due rows, and the lease moves
        // each claimed row out of the due window before the lock is released.
        let mut rows = sqlx::query_as!(
            EmailRow,
            "UPDATE email_outbox
                SET next_attempt_at = $2, attempts = attempts + 1
              WHERE id IN (SELECT id FROM email_outbox
                            WHERE sent_at IS NULL AND next_attempt_at <= $1 AND expires_at > $1
                            ORDER BY next_attempt_at, id
                            LIMIT $3
                              FOR UPDATE SKIP LOCKED)
          RETURNING id, tenant_id, recipient, template, payload, attempts, next_attempt_at,
                    created_at, expires_at, sent_at, last_error",
            now,
            lease_until,
            i64::from(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        // RETURNING has no defined order; hand the batch out oldest first.
        rows.sort_by_key(|r| (r.created_at, r.id));
        rows.into_iter().map(EmailRow::into_model).collect()
    }

    async fn mark_sent(&self, id: OutboxId, now: OffsetDateTime) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE email_outbox SET sent_at = $2 WHERE id = $1",
            id.0,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn mark_failed(
        &self,
        id: OutboxId,
        error: &str,
        next_attempt_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE email_outbox SET last_error = $2, next_attempt_at = $3 WHERE id = $1",
            id.0,
            error,
            next_attempt_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
