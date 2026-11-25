//! `OutboxRepo` on SQLite.

use std::time::Duration;

use anvil_core::model::{NewEmail, OutboxEmail, OutboxId, TenantId};
use anvil_core::ports::{OutboxRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{
    from_json, i64_to_u32, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, to_json,
};

#[derive(Debug, Clone)]
pub(crate) struct SqliteOutbox {
    pub(crate) writer: SqlitePool,
}

/// Enqueues an email on `conn` (`attempts = 0`, `next_attempt_at = created_at`), so callers can
/// enqueue inside the transaction of the change that triggers the email.
pub(crate) async fn insert_email(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    email: &NewEmail,
) -> Result<(), StorageError> {
    let payload = to_json(&email.payload, "email_outbox.payload")?;
    let created_at = odt_to_ms(email.created_at);
    let expires_at = odt_to_ms(email.expires_at);
    sqlx::query!(
        "INSERT INTO email_outbox
             (id, tenant_id, recipient, template, payload, attempts, next_attempt_at, created_at,
              expires_at, sent_at, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6, ?7, NULL, NULL)",
        email.id.0,
        tenant.0,
        email.to,
        email.template,
        payload,
        created_at,
        expires_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

/// Lease end `now + lease`; a lease that overflows the timestamp range is a caller bug.
fn lease_end(now: OffsetDateTime, lease: Duration) -> Result<OffsetDateTime, StorageError> {
    time::Duration::try_from(lease)
        .ok()
        .and_then(|d| now.checked_add(d))
        .ok_or_else(|| StorageError::Backend(format!("outbox lease {lease:?} out of range").into()))
}

#[async_trait::async_trait]
impl OutboxRepo for SqliteOutbox {
    async fn enqueue(&self, tenant: TenantId, email: &NewEmail) -> Result<(), StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_email(&mut conn, tenant, email).await
    }

    async fn claim_due(
        &self,
        now: OffsetDateTime,
        limit: u32,
        lease: Duration,
    ) -> Result<Vec<OutboxEmail>, StorageError> {
        let now_ms = odt_to_ms(now);
        let leased_until = odt_to_ms(lease_end(now, lease)?);
        let limit = i64::from(limit);
        // One statement on the single writer: selection and lease cannot interleave with another
        // claimer.
        let rows = sqlx::query!(
            r#"UPDATE email_outbox
                  SET next_attempt_at = ?1, attempts = attempts + 1
                WHERE id IN (SELECT id FROM email_outbox
                              WHERE sent_at IS NULL AND next_attempt_at <= ?2 AND expires_at > ?2
                              ORDER BY created_at, id
                              LIMIT ?3)
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      recipient AS "recipient!", template AS "template!", payload AS "payload!",
                      attempts AS "attempts!", next_attempt_at AS "next_attempt_at!",
                      created_at AS "created_at!", expires_at AS "expires_at!",
                      sent_at AS "sent_at?", last_error AS "last_error?""#,
            leased_until,
            now_ms,
            limit,
        )
        .fetch_all(&self.writer)
        .await
        .map_err(map_err)?;

        let mut emails = rows
            .into_iter()
            .map(|r| {
                Ok(OutboxEmail {
                    id: OutboxId(r.id),
                    tenant_id: TenantId(r.tenant_id),
                    to: r.recipient,
                    template: r.template,
                    payload: from_json(&r.payload, "email_outbox.payload")?,
                    attempts: i64_to_u32(r.attempts, "email_outbox.attempts")?,
                    next_attempt_at: ms_to_odt(r.next_attempt_at)?,
                    created_at: ms_to_odt(r.created_at)?,
                    expires_at: ms_to_odt(r.expires_at)?,
                    sent_at: opt_ms_to_odt(r.sent_at)?,
                    last_error: r.last_error,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        // RETURNING order is unspecified in SQLite: restore oldest-first.
        emails.sort_by_key(|e| (e.created_at, e.id));
        Ok(emails)
    }

    async fn mark_sent(&self, id: OutboxId, now: OffsetDateTime) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE email_outbox SET sent_at = ?2 WHERE id = ?1",
            id.0,
            now_ms,
        )
        .execute(&self.writer)
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
        let next = odt_to_ms(next_attempt_at);
        let done = sqlx::query!(
            "UPDATE email_outbox SET last_error = ?2, next_attempt_at = ?3 WHERE id = ?1",
            id.0,
            error,
            next,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
