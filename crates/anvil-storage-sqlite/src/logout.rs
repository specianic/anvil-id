//! `LogoutRepo` on SQLite: RP sessions and the back-channel logout delivery queue, plus the
//! enqueue helper that every revoking intent calls inside its own transaction.

use anvil_core::model::{
    DeliveryResult, LOGOUT_DELIVERY_TTL, LogoutDelivery, LogoutDeliveryId, RpSession, SessionId,
    TenantId, UserId,
};
use anvil_core::ports::{LogoutRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{i64_to_u32, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt};

#[derive(Debug, Clone)]
pub(crate) struct SqliteLogout {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct DeliveryRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    client_id: String,
    uri: String,
    sub: String,
    sid: String,
    attempts: i64,
    next_attempt_at: i64,
    give_up_at: i64,
    created_at: i64,
    delivered_at: Option<i64>,
    last_error: Option<String>,
}

impl TryFrom<DeliveryRow> for LogoutDelivery {
    type Error = StorageError;

    fn try_from(r: DeliveryRow) -> Result<Self, StorageError> {
        Ok(LogoutDelivery {
            id: LogoutDeliveryId(r.id),
            tenant_id: TenantId(r.tenant_id),
            client_id: r.client_id,
            uri: r.uri,
            sub: r.sub,
            sid: r.sid,
            attempts: i64_to_u32(r.attempts, "logout_delivery.attempts")?,
            next_attempt_at: ms_to_odt(r.next_attempt_at)?,
            give_up_at: ms_to_odt(r.give_up_at)?,
            created_at: ms_to_odt(r.created_at)?,
            delivered_at: opt_ms_to_odt(r.delivered_at)?,
            last_error: r.last_error,
        })
    }
}

/// Enqueues, on `conn` (the caller's transaction), one back-channel logout delivery per RP
/// session of each of `sessions` whose client has a `backchannel_logout_uri`: the uri is copied
/// from the client, `sub` = `user`, `sid` = the session id, due now, given up after
/// [`LOGOUT_DELIVERY_TTL`]. Callers pass only the sessions their own statement revoked, so a call
/// that revoked nothing enqueues nothing.
pub(crate) async fn enqueue_deliveries(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    user: UserId,
    sessions: &[uuid::Uuid],
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let now_ms = odt_to_ms(now);
    let give_up_ms = odt_to_ms(now + LOGOUT_DELIVERY_TTL);
    let sub = user.to_string();
    for &session in sessions {
        let targets = sqlx::query!(
            r#"SELECT r.client_id AS "client_id!", c.backchannel_logout_uri AS "uri!"
                 FROM rp_session r
                 JOIN client c ON c.tenant_id = r.tenant_id AND c.client_id = r.client_id
                WHERE r.tenant_id = ?1 AND r.session_id = ?2
                  AND c.backchannel_logout_uri IS NOT NULL
                ORDER BY r.client_id"#,
            tenant.0,
            session,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(map_err)?;
        let sid = SessionId(session).to_string();
        for t in targets {
            let id = LogoutDeliveryId::new_v7();
            sqlx::query!(
                "INSERT INTO logout_delivery
                     (id, tenant_id, client_id, uri, sub, sid, attempts, next_attempt_at,
                      give_up_at, created_at, delivered_at, last_error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?7, NULL, NULL)",
                id.0,
                tenant.0,
                t.client_id,
                t.uri,
                sub,
                sid,
                now_ms,
                give_up_ms,
            )
            .execute(&mut *conn)
            .await
            .map_err(map_err)?;
        }
    }
    Ok(())
}

/// Records on `conn` (the `create_code` transaction) that `session` signed in to `client_id`.
/// Idempotent; only a session of `tenant` that exists is recorded.
pub(crate) async fn record_rp_session(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    session: SessionId,
    client_id: &str,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let now_ms = odt_to_ms(now);
    sqlx::query!(
        "INSERT OR IGNORE INTO rp_session (tenant_id, session_id, client_id, created_at)
         SELECT tenant_id, id, ?3, ?4 FROM browser_session WHERE tenant_id = ?1 AND id = ?2",
        tenant.0,
        session.0,
        client_id,
        now_ms,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl LogoutRepo for SqliteLogout {
    async fn rp_sessions(
        &self,
        tenant: TenantId,
        session_id: SessionId,
    ) -> Result<Vec<RpSession>, StorageError> {
        let rows = sqlx::query!(
            r#"SELECT tenant_id AS "tenant_id!: uuid::Uuid", session_id AS "session_id!: uuid::Uuid",
                      client_id AS "client_id!", created_at AS "created_at!"
                 FROM rp_session
                WHERE tenant_id = ?1 AND session_id = ?2
                ORDER BY client_id"#,
            tenant.0,
            session_id.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(RpSession {
                    tenant_id: TenantId(r.tenant_id),
                    session_id: SessionId(r.session_id),
                    client_id: r.client_id,
                    created_at: ms_to_odt(r.created_at)?,
                })
            })
            .collect()
    }

    async fn claim_due_deliveries(
        &self,
        owner_lease_until: OffsetDateTime,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<LogoutDelivery>, StorageError> {
        let now_ms = odt_to_ms(now);
        let lease_ms = odt_to_ms(owner_lease_until);
        let limit = i64::from(limit);
        // One statement on the single writer connection: selecting the due ids and leasing them
        // cannot interleave with another claimer.
        let rows = sqlx::query_as!(
            DeliveryRow,
            r#"UPDATE logout_delivery SET next_attempt_at = ?1
                WHERE id IN (SELECT id FROM logout_delivery
                              WHERE delivered_at IS NULL AND next_attempt_at <= ?2
                                AND give_up_at > ?2
                              ORDER BY next_attempt_at, created_at, id
                              LIMIT ?3)
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", uri AS "uri!", sub AS "sub!", sid AS "sid!",
                      attempts AS "attempts!", next_attempt_at AS "next_attempt_at!",
                      give_up_at AS "give_up_at!", created_at AS "created_at!",
                      delivered_at AS "delivered_at?", last_error AS "last_error?""#,
            lease_ms,
            now_ms,
            limit,
        )
        .fetch_all(&self.writer)
        .await
        .map_err(map_err)?;
        let mut claimed = rows
            .into_iter()
            .map(LogoutDelivery::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        // RETURNING order is unspecified: oldest first.
        claimed.sort_by_key(|d| (d.created_at, d.id.0));
        Ok(claimed)
    }

    async fn complete_delivery(
        &self,
        id: LogoutDeliveryId,
        result: &DeliveryResult,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let done = match result {
            DeliveryResult::Delivered => sqlx::query!(
                "UPDATE logout_delivery SET delivered_at = ?2 WHERE id = ?1",
                id.0,
                now_ms,
            )
            .execute(&self.writer)
            .await
            .map_err(map_err)?,
            DeliveryResult::Retry {
                next_attempt_at,
                error,
            } => {
                let next = odt_to_ms(*next_attempt_at);
                sqlx::query!(
                    "UPDATE logout_delivery
                        SET attempts = attempts + 1, next_attempt_at = ?2, last_error = ?3
                      WHERE id = ?1",
                    id.0,
                    next,
                    error,
                )
                .execute(&self.writer)
                .await
                .map_err(map_err)?
            }
            DeliveryResult::GiveUp { error } => sqlx::query!(
                "UPDATE logout_delivery
                    SET attempts = attempts + 1, give_up_at = ?2, last_error = ?3
                  WHERE id = ?1",
                id.0,
                now_ms,
                error,
            )
            .execute(&self.writer)
            .await
            .map_err(map_err)?,
        };
        Ok(done.rows_affected() > 0)
    }

    async fn deliveries_for_client(
        &self,
        tenant: TenantId,
        client_id: &str,
    ) -> Result<Vec<LogoutDelivery>, StorageError> {
        sqlx::query_as!(
            DeliveryRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", uri AS "uri!", sub AS "sub!", sid AS "sid!",
                      attempts AS "attempts!", next_attempt_at AS "next_attempt_at!",
                      give_up_at AS "give_up_at!", created_at AS "created_at!",
                      delivered_at AS "delivered_at?", last_error AS "last_error?"
                 FROM logout_delivery
                WHERE tenant_id = ?1 AND client_id = ?2
                ORDER BY created_at, id"#,
            tenant.0,
            client_id,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(LogoutDelivery::try_from)
        .collect()
    }
}
