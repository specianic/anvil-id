//! `LogoutRepo` on Postgres: RP sessions and the back-channel logout delivery queue, plus
//! [`enqueue_deliveries`], called by every revoking intent inside its own transaction.
//!
//! The queue is installation-wide, like the email outbox: concurrent nodes claim disjoint rows
//! with `FOR UPDATE SKIP LOCKED`, and the claim moves each row's `next_attempt_at` to the lease
//! end before the row lock is released.

use anvil_core::model::{
    DeliveryResult, LOGOUT_DELIVERY_TTL, LogoutDelivery, LogoutDeliveryId, RpSession, SessionId,
    TenantId,
};
use anvil_core::ports::{LogoutRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{map_err, to_u32};

#[derive(Debug, Clone)]
pub(crate) struct PgLogout {
    pub(crate) pool: PgPool,
}

struct DeliveryRow {
    id: Uuid,
    tenant_id: Uuid,
    client_id: String,
    uri: String,
    sub: String,
    sid: String,
    issuer: Option<String>,
    attempts: i32,
    next_attempt_at: OffsetDateTime,
    give_up_at: OffsetDateTime,
    created_at: OffsetDateTime,
    delivered_at: Option<OffsetDateTime>,
    last_error: Option<String>,
}

impl DeliveryRow {
    fn into_model(self) -> Result<LogoutDelivery, StorageError> {
        Ok(LogoutDelivery {
            id: LogoutDeliveryId(self.id),
            tenant_id: TenantId(self.tenant_id),
            client_id: self.client_id,
            uri: self.uri,
            sub: self.sub,
            sid: self.sid,
            issuer: self.issuer,
            attempts: to_u32("logout_delivery.attempts", self.attempts)?,
            next_attempt_at: self.next_attempt_at,
            give_up_at: self.give_up_at,
            created_at: self.created_at,
            delivered_at: self.delivered_at,
            last_error: self.last_error,
        })
    }
}

/// Enqueues, on the caller's transaction, one delivery per (session in `sessions` x RP session
/// of it whose client has a `backchannel_logout_uri`): `uri` copied from the client, `sub` = the
/// session's user id, `sid` = the session id, `issuer` copied from the RP session (the issuer of
/// the RP's ID tokens), due `now`, given up at `now + 24h`.
///
/// `sessions` must be exactly the sessions the calling intent revoked (the ids its revoking
/// `UPDATE … RETURNING id` produced) and must still exist: call this before anything deletes
/// them. Nothing is inserted for an empty slice.
pub(crate) async fn enqueue_deliveries(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    sessions: &[Uuid],
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    if sessions.is_empty() {
        return Ok(());
    }
    let targets = sqlx::query!(
        r#"SELECT r.session_id, r.client_id, c.backchannel_logout_uri AS "uri!", s.user_id,
                  r.issuer
             FROM rp_session r
             JOIN client c ON c.tenant_id = r.tenant_id AND c.client_id = r.client_id
             JOIN browser_session s ON s.tenant_id = r.tenant_id AND s.id = r.session_id
            WHERE r.tenant_id = $1 AND r.session_id = ANY($2)
              AND c.backchannel_logout_uri IS NOT NULL
            ORDER BY r.session_id, r.client_id"#,
        tenant.0,
        sessions,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(map_err)?;
    if targets.is_empty() {
        return Ok(());
    }
    // Time-ordered ids generated here, in (session, client) order.
    let mut ids = Vec::with_capacity(targets.len());
    let mut clients = Vec::with_capacity(targets.len());
    let mut uris = Vec::with_capacity(targets.len());
    let mut subs = Vec::with_capacity(targets.len());
    let mut sids = Vec::with_capacity(targets.len());
    let mut issuers: Vec<Option<String>> = Vec::with_capacity(targets.len());
    for t in targets {
        ids.push(LogoutDeliveryId::new_v7().0);
        clients.push(t.client_id);
        uris.push(t.uri);
        subs.push(t.user_id.to_string());
        sids.push(t.session_id.to_string());
        issuers.push(t.issuer);
    }
    sqlx::query!(
        "INSERT INTO logout_delivery
             (id, tenant_id, client_id, uri, sub, sid, issuer, attempts, next_attempt_at,
              give_up_at, created_at)
         SELECT d.id, $1, d.client_id, d.uri, d.sub, d.sid, d.issuer, 0, $7, $8, $7
           FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $9::text[])
                AS d(id, client_id, uri, sub, sid, issuer)",
        tenant.0,
        &ids,
        &clients,
        &uris,
        &subs,
        &sids,
        now,
        now + LOGOUT_DELIVERY_TTL,
        &issuers as &[Option<String>],
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

/// Records the RP session of (`session`, `client_id`) with ID tokens from `issuer` on the
/// caller's transaction. An existing row keeps its `created_at` and takes the latest issuer;
/// only an existing session of `tenant` is recorded (same semantics as SQLite).
pub(crate) async fn record_rp_session(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    session: SessionId,
    client_id: &str,
    issuer: &str,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    sqlx::query!(
        "INSERT INTO rp_session (tenant_id, session_id, client_id, created_at, issuer)
         SELECT tenant_id, id, $3, $4, $5 FROM browser_session WHERE tenant_id = $1 AND id = $2
         ON CONFLICT (tenant_id, session_id, client_id) DO UPDATE SET issuer = EXCLUDED.issuer",
        tenant.0,
        session.0,
        client_id,
        now,
        issuer,
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl LogoutRepo for PgLogout {
    async fn rp_sessions(
        &self,
        tenant: TenantId,
        session_id: SessionId,
    ) -> Result<Vec<RpSession>, StorageError> {
        let rows = sqlx::query!(
            "SELECT tenant_id, session_id, client_id, issuer, created_at
               FROM rp_session
              WHERE tenant_id = $1 AND session_id = $2
              ORDER BY client_id COLLATE \"C\"",
            tenant.0,
            session_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| RpSession {
                tenant_id: TenantId(r.tenant_id),
                session_id: SessionId(r.session_id),
                client_id: r.client_id,
                issuer: r.issuer,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn claim_due_deliveries(
        &self,
        owner_lease_until: OffsetDateTime,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<LogoutDelivery>, StorageError> {
        // FOR UPDATE SKIP LOCKED: concurrent claimers lock disjoint due rows, and the lease moves
        // each claimed row out of the due window before its lock is released.
        let mut rows = sqlx::query_as!(
            DeliveryRow,
            "UPDATE logout_delivery
                SET next_attempt_at = $1
              WHERE id IN (SELECT id FROM logout_delivery
                            WHERE delivered_at IS NULL AND next_attempt_at <= $2
                              AND give_up_at > $2
                            ORDER BY next_attempt_at, id
                            LIMIT $3
                              FOR UPDATE SKIP LOCKED)
          RETURNING id, tenant_id, client_id, uri, sub, sid, issuer, attempts, next_attempt_at,
                    give_up_at, created_at, delivered_at, last_error",
            owner_lease_until,
            now,
            i64::from(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        // RETURNING has no defined order; hand the batch out oldest first.
        rows.sort_by_key(|r| (r.created_at, r.id));
        rows.into_iter().map(DeliveryRow::into_model).collect()
    }

    async fn complete_delivery(
        &self,
        id: LogoutDeliveryId,
        result: &DeliveryResult,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = match result {
            DeliveryResult::Delivered => sqlx::query!(
                "UPDATE logout_delivery SET delivered_at = $2 WHERE id = $1",
                id.0,
                now,
            )
            .execute(&self.pool)
            .await
            .map_err(map_err)?,
            DeliveryResult::Retry {
                next_attempt_at,
                error,
            } => sqlx::query!(
                "UPDATE logout_delivery
                    SET attempts = attempts + 1, next_attempt_at = $2, last_error = $3
                  WHERE id = $1",
                id.0,
                next_attempt_at,
                error,
            )
            .execute(&self.pool)
            .await
            .map_err(map_err)?,
            DeliveryResult::GiveUp { error } => sqlx::query!(
                "UPDATE logout_delivery
                    SET attempts = attempts + 1, give_up_at = $2, last_error = $3
                  WHERE id = $1",
                id.0,
                now,
                error,
            )
            .execute(&self.pool)
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
            "SELECT id, tenant_id, client_id, uri, sub, sid, issuer, attempts, next_attempt_at,
                    give_up_at, created_at, delivered_at, last_error
               FROM logout_delivery
              WHERE tenant_id = $1 AND client_id = $2
              ORDER BY created_at, id",
            tenant.0,
            client_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(DeliveryRow::into_model)
        .collect()
    }
}
