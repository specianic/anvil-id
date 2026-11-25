//! `SessionRepo` on SQLite.

use anvil_core::model::{
    BrowserSession, NewBrowserSession, SecretHash, SessionId, TenantId, UserId,
};
use anvil_core::ports::{SessionRepo, StorageError};
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::convert::{
    blob_to_hash, from_json, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, to_json,
};

#[derive(Debug, Clone)]
pub(crate) struct SqliteSessions {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

// TRANSITIONAL(03-05): browser_session has no ip/user_agent columns yet. Sessions read back
// with `None`; a value is refused explicitly instead of being dropped silently.
fn ensure_no_request_context(s: &NewBrowserSession) -> Result<(), StorageError> {
    if s.ip.is_some() || s.user_agent.is_some() {
        return Err(StorageError::Unsupported("browser session ip/user_agent"));
    }
    Ok(())
}

#[async_trait::async_trait]
impl SessionRepo for SqliteSessions {
    async fn create(
        &self,
        tenant: TenantId,
        session: &NewBrowserSession,
    ) -> Result<(), StorageError> {
        ensure_no_request_context(session)?;
        let hash = session.token_hash.as_bytes().as_slice();
        let amr = to_json(&session.amr, "browser_session.amr")?;
        let auth_time = odt_to_ms(session.auth_time);
        let created_at = odt_to_ms(session.created_at);
        let expires_at = odt_to_ms(session.expires_at);
        let idle_expires_at = odt_to_ms(session.idle_expires_at);
        sqlx::query!(
            "INSERT INTO browser_session
                 (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                  last_seen_at, expires_at, idle_expires_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, NULL)",
            session.id.0,
            tenant.0,
            session.user_id.0,
            hash,
            auth_time,
            session.acr,
            amr,
            created_at,
            expires_at,
            idle_expires_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_active(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<BrowserSession>, StorageError> {
        let hash = token_hash.as_bytes().as_slice();
        let now_ms = odt_to_ms(now);
        let row = sqlx::query!(
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      user_id AS "user_id!: uuid::Uuid", token_hash AS "token_hash!",
                      auth_time AS "auth_time!", acr AS "acr!", amr AS "amr!",
                      created_at AS "created_at!", last_seen_at AS "last_seen_at!",
                      expires_at AS "expires_at!", idle_expires_at AS "idle_expires_at!",
                      revoked_at AS "revoked_at?"
                 FROM browser_session
                WHERE tenant_id = ?1 AND token_hash = ?2 AND revoked_at IS NULL
                  AND expires_at > ?3 AND idle_expires_at > ?3"#,
            tenant.0,
            hash,
            now_ms,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok(BrowserSession {
                id: SessionId(r.id),
                tenant_id: TenantId(r.tenant_id),
                user_id: UserId(r.user_id),
                token_hash: blob_to_hash(&r.token_hash, "browser_session.token_hash")?,
                auth_time: ms_to_odt(r.auth_time)?,
                acr: r.acr,
                amr: from_json(&r.amr, "browser_session.amr")?,
                created_at: ms_to_odt(r.created_at)?,
                last_seen_at: ms_to_odt(r.last_seen_at)?,
                expires_at: ms_to_odt(r.expires_at)?,
                idle_expires_at: ms_to_odt(r.idle_expires_at)?,
                revoked_at: opt_ms_to_odt(r.revoked_at)?,
                // TRANSITIONAL(03-05): columns arrive with the 0003 migration.
                ip: None,
                user_agent: None,
            })
        })
        .transpose()
    }

    async fn touch(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
        idle_expires_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let idle = odt_to_ms(idle_expires_at);
        let done = sqlx::query!(
            "UPDATE browser_session SET last_seen_at = ?3, idle_expires_at = ?4
              WHERE tenant_id = ?1 AND id = ?2 AND revoked_at IS NULL
                AND expires_at > ?3 AND idle_expires_at > ?3",
            tenant.0,
            id.0,
            now_ms,
            idle,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn revoke(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE browser_session SET revoked_at = ?3
              WHERE tenant_id = ?1 AND id = ?2 AND revoked_at IS NULL",
            tenant.0,
            id.0,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
