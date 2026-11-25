//! `SessionRepo` on SQLite.

use anvil_core::model::{
    BrowserSession, NewBrowserSession, Page, PageRequest, RevokeReason, SecretHash, SessionId,
    TenantId, UserId,
};
use anvil_core::ports::{SessionRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{
    blob_to_hash, from_json, into_page, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, to_json,
};

#[derive(Debug, Clone)]
pub(crate) struct SqliteSessions {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct SessionRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    user_id: uuid::Uuid,
    token_hash: Vec<u8>,
    auth_time: i64,
    acr: String,
    amr: String,
    created_at: i64,
    last_seen_at: i64,
    expires_at: i64,
    idle_expires_at: i64,
    revoked_at: Option<i64>,
    ip: Option<String>,
    user_agent: Option<String>,
}

impl TryFrom<SessionRow> for BrowserSession {
    type Error = StorageError;

    fn try_from(r: SessionRow) -> Result<Self, StorageError> {
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
            ip: r.ip,
            user_agent: r.user_agent,
        })
    }
}

/// Revokes the unrevoked token families bound to session `id` on `conn` (reason
/// `SessionRevoked`; already revoked families keep their first reason).
async fn revoke_session_families(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    id: uuid::Uuid,
    now_ms: i64,
) -> Result<(), StorageError> {
    let reason = RevokeReason::SessionRevoked.as_str();
    sqlx::query!(
        "UPDATE token_family SET revoked_at = ?3, revoked_reason = ?4
          WHERE tenant_id = ?1 AND session_id = ?2 AND revoked_at IS NULL",
        tenant.0,
        id,
        now_ms,
        reason,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl SessionRepo for SqliteSessions {
    async fn create(
        &self,
        tenant: TenantId,
        session: &NewBrowserSession,
    ) -> Result<(), StorageError> {
        let hash = session.token_hash.as_bytes().as_slice();
        let amr = to_json(&session.amr, "browser_session.amr")?;
        let auth_time = odt_to_ms(session.auth_time);
        let created_at = odt_to_ms(session.created_at);
        let expires_at = odt_to_ms(session.expires_at);
        let idle_expires_at = odt_to_ms(session.idle_expires_at);
        sqlx::query!(
            "INSERT INTO browser_session
                 (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                  last_seen_at, expires_at, idle_expires_at, revoked_at, ip, user_agent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, NULL, ?11, ?12)",
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
            session.ip,
            session.user_agent,
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
        sqlx::query_as!(
            SessionRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      user_id AS "user_id!: uuid::Uuid", token_hash AS "token_hash!",
                      auth_time AS "auth_time!", acr AS "acr!", amr AS "amr!",
                      created_at AS "created_at!", last_seen_at AS "last_seen_at!",
                      expires_at AS "expires_at!", idle_expires_at AS "idle_expires_at!",
                      revoked_at AS "revoked_at?", ip AS "ip?", user_agent AS "user_agent?"
                 FROM browser_session
                WHERE tenant_id = ?1 AND token_hash = ?2 AND revoked_at IS NULL
                  AND expires_at > ?3 AND idle_expires_at > ?3"#,
            tenant.0,
            hash,
            now_ms,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(BrowserSession::try_from)
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

    async fn get(
        &self,
        tenant: TenantId,
        id: SessionId,
    ) -> Result<Option<BrowserSession>, StorageError> {
        sqlx::query_as!(
            SessionRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      user_id AS "user_id!: uuid::Uuid", token_hash AS "token_hash!",
                      auth_time AS "auth_time!", acr AS "acr!", amr AS "amr!",
                      created_at AS "created_at!", last_seen_at AS "last_seen_at!",
                      expires_at AS "expires_at!", idle_expires_at AS "idle_expires_at!",
                      revoked_at AS "revoked_at?", ip AS "ip?", user_agent AS "user_agent?"
                 FROM browser_session
                WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(BrowserSession::try_from)
        .transpose()
    }

    async fn list_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<BrowserSession>, StorageError> {
        let now_ms = odt_to_ms(now);
        // UUIDv7 ids sort by creation time; created_at first keeps the order for any id.
        sqlx::query_as!(
            SessionRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      user_id AS "user_id!: uuid::Uuid", token_hash AS "token_hash!",
                      auth_time AS "auth_time!", acr AS "acr!", amr AS "amr!",
                      created_at AS "created_at!", last_seen_at AS "last_seen_at!",
                      expires_at AS "expires_at!", idle_expires_at AS "idle_expires_at!",
                      revoked_at AS "revoked_at?", ip AS "ip?", user_agent AS "user_agent?"
                 FROM browser_session
                WHERE tenant_id = ?1 AND user_id = ?2 AND revoked_at IS NULL
                  AND expires_at > ?3 AND idle_expires_at > ?3
                ORDER BY created_at DESC, id DESC"#,
            tenant.0,
            user.0,
            now_ms,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(BrowserSession::try_from)
        .collect()
    }

    async fn list(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
        page: PageRequest,
    ) -> Result<Page<BrowserSession>, StorageError> {
        let now_ms = odt_to_ms(now);
        let limit = page.clamped_limit();
        let fetch = i64::from(limit) + 1;
        let rows = sqlx::query_as!(
            SessionRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      user_id AS "user_id!: uuid::Uuid", token_hash AS "token_hash!",
                      auth_time AS "auth_time!", acr AS "acr!", amr AS "amr!",
                      created_at AS "created_at!", last_seen_at AS "last_seen_at!",
                      expires_at AS "expires_at!", idle_expires_at AS "idle_expires_at!",
                      revoked_at AS "revoked_at?", ip AS "ip?", user_agent AS "user_agent?"
                 FROM browser_session
                WHERE tenant_id = ?1 AND revoked_at IS NULL
                  AND expires_at > ?2 AND idle_expires_at > ?2
                  AND (?3 IS NULL OR id > ?3)
                ORDER BY id
                LIMIT ?4"#,
            tenant.0,
            now_ms,
            page.after,
            fetch,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(BrowserSession::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |s| s.id.0))
    }

    async fn revoke_with_families(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let done = sqlx::query!(
            "UPDATE browser_session SET revoked_at = ?3
              WHERE tenant_id = ?1 AND id = ?2 AND revoked_at IS NULL",
            tenant.0,
            id.0,
            now_ms,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            tx.rollback().await.map_err(map_err)?;
            return Ok(false);
        }
        revoke_session_families(&mut tx, tenant, id.0, now_ms).await?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn revoke_all_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
        except: Option<SessionId>,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let now_ms = odt_to_ms(now);
        let except = except.map(|s| s.0);
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let revoked = sqlx::query!(
            r#"UPDATE browser_session SET revoked_at = ?4
                WHERE tenant_id = ?1 AND user_id = ?2 AND revoked_at IS NULL
                  AND (?3 IS NULL OR id <> ?3)
            RETURNING id AS "id!: uuid::Uuid""#,
            tenant.0,
            user.0,
            except,
            now_ms,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        for row in &revoked {
            revoke_session_families(&mut tx, tenant, row.id, now_ms).await?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(revoked.len() as u64)
    }
}
