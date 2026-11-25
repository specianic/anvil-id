//! `SessionRepo` on Postgres.

use anvil_core::model::{
    BrowserSession, NewBrowserSession, Page, PageRequest, RevokeReason, SecretHash, SessionId,
    TenantId, UserId,
};
use anvil_core::ports::{SessionRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{fetch_limit, hash, into_page, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgSessions {
    pub(crate) pool: PgPool,
}

struct SessionRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    token_hash: Vec<u8>,
    auth_time: OffsetDateTime,
    acr: String,
    amr: Vec<String>,
    created_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    idle_expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    ip: Option<String>,
    user_agent: Option<String>,
}

impl SessionRow {
    fn into_model(self) -> Result<BrowserSession, StorageError> {
        Ok(BrowserSession {
            id: SessionId(self.id),
            tenant_id: TenantId(self.tenant_id),
            user_id: UserId(self.user_id),
            token_hash: hash("browser_session.token_hash", &self.token_hash)?,
            auth_time: self.auth_time,
            acr: self.acr,
            amr: self.amr,
            created_at: self.created_at,
            last_seen_at: self.last_seen_at,
            expires_at: self.expires_at,
            idle_expires_at: self.idle_expires_at,
            revoked_at: self.revoked_at,
            ip: self.ip,
            user_agent: self.user_agent,
        })
    }
}

/// Revokes the unrevoked token families of `sessions` (reason `SessionRevoked`) on any executor.
async fn revoke_session_families<'e, E>(
    exec: E,
    tenant: TenantId,
    sessions: &[Uuid],
    now: OffsetDateTime,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        "UPDATE token_family SET revoked_at = $3, revoked_reason = $4
          WHERE tenant_id = $1 AND session_id = ANY($2) AND revoked_at IS NULL",
        tenant.0,
        sessions,
        now,
        RevokeReason::SessionRevoked.as_str(),
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl SessionRepo for PgSessions {
    async fn create(
        &self,
        tenant: TenantId,
        session: &NewBrowserSession,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            "INSERT INTO browser_session
                 (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                  last_seen_at, expires_at, idle_expires_at, ip, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10, $11, $12)",
            session.id.0,
            tenant.0,
            session.user_id.0,
            session.token_hash.as_bytes().as_slice(),
            session.auth_time,
            session.acr,
            &session.amr,
            session.created_at,
            session.expires_at,
            session.idle_expires_at,
            session.ip,
            session.user_agent,
        )
        .execute(&self.pool)
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
        sqlx::query_as!(
            SessionRow,
            "SELECT id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                    last_seen_at, expires_at, idle_expires_at, revoked_at, ip, user_agent
               FROM browser_session
              WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL
                AND expires_at > $3 AND idle_expires_at > $3",
            tenant.0,
            token_hash.as_bytes().as_slice(),
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(SessionRow::into_model)
        .transpose()
    }

    async fn touch(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
        idle_expires_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE browser_session SET last_seen_at = $3, idle_expires_at = $4
              WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL
                AND expires_at > $3 AND idle_expires_at > $3",
            tenant.0,
            id.0,
            now,
            idle_expires_at,
        )
        .execute(&self.pool)
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
        let done = sqlx::query!(
            "UPDATE browser_session SET revoked_at = $3
              WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
            tenant.0,
            id.0,
            now,
        )
        .execute(&self.pool)
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
            "SELECT id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                    last_seen_at, expires_at, idle_expires_at, revoked_at, ip, user_agent
               FROM browser_session
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(SessionRow::into_model)
        .transpose()
    }

    async fn list_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<BrowserSession>, StorageError> {
        sqlx::query_as!(
            SessionRow,
            "SELECT id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                    last_seen_at, expires_at, idle_expires_at, revoked_at, ip, user_agent
               FROM browser_session
              WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL
                AND expires_at > $3 AND idle_expires_at > $3
              ORDER BY created_at DESC, id DESC",
            tenant.0,
            user.0,
            now,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(SessionRow::into_model)
        .collect()
    }

    async fn list(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
        page: PageRequest,
    ) -> Result<Page<BrowserSession>, StorageError> {
        let limit = page.clamped_limit();
        let items = sqlx::query_as!(
            SessionRow,
            "SELECT id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                    last_seen_at, expires_at, idle_expires_at, revoked_at, ip, user_agent
               FROM browser_session
              WHERE tenant_id = $1 AND revoked_at IS NULL
                AND expires_at > $2 AND idle_expires_at > $2
                AND ($3::uuid IS NULL OR id > $3)
              ORDER BY id
              LIMIT $4",
            tenant.0,
            now,
            page.after,
            fetch_limit(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(SessionRow::into_model)
        .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |s| s.id.0))
    }

    async fn revoke_with_families(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let done = sqlx::query!(
            "UPDATE browser_session SET revoked_at = $3
              WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
            tenant.0,
            id.0,
            now,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        revoke_session_families(&mut *tx, tenant, &[id.0], now).await?;
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
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let revoked = sqlx::query_scalar!(
            "UPDATE browser_session SET revoked_at = $4
              WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL
                AND ($3::uuid IS NULL OR id <> $3)
          RETURNING id",
            tenant.0,
            user.0,
            except.map(|s| s.0),
            now,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        if !revoked.is_empty() {
            revoke_session_families(&mut *tx, tenant, &revoked, now).await?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(revoked.len() as u64)
    }
}
