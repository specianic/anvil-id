//! `SessionRepo` on Postgres.

use anvil_core::model::{
    BrowserSession, NewBrowserSession, Page, PageRequest, SecretHash, SessionId, TenantId, UserId,
};
use anvil_core::ports::{SessionRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::convert::{hash, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgSessions {
    pub(crate) pool: PgPool,
}

// TRANSITIONAL(03-06): browser_session has no ip/user_agent columns yet. Sessions read back
// with `None`; a value is refused explicitly instead of being dropped silently.
fn ensure_no_request_context(s: &NewBrowserSession) -> Result<(), StorageError> {
    if s.ip.is_some() || s.user_agent.is_some() {
        return Err(StorageError::Unsupported("browser session ip/user_agent"));
    }
    Ok(())
}

#[async_trait::async_trait]
impl SessionRepo for PgSessions {
    async fn create(
        &self,
        tenant: TenantId,
        session: &NewBrowserSession,
    ) -> Result<(), StorageError> {
        ensure_no_request_context(session)?;
        sqlx::query!(
            "INSERT INTO browser_session
                 (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                  last_seen_at, expires_at, idle_expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10)",
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
        let row = sqlx::query!(
            "SELECT id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                    last_seen_at, expires_at, idle_expires_at, revoked_at
               FROM browser_session
              WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL
                AND expires_at > $3 AND idle_expires_at > $3",
            tenant.0,
            token_hash.as_bytes().as_slice(),
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok(BrowserSession {
                id: SessionId(r.id),
                tenant_id: TenantId(r.tenant_id),
                user_id: UserId(r.user_id),
                token_hash: hash("browser_session.token_hash", &r.token_hash)?,
                auth_time: r.auth_time,
                acr: r.acr,
                amr: r.amr,
                created_at: r.created_at,
                last_seen_at: r.last_seen_at,
                expires_at: r.expires_at,
                idle_expires_at: r.idle_expires_at,
                revoked_at: r.revoked_at,
                // TRANSITIONAL(03-06): columns arrive with the 0003 migration.
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

    // TRANSITIONAL(03-06): Phase 3 methods, implemented with the 0003 migration.
    async fn get(
        &self,
        _tenant: TenantId,
        _id: SessionId,
    ) -> Result<Option<BrowserSession>, StorageError> {
        crate::pending::unsupported("SessionRepo::get")
    }

    async fn list_for_user(
        &self,
        _tenant: TenantId,
        _user: UserId,
        _now: OffsetDateTime,
    ) -> Result<Vec<BrowserSession>, StorageError> {
        crate::pending::unsupported("SessionRepo::list_for_user")
    }

    async fn list(
        &self,
        _tenant: TenantId,
        _now: OffsetDateTime,
        _page: PageRequest,
    ) -> Result<Page<BrowserSession>, StorageError> {
        crate::pending::unsupported("SessionRepo::list")
    }

    async fn revoke_with_families(
        &self,
        _tenant: TenantId,
        _id: SessionId,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        crate::pending::unsupported("SessionRepo::revoke_with_families")
    }

    async fn revoke_all_for_user(
        &self,
        _tenant: TenantId,
        _user: UserId,
        _except: Option<SessionId>,
        _now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        crate::pending::unsupported("SessionRepo::revoke_all_for_user")
    }
}
