//! `RegistrationRepo` on Postgres: RFC 7591 initial access tokens (by hash only) and the
//! per-source client count behind the DCR `max_clients` cap.

use anvil_core::model::{
    ClientSource, InitialAccessToken, InitialAccessTokenId, NewInitialAccessToken, SecretHash,
    TenantId,
};
use anvil_core::ports::{RegistrationRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{hash, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgRegistration {
    pub(crate) pool: PgPool,
}

struct IatRow {
    id: Uuid,
    tenant_id: Uuid,
    description: String,
    token_hash: Vec<u8>,
    expires_at: Option<OffsetDateTime>,
    uses_remaining: Option<i64>,
    created_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

impl IatRow {
    fn into_model(self) -> Result<InitialAccessToken, StorageError> {
        Ok(InitialAccessToken {
            id: InitialAccessTokenId(self.id),
            tenant_id: TenantId(self.tenant_id),
            description: self.description,
            token_hash: hash("initial_access_token.token_hash", &self.token_hash)?,
            expires_at: self.expires_at,
            uses_remaining: self
                .uses_remaining
                .map(|n| {
                    u32::try_from(n).map_err(|_| {
                        StorageError::Corrupt(format!(
                            "initial_access_token.uses_remaining: out of range {n}"
                        ))
                    })
                })
                .transpose()?,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
        })
    }
}

#[async_trait::async_trait]
impl RegistrationRepo for PgRegistration {
    async fn create_iat(
        &self,
        tenant: TenantId,
        t: &NewInitialAccessToken,
    ) -> Result<InitialAccessToken, StorageError> {
        sqlx::query!(
            "INSERT INTO initial_access_token
                 (id, tenant_id, description, token_hash, expires_at, uses_remaining, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            t.id.0,
            tenant.0,
            t.description,
            t.token_hash.as_bytes().as_slice(),
            t.expires_at,
            t.uses_remaining.map(i64::from),
            t.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(InitialAccessToken {
            id: t.id,
            tenant_id: tenant,
            description: t.description.clone(),
            token_hash: t.token_hash,
            expires_at: t.expires_at,
            uses_remaining: t.uses_remaining,
            created_at: t.created_at,
            revoked_at: None,
        })
    }

    async fn list_iats(&self, tenant: TenantId) -> Result<Vec<InitialAccessToken>, StorageError> {
        sqlx::query_as!(
            IatRow,
            "SELECT id, tenant_id, description, token_hash, expires_at, uses_remaining,
                    created_at, revoked_at
               FROM initial_access_token
              WHERE tenant_id = $1
              ORDER BY id",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(IatRow::into_model)
        .collect()
    }

    async fn revoke_iat(
        &self,
        tenant: TenantId,
        id: InitialAccessTokenId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE initial_access_token SET revoked_at = $3
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

    async fn consume_iat(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<InitialAccessToken>, StorageError> {
        // One conditional UPDATE: concurrent consumers serialise on the row lock and, under READ
        // COMMITTED, re-check the WHERE against the committed row, so a single-use token has
        // exactly one winner. `NULL - 1` stays NULL (unlimited).
        sqlx::query_as!(
            IatRow,
            "UPDATE initial_access_token
                SET uses_remaining = uses_remaining - 1
              WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL
                AND (expires_at IS NULL OR expires_at > $3)
                AND (uses_remaining IS NULL OR uses_remaining > 0)
          RETURNING id, tenant_id, description, token_hash, expires_at, uses_remaining,
                    created_at, revoked_at",
            tenant.0,
            token_hash.as_bytes().as_slice(),
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(IatRow::into_model)
        .transpose()
    }

    async fn count_clients_by_source(
        &self,
        tenant: TenantId,
        source: ClientSource,
    ) -> Result<u64, StorageError> {
        let count = sqlx::query_scalar!(
            "SELECT count(*) AS \"count!\" FROM client
              WHERE tenant_id = $1 AND registration_source = $2",
            tenant.0,
            source.as_str(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        u64::try_from(count)
            .map_err(|_| StorageError::Corrupt(format!("client count: negative {count}")))
    }
}
