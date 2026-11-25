//! `KeyRepo` on Postgres.

use anvil_core::model::{KeyState, NewSigningKey, SigningKey, SigningKeyId, TenantId};
use anvil_core::ports::{KeyRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{enum_from, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgKeys {
    pub(crate) pool: PgPool,
}

struct KeyRow {
    id: Uuid,
    tenant_id: Uuid,
    kid: String,
    alg: String,
    state: String,
    private_key_enc: Vec<u8>,
    public_jwk: String,
    created_at: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    retired_at: Option<OffsetDateTime>,
    expires_at: Option<OffsetDateTime>,
}

impl KeyRow {
    fn into_model(self) -> Result<SigningKey, StorageError> {
        Ok(SigningKey {
            id: SigningKeyId(self.id),
            tenant_id: TenantId(self.tenant_id),
            kid: self.kid,
            alg: self.alg,
            state: enum_from("signing_key.state", &self.state, KeyState::parse)?,
            private_key_enc: self.private_key_enc,
            public_jwk: self.public_jwk,
            created_at: self.created_at,
            activated_at: self.activated_at,
            retired_at: self.retired_at,
            expires_at: self.expires_at,
        })
    }
}

/// Inserts a key on any executor. The partial unique index `signing_key_one_active` rejects a
/// second active key per (tenant, alg) with `Conflict`.
pub(crate) async fn insert_key<'e, E>(
    exec: E,
    tenant: TenantId,
    k: &NewSigningKey,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        "INSERT INTO signing_key
             (id, tenant_id, kid, alg, state, private_key_enc, public_jwk, created_at,
              activated_at, retired_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        k.id.0,
        tenant.0,
        k.kid,
        k.alg,
        k.state.as_str(),
        k.private_key_enc,
        k.public_jwk,
        k.created_at,
        k.activated_at,
        k.retired_at,
        k.expires_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl KeyRepo for PgKeys {
    async fn insert(&self, tenant: TenantId, key: &NewSigningKey) -> Result<(), StorageError> {
        insert_key(&self.pool, tenant, key).await
    }

    async fn active(
        &self,
        tenant: TenantId,
        alg: &str,
    ) -> Result<Option<SigningKey>, StorageError> {
        sqlx::query_as!(
            KeyRow,
            "SELECT id, tenant_id, kid, alg, state, private_key_enc, public_jwk, created_at,
                    activated_at, retired_at, expires_at
               FROM signing_key
              WHERE tenant_id = $1 AND alg = $2 AND state = 'active'",
            tenant.0,
            alg,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(KeyRow::into_model)
        .transpose()
    }

    async fn published(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<Vec<SigningKey>, StorageError> {
        sqlx::query_as!(
            KeyRow,
            "SELECT id, tenant_id, kid, alg, state, private_key_enc, public_jwk, created_at,
                    activated_at, retired_at, expires_at
               FROM signing_key
              WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > $2)
              ORDER BY id",
            tenant.0,
            now,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(KeyRow::into_model)
        .collect()
    }

    async fn list(&self, tenant: TenantId) -> Result<Vec<SigningKey>, StorageError> {
        sqlx::query_as!(
            KeyRow,
            "SELECT id, tenant_id, kid, alg, state, private_key_enc, public_jwk, created_at,
                    activated_at, retired_at, expires_at
               FROM signing_key
              WHERE tenant_id = $1
              ORDER BY id",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(KeyRow::into_model)
        .collect()
    }

    async fn promote(
        &self,
        tenant: TenantId,
        retire: Option<(SigningKeyId, OffsetDateTime)>,
        activate: SigningKeyId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        // `signing_key_one_active` is a non-deferrable partial unique index, checked per row: the
        // old key is retired first, then the next key activated, in one transaction. Returning
        // early drops `tx`, which rolls back.
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        if let Some((old, expires_at)) = retire {
            let retired = sqlx::query!(
                "UPDATE signing_key SET state = 'retired', retired_at = $3, expires_at = $4
                  WHERE tenant_id = $1 AND id = $2 AND state = 'active'",
                tenant.0,
                old.0,
                now,
                expires_at,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
            if retired.rows_affected() != 1 {
                return Ok(false);
            }
        }
        // A second active key of the same alg is a unique violation: `Conflict`, rolled back.
        let activated = sqlx::query!(
            "UPDATE signing_key SET state = 'active', activated_at = $3
              WHERE tenant_id = $1 AND id = $2 AND state = 'next'",
            tenant.0,
            activate.0,
            now,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if activated.rows_affected() != 1 {
            return Ok(false);
        }
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn delete_expired(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM signing_key
              WHERE tenant_id = $1 AND state = 'retired' AND expires_at <= $2",
            tenant.0,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected())
    }
}
