//! `KeyRepo` on SQLite.

use anvil_core::model::{KeyState, NewSigningKey, SigningKey, SigningKeyId, TenantId};
use anvil_core::ports::{KeyRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, opt_odt_to_ms, parse_enum};

#[derive(Debug, Clone)]
pub(crate) struct SqliteKeys {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct KeyRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    kid: String,
    alg: String,
    state: String,
    private_key_enc: Vec<u8>,
    public_jwk: String,
    created_at: i64,
    activated_at: Option<i64>,
    retired_at: Option<i64>,
    expires_at: Option<i64>,
}

impl TryFrom<KeyRow> for SigningKey {
    type Error = StorageError;

    fn try_from(r: KeyRow) -> Result<Self, StorageError> {
        Ok(SigningKey {
            id: SigningKeyId(r.id),
            tenant_id: TenantId(r.tenant_id),
            kid: r.kid,
            alg: r.alg,
            state: parse_enum(&r.state, KeyState::parse, "key state")?,
            private_key_enc: r.private_key_enc,
            public_jwk: r.public_jwk,
            created_at: ms_to_odt(r.created_at)?,
            activated_at: opt_ms_to_odt(r.activated_at)?,
            retired_at: opt_ms_to_odt(r.retired_at)?,
            expires_at: opt_ms_to_odt(r.expires_at)?,
        })
    }
}

/// Inserts a signing key on `conn`. `Conflict` on a duplicate kid or a second active key for
/// the same (tenant, alg).
pub(crate) async fn insert_key(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    key: &NewSigningKey,
) -> Result<(), StorageError> {
    let state = key.state.as_str();
    let created_at = odt_to_ms(key.created_at);
    let activated_at = opt_odt_to_ms(key.activated_at);
    let retired_at = opt_odt_to_ms(key.retired_at);
    let expires_at = opt_odt_to_ms(key.expires_at);
    sqlx::query!(
        "INSERT INTO signing_key
             (id, tenant_id, kid, alg, state, private_key_enc, public_jwk, created_at,
              activated_at, retired_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        key.id.0,
        tenant.0,
        key.kid,
        key.alg,
        state,
        key.private_key_enc,
        key.public_jwk,
        created_at,
        activated_at,
        retired_at,
        expires_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl KeyRepo for SqliteKeys {
    async fn insert(&self, tenant: TenantId, key: &NewSigningKey) -> Result<(), StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_key(&mut conn, tenant, key).await
    }

    async fn active(
        &self,
        tenant: TenantId,
        alg: &str,
    ) -> Result<Option<SigningKey>, StorageError> {
        sqlx::query_as!(
            KeyRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      kid AS "kid!", alg AS "alg!", state AS "state!",
                      private_key_enc AS "private_key_enc!", public_jwk AS "public_jwk!",
                      created_at AS "created_at!", activated_at AS "activated_at?",
                      retired_at AS "retired_at?", expires_at AS "expires_at?"
                 FROM signing_key
                WHERE tenant_id = ?1 AND alg = ?2 AND state = 'active'"#,
            tenant.0,
            alg,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(SigningKey::try_from)
        .transpose()
    }

    async fn published(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<Vec<SigningKey>, StorageError> {
        let now_ms = odt_to_ms(now);
        sqlx::query_as!(
            KeyRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      kid AS "kid!", alg AS "alg!", state AS "state!",
                      private_key_enc AS "private_key_enc!", public_jwk AS "public_jwk!",
                      created_at AS "created_at!", activated_at AS "activated_at?",
                      retired_at AS "retired_at?", expires_at AS "expires_at?"
                 FROM signing_key
                WHERE tenant_id = ?1 AND (expires_at IS NULL OR expires_at > ?2)
                ORDER BY id"#,
            tenant.0,
            now_ms,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(SigningKey::try_from)
        .collect()
    }

    async fn list(&self, tenant: TenantId) -> Result<Vec<SigningKey>, StorageError> {
        sqlx::query_as!(
            KeyRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      kid AS "kid!", alg AS "alg!", state AS "state!",
                      private_key_enc AS "private_key_enc!", public_jwk AS "public_jwk!",
                      created_at AS "created_at!", activated_at AS "activated_at?",
                      retired_at AS "retired_at?", expires_at AS "expires_at?"
                 FROM signing_key WHERE tenant_id = ?1 ORDER BY id"#,
            tenant.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(SigningKey::try_from)
        .collect()
    }

    async fn promote(
        &self,
        tenant: TenantId,
        retire: Option<(SigningKeyId, OffsetDateTime)>,
        activate: SigningKeyId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // Retire first: the partial unique index allows one active key per (tenant, alg), so a
        // single swapping UPDATE would be rejected. Any early return drops `tx` uncommitted.
        if let Some((old, expires_at)) = retire {
            let expires_ms = odt_to_ms(expires_at);
            let retired = sqlx::query!(
                "UPDATE signing_key SET state = 'retired', retired_at = ?3, expires_at = ?4
                  WHERE tenant_id = ?1 AND id = ?2 AND state = 'active'",
                tenant.0,
                old.0,
                now_ms,
                expires_ms,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
            if retired.rows_affected() != 1 {
                tx.rollback().await.map_err(map_err)?;
                return Ok(false);
            }
        }
        // A second active key of the same alg makes this fail with a unique violation
        // (Conflict); the retire above is rolled back with the transaction.
        let activated = sqlx::query!(
            "UPDATE signing_key SET state = 'active', activated_at = ?3
              WHERE tenant_id = ?1 AND id = ?2 AND state = 'next'",
            tenant.0,
            activate.0,
            now_ms,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if activated.rows_affected() != 1 {
            tx.rollback().await.map_err(map_err)?;
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
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "DELETE FROM signing_key
              WHERE tenant_id = ?1 AND state = 'retired' AND expires_at IS NOT NULL
                AND expires_at <= ?2",
            tenant.0,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected())
    }
}
