//! `RegistrationRepo` on SQLite: initial access tokens (stored by hash only) and the per-source
//! client count behind the DCR `max_clients` cap.

use anvil_core::model::{
    ClientSource, InitialAccessToken, InitialAccessTokenId, NewInitialAccessToken, SecretHash,
    TenantId,
};
use anvil_core::ports::{RegistrationRepo, StorageError};
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::convert::{
    blob_to_hash, i64_to_u32, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, opt_odt_to_ms,
};

#[derive(Debug, Clone)]
pub(crate) struct SqliteRegistration {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct IatRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    description: String,
    token_hash: Vec<u8>,
    expires_at: Option<i64>,
    uses_remaining: Option<i64>,
    created_at: i64,
    revoked_at: Option<i64>,
}

impl TryFrom<IatRow> for InitialAccessToken {
    type Error = StorageError;

    fn try_from(r: IatRow) -> Result<Self, StorageError> {
        Ok(InitialAccessToken {
            id: InitialAccessTokenId(r.id),
            tenant_id: TenantId(r.tenant_id),
            description: r.description,
            token_hash: blob_to_hash(&r.token_hash, "initial_access_token.token_hash")?,
            expires_at: opt_ms_to_odt(r.expires_at)?,
            uses_remaining: r
                .uses_remaining
                .map(|u| i64_to_u32(u, "initial_access_token.uses_remaining"))
                .transpose()?,
            created_at: ms_to_odt(r.created_at)?,
            revoked_at: opt_ms_to_odt(r.revoked_at)?,
        })
    }
}

#[async_trait::async_trait]
impl RegistrationRepo for SqliteRegistration {
    async fn create_iat(
        &self,
        tenant: TenantId,
        token: &NewInitialAccessToken,
    ) -> Result<InitialAccessToken, StorageError> {
        let hash = token.token_hash.as_bytes().as_slice();
        let expires_at = opt_odt_to_ms(token.expires_at);
        let uses = token.uses_remaining.map(i64::from);
        let created_at = odt_to_ms(token.created_at);
        sqlx::query!(
            "INSERT INTO initial_access_token
                 (id, tenant_id, description, token_hash, expires_at, uses_remaining, created_at,
                  revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            token.id.0,
            tenant.0,
            token.description,
            hash,
            expires_at,
            uses,
            created_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(InitialAccessToken {
            id: token.id,
            tenant_id: tenant,
            description: token.description.clone(),
            token_hash: token.token_hash,
            expires_at: token.expires_at,
            uses_remaining: token.uses_remaining,
            created_at: token.created_at,
            revoked_at: None,
        })
    }

    async fn list_iats(&self, tenant: TenantId) -> Result<Vec<InitialAccessToken>, StorageError> {
        sqlx::query_as!(
            IatRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      description AS "description!", token_hash AS "token_hash!",
                      expires_at AS "expires_at?", uses_remaining AS "uses_remaining?",
                      created_at AS "created_at!", revoked_at AS "revoked_at?"
                 FROM initial_access_token WHERE tenant_id = ?1
                ORDER BY id"#,
            tenant.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(InitialAccessToken::try_from)
        .collect()
    }

    async fn revoke_iat(
        &self,
        tenant: TenantId,
        id: InitialAccessTokenId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE initial_access_token SET revoked_at = ?3
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

    async fn consume_iat(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<InitialAccessToken>, StorageError> {
        let hash = token_hash.as_bytes().as_slice();
        let now_ms = odt_to_ms(now);
        // One conditional statement on the single writer: of concurrent consumers of a
        // single-use token exactly one sees the row still at uses_remaining = 1.
        sqlx::query_as!(
            IatRow,
            r#"UPDATE initial_access_token
                  SET uses_remaining = CASE WHEN uses_remaining IS NULL THEN NULL
                                            ELSE uses_remaining - 1 END
                WHERE tenant_id = ?1 AND token_hash = ?2 AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > ?3)
                  AND (uses_remaining IS NULL OR uses_remaining > 0)
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      description AS "description!", token_hash AS "token_hash!",
                      expires_at AS "expires_at?", uses_remaining AS "uses_remaining?",
                      created_at AS "created_at!", revoked_at AS "revoked_at?""#,
            tenant.0,
            hash,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(InitialAccessToken::try_from)
        .transpose()
    }

    async fn count_clients_by_source(
        &self,
        tenant: TenantId,
        source: ClientSource,
    ) -> Result<u64, StorageError> {
        let source = source.as_str();
        let count = sqlx::query_scalar!(
            r#"SELECT count(*) AS "count!: i64" FROM client
                WHERE tenant_id = ?1 AND registration_source = ?2"#,
            tenant.0,
            source,
        )
        .fetch_one(&self.reader)
        .await
        .map_err(map_err)?;
        u64::try_from(count).map_err(|_| StorageError::Corrupt(format!("negative count {count}")))
    }
}
