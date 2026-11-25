//! `GrantRepo` on Postgres.

use anvil_core::model::{
    AuthorizationCode, CodeHash, NewAuthorizationCode, TenantId, TokenFamilyId,
};
use anvil_core::ports::{ConsumeOutcome, GrantRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::convert::{bytea_to_code_hash, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgGrants {
    pub(crate) pool: PgPool,
}

#[async_trait::async_trait]
impl GrantRepo for PgGrants {
    async fn create_code(
        &self,
        tenant: TenantId,
        code: &NewAuthorizationCode,
    ) -> Result<(), StorageError> {
        let code_hash = code.code_hash.as_bytes().as_slice();
        let token_family_id = code.token_family_id.map(|f| f.0);
        sqlx::query!(
            "INSERT INTO authorization_code
                 (code_hash, tenant_id, client_id, redirect_uri, scope, code_challenge, nonce,
                  token_family_id, expires_at, consumed_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, $10)",
            code_hash,
            tenant.0,
            code.client_id,
            code.redirect_uri,
            code.scope,
            code.code_challenge,
            code.nonce,
            token_family_id,
            code.expires_at,
            code.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn consume_code(
        &self,
        tenant: TenantId,
        code_hash: &CodeHash,
        now: OffsetDateTime,
    ) -> Result<ConsumeOutcome, StorageError> {
        let hash = code_hash.as_bytes().as_slice();

        // The race is decided by this single statement: concurrent UPDATEs block on the row lock
        // and, under READ COMMITTED, re-evaluate the WHERE clause against the committed row, so
        // only the first one matches.
        let row = sqlx::query!(
            "UPDATE authorization_code
                SET consumed_at = $3
              WHERE tenant_id = $1 AND code_hash = $2
                AND consumed_at IS NULL AND expires_at > $3
          RETURNING code_hash, tenant_id, client_id, redirect_uri, scope, code_challenge, nonce,
                    token_family_id, expires_at, created_at",
            tenant.0,
            hash,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;

        if let Some(r) = row {
            return Ok(ConsumeOutcome::Consumed(AuthorizationCode {
                tenant_id: TenantId(r.tenant_id),
                code_hash: bytea_to_code_hash(&r.code_hash)?,
                client_id: r.client_id,
                redirect_uri: r.redirect_uri,
                scope: r.scope,
                code_challenge: r.code_challenge,
                nonce: r.nonce,
                token_family_id: r.token_family_id.map(TokenFamilyId),
                expires_at: r.expires_at,
                created_at: r.created_at,
            }));
        }

        // Zero rows: classify the loser. This read does not decide anything, it only tells a
        // replay (already consumed) apart from unknown / expired / other tenant.
        let existing = sqlx::query!(
            "SELECT consumed_at, token_family_id
               FROM authorization_code
              WHERE tenant_id = $1 AND code_hash = $2",
            tenant.0,
            hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(match existing {
            Some(r) if r.consumed_at.is_some() => ConsumeOutcome::AlreadyConsumed {
                family_id: r.token_family_id.map(TokenFamilyId),
            },
            _ => ConsumeOutcome::NotFound,
        })
    }
}
