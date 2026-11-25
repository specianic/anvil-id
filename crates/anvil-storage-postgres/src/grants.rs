//! `GrantRepo` on Postgres: authorization requests, codes, token families, refresh tokens and
//! replay guards; opaque access tokens; consent (delegated to `consent`).
//!
//! Concurrency (READ COMMITTED): every race is decided by one conditional statement. Competing
//! `UPDATE … WHERE consumed_at IS NULL` statements block on the row lock and re-evaluate the
//! WHERE clause against the committed row, so only the first matches; competing
//! `INSERT … ON CONFLICT` statements wait for the first inserter's commit.

use anvil_core::model::{
    AccessTokenRecord, AuthRequestId, AuthorizationCode, AuthorizationRequest, CodeHash,
    ConsentGrant, NewAccessToken, NewAuthorizationCode, NewAuthorizationRequest, NewConsent,
    NewRefreshToken, NewTokenFamily, RefreshToken, ReplayKind, RevokeReason, SecretHash, SessionId,
    TenantId, TokenFamily, TokenFamilyId, UserId,
};
use anvil_core::ports::{ConsumeOutcome, GrantRepo, JtiOutcome, RotateOutcome, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::consent;
use crate::convert::{enum_from, from_json, hash, map_err, opt_from_json, opt_hash, to_json};

#[derive(Debug, Clone)]
pub(crate) struct PgGrants {
    pub(crate) pool: PgPool,
}

struct FamilyRow {
    id: Uuid,
    tenant_id: Uuid,
    client_id: String,
    user_id: Option<Uuid>,
    scope: String,
    auth_time: Option<OffsetDateTime>,
    acr: Option<String>,
    amr: Vec<String>,
    session_id: Option<Uuid>,
    claims: Option<serde_json::Value>,
    created_at: OffsetDateTime,
    absolute_expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    revoked_reason: Option<String>,
}

impl FamilyRow {
    fn into_model(self) -> Result<TokenFamily, StorageError> {
        Ok(TokenFamily {
            id: TokenFamilyId(self.id),
            tenant_id: TenantId(self.tenant_id),
            client_id: self.client_id,
            user_id: self.user_id.map(UserId),
            scope: self.scope,
            auth_time: self.auth_time,
            acr: self.acr,
            amr: self.amr,
            session_id: self.session_id.map(SessionId),
            claims: opt_from_json("token_family.claims", self.claims)?,
            created_at: self.created_at,
            absolute_expires_at: self.absolute_expires_at,
            revoked_at: self.revoked_at,
            revoked_reason: self
                .revoked_reason
                .as_deref()
                .map(|r| enum_from("token_family.revoked_reason", r, RevokeReason::parse))
                .transpose()?,
        })
    }
}

async fn fetch_family<'e, E>(
    exec: E,
    tenant: TenantId,
    id: Uuid,
) -> Result<Option<TokenFamily>, StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        FamilyRow,
        "SELECT id, tenant_id, client_id, user_id, scope, auth_time, acr, amr, session_id, claims,
                created_at, absolute_expires_at, revoked_at, revoked_reason
           FROM token_family
          WHERE tenant_id = $1 AND id = $2",
        tenant.0,
        id,
    )
    .fetch_optional(exec)
    .await
    .map_err(map_err)?
    .map(FamilyRow::into_model)
    .transpose()
}

/// Inserts a token family on any executor. `Conflict` on a duplicate id.
async fn insert_family<'e, E>(
    exec: E,
    tenant: TenantId,
    family: &NewTokenFamily,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let claims = family
        .claims
        .as_ref()
        .map(|c| to_json("token_family.claims", c))
        .transpose()?;
    sqlx::query!(
        "INSERT INTO token_family
             (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr, session_id,
              claims, created_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        family.id.0,
        tenant.0,
        family.client_id,
        family.user_id.map(|u| u.0),
        family.scope,
        family.auth_time,
        family.acr,
        &family.amr,
        family.session_id.map(|s| s.0),
        claims,
        family.created_at,
        family.absolute_expires_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

async fn insert_refresh<'e, E>(
    exec: E,
    tenant: TenantId,
    t: &NewRefreshToken,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let parent = t.parent_hash.as_ref().map(|h| h.as_bytes().as_slice());
    sqlx::query!(
        "INSERT INTO refresh_token
             (token_hash, tenant_id, family_id, parent_hash, scope, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        t.token_hash.as_bytes().as_slice(),
        tenant.0,
        t.family_id.0,
        parent,
        t.scope,
        t.created_at,
        t.expires_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl GrantRepo for PgGrants {
    async fn create_authorization_request(
        &self,
        tenant: TenantId,
        request: &NewAuthorizationRequest,
    ) -> Result<(), StorageError> {
        let params = to_json("authorization_request.params", &request.params)?;
        sqlx::query!(
            "INSERT INTO authorization_request
                 (id, tenant_id, client_id, params, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
            request.id.0,
            tenant.0,
            request.client_id,
            params,
            request.created_at,
            request.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_authorization_request(
        &self,
        tenant: TenantId,
        id: AuthRequestId,
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationRequest>, StorageError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, client_id, params, created_at, expires_at
               FROM authorization_request
              WHERE tenant_id = $1 AND id = $2 AND expires_at > $3",
            tenant.0,
            id.0,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok(AuthorizationRequest {
                id: AuthRequestId(r.id),
                tenant_id: TenantId(r.tenant_id),
                client_id: r.client_id,
                params: from_json("authorization_request.params", r.params)?,
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
        })
        .transpose()
    }

    async fn delete_authorization_request(
        &self,
        tenant: TenantId,
        id: AuthRequestId,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM authorization_request WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn create_code(
        &self,
        tenant: TenantId,
        code: &NewAuthorizationCode,
        family: &NewTokenFamily,
    ) -> Result<(), StorageError> {
        if code.token_family_id != family.id {
            return Err(StorageError::Conflict(
                "authorization code token_family_id does not match the family".to_owned(),
            ));
        }
        // Family first, then the code, in one transaction: a conflict on either rolls back both.
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        insert_family(&mut *tx, tenant, family).await?;
        sqlx::query!(
            "INSERT INTO authorization_code
                 (code_hash, tenant_id, client_id, user_id, session_id, redirect_uri, scope,
                  nonce, code_challenge, auth_time, acr, amr, token_family_id, expires_at,
                  consumed_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NULL, $15)",
            code.code_hash.as_bytes().as_slice(),
            tenant.0,
            code.client_id,
            code.user_id.0,
            code.session_id.0,
            code.redirect_uri,
            code.scope,
            code.nonce,
            code.code_challenge,
            code.auth_time,
            code.acr,
            &code.amr,
            code.token_family_id.0,
            code.expires_at,
            code.created_at,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)
    }

    async fn consume_code(
        &self,
        tenant: TenantId,
        code_hash: &CodeHash,
        now: OffsetDateTime,
    ) -> Result<ConsumeOutcome, StorageError> {
        let hash_bytes = code_hash.as_bytes().as_slice();

        // The race is decided by this single statement.
        let row = sqlx::query!(
            "UPDATE authorization_code
                SET consumed_at = $3
              WHERE tenant_id = $1 AND code_hash = $2
                AND consumed_at IS NULL AND expires_at > $3
          RETURNING code_hash, tenant_id, client_id, user_id, session_id, redirect_uri, scope,
                    nonce, code_challenge, auth_time, acr, amr, token_family_id, expires_at,
                    created_at",
            tenant.0,
            hash_bytes,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;

        if let Some(r) = row {
            return Ok(ConsumeOutcome::Consumed(AuthorizationCode {
                tenant_id: TenantId(r.tenant_id),
                code_hash: hash("authorization_code.code_hash", &r.code_hash)?,
                client_id: r.client_id,
                user_id: UserId(r.user_id),
                session_id: SessionId(r.session_id),
                redirect_uri: r.redirect_uri,
                scope: r.scope,
                nonce: r.nonce,
                code_challenge: r.code_challenge,
                auth_time: r.auth_time,
                acr: r.acr,
                amr: r.amr,
                token_family_id: TokenFamilyId(r.token_family_id),
                expires_at: r.expires_at,
                created_at: r.created_at,
            }));
        }

        // Zero rows: classify the loser. This read decides nothing; it only tells a replay
        // (already consumed) apart from unknown / expired / other tenant.
        let existing = sqlx::query!(
            "SELECT consumed_at, token_family_id
               FROM authorization_code
              WHERE tenant_id = $1 AND code_hash = $2",
            tenant.0,
            hash_bytes,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(match existing {
            Some(r) if r.consumed_at.is_some() => ConsumeOutcome::AlreadyConsumed {
                family_id: Some(TokenFamilyId(r.token_family_id)),
            },
            _ => ConsumeOutcome::NotFound,
        })
    }

    async fn get_family(
        &self,
        tenant: TenantId,
        id: TokenFamilyId,
    ) -> Result<Option<TokenFamily>, StorageError> {
        fetch_family(&self.pool, tenant, id.0).await
    }

    async fn revoke_family(
        &self,
        tenant: TenantId,
        id: TokenFamilyId,
        reason: RevokeReason,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        // Idempotent: COALESCE keeps the first time and reason; the row matches either way.
        let done = sqlx::query!(
            "UPDATE token_family
                SET revoked_at = COALESCE(revoked_at, $3),
                    revoked_reason = COALESCE(revoked_reason, $4)
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
            now,
            reason.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn create_refresh_token(
        &self,
        tenant: TenantId,
        token: &NewRefreshToken,
    ) -> Result<(), StorageError> {
        insert_refresh(&self.pool, tenant, token).await
    }

    async fn find_refresh_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
    ) -> Result<Option<(RefreshToken, TokenFamily)>, StorageError> {
        let Some(r) = sqlx::query!(
            "SELECT token_hash, tenant_id, family_id, parent_hash, scope, created_at, expires_at,
                    consumed_at
               FROM refresh_token
              WHERE tenant_id = $1 AND token_hash = $2",
            tenant.0,
            token_hash.as_bytes().as_slice(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        else {
            return Ok(None);
        };
        let token = RefreshToken {
            token_hash: hash("refresh_token.token_hash", &r.token_hash)?,
            tenant_id: TenantId(r.tenant_id),
            family_id: TokenFamilyId(r.family_id),
            parent_hash: opt_hash("refresh_token.parent_hash", r.parent_hash.as_deref())?,
            scope: r.scope,
            created_at: r.created_at,
            expires_at: r.expires_at,
            consumed_at: r.consumed_at,
        };
        // The family FK (ON DELETE CASCADE) guarantees the family exists.
        let family = fetch_family(&self.pool, tenant, r.family_id)
            .await?
            .ok_or_else(|| {
                StorageError::Corrupt("refresh_token.family_id: family missing".to_owned())
            })?;
        Ok(Some((token, family)))
    }

    async fn rotate_refresh(
        &self,
        tenant: TenantId,
        presented: &SecretHash,
        child: &NewRefreshToken,
        now: OffsetDateTime,
    ) -> Result<RotateOutcome, StorageError> {
        let presented = presented.as_bytes().as_slice();
        let mut tx = self.pool.begin().await.map_err(map_err)?;

        // Concurrent rotations of the same token serialise on its row lock; the losers
        // re-evaluate `consumed_at IS NULL` against the winner's committed row and match nothing.
        let consumed = sqlx::query!(
            "UPDATE refresh_token SET consumed_at = $3
              WHERE tenant_id = $1 AND token_hash = $2
                AND consumed_at IS NULL AND expires_at > $3
                AND family_id IN (SELECT id FROM token_family
                                   WHERE tenant_id = $1 AND revoked_at IS NULL
                                     AND absolute_expires_at > $3)
          RETURNING family_id",
            tenant.0,
            presented,
            now,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;

        if let Some(row) = consumed {
            insert_refresh(&mut *tx, tenant, child).await?;
            let family = fetch_family(&mut *tx, tenant, row.family_id)
                .await?
                .ok_or_else(|| {
                    StorageError::Corrupt("refresh_token.family_id: family missing".to_owned())
                })?;
            tx.commit().await.map_err(map_err)?;
            return Ok(RotateOutcome::Rotated(family));
        }

        // Zero rows: a consumed token means reuse (revoke the family); anything else is NotFound.
        let existing = sqlx::query!(
            "SELECT consumed_at, family_id FROM refresh_token
              WHERE tenant_id = $1 AND token_hash = $2",
            tenant.0,
            presented,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        match existing {
            Some(r) if r.consumed_at.is_some() => {
                sqlx::query!(
                    "UPDATE token_family SET revoked_at = $3, revoked_reason = $4
                      WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
                    tenant.0,
                    r.family_id,
                    now,
                    RevokeReason::RefreshReuse.as_str(),
                )
                .execute(&mut *tx)
                .await
                .map_err(map_err)?;
                tx.commit().await.map_err(map_err)?;
                Ok(RotateOutcome::ReuseDetected {
                    family_id: TokenFamilyId(r.family_id),
                })
            }
            _ => Ok(RotateOutcome::NotFound),
        }
    }

    async fn record_jti(
        &self,
        tenant: TenantId,
        kind: ReplayKind,
        hash: &SecretHash,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<JtiOutcome, StorageError> {
        // Insert-or-fail; an expired entry is replaced in the same statement. A concurrent
        // inserter of the same key waits for the first one's commit and then hits the conflict.
        let row = sqlx::query!(
            "INSERT INTO replay_guard (tenant_id, kind, value_hash, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, kind, value_hash)
             DO UPDATE SET expires_at = EXCLUDED.expires_at
                WHERE replay_guard.expires_at <= $5
          RETURNING value_hash",
            tenant.0,
            kind.as_str(),
            hash.as_bytes().as_slice(),
            expires_at,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(if row.is_some() {
            JtiOutcome::Recorded
        } else {
            JtiOutcome::Replayed
        })
    }

    async fn create_family(
        &self,
        tenant: TenantId,
        family: &NewTokenFamily,
    ) -> Result<(), StorageError> {
        insert_family(&self.pool, tenant, family).await
    }

    async fn create_access_token(
        &self,
        tenant: TenantId,
        token: &NewAccessToken,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            "INSERT INTO access_token
                 (token_hash, tenant_id, family_id, client_id, user_id, scope, created_at,
                  expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            token.token_hash.as_bytes().as_slice(),
            tenant.0,
            token.family_id.map(|f| f.0),
            token.client_id,
            token.user_id.map(|u| u.0),
            token.scope,
            token.created_at,
            token.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn find_access_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
    ) -> Result<Option<(AccessTokenRecord, Option<TokenFamily>)>, StorageError> {
        let Some(r) = sqlx::query!(
            "SELECT token_hash, tenant_id, family_id, client_id, user_id, scope, created_at,
                    expires_at, revoked_at
               FROM access_token
              WHERE tenant_id = $1 AND token_hash = $2",
            tenant.0,
            token_hash.as_bytes().as_slice(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        else {
            return Ok(None);
        };
        let family = match r.family_id {
            // The family FK (ON DELETE CASCADE) guarantees the family exists.
            Some(id) => Some(fetch_family(&self.pool, tenant, id).await?.ok_or_else(|| {
                StorageError::Corrupt("access_token.family_id: family missing".to_owned())
            })?),
            None => None,
        };
        let token = AccessTokenRecord {
            token_hash: hash("access_token.token_hash", &r.token_hash)?,
            tenant_id: TenantId(r.tenant_id),
            family_id: r.family_id.map(TokenFamilyId),
            client_id: r.client_id,
            user_id: r.user_id.map(UserId),
            scope: r.scope,
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
        };
        Ok(Some((token, family)))
    }

    async fn revoke_access_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE access_token SET revoked_at = $3
              WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL",
            tenant.0,
            token_hash.as_bytes().as_slice(),
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn consent(
        &self,
        tenant: TenantId,
        user: UserId,
        client_id: &str,
    ) -> Result<Option<ConsentGrant>, StorageError> {
        consent::consent(&self.pool, tenant, user, client_id).await
    }

    async fn list_consents(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<ConsentGrant>, StorageError> {
        consent::list_consents(&self.pool, tenant, user).await
    }

    async fn upsert_consent(
        &self,
        tenant: TenantId,
        consent: &NewConsent,
        now: OffsetDateTime,
    ) -> Result<ConsentGrant, StorageError> {
        consent::upsert_consent(&self.pool, tenant, consent, now).await
    }

    async fn revoke_consent(
        &self,
        tenant: TenantId,
        user: UserId,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        consent::revoke_consent(&self.pool, tenant, user, client_id, now).await
    }
}
