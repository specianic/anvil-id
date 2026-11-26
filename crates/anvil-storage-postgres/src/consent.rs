//! Consent grants on Postgres (the `GrantRepo` consent methods; the trait impl in `grants.rs`
//! delegates here).
//!
//! `upsert_consent` is one `INSERT … ON CONFLICT DO UPDATE`: concurrent first grants for the same
//! (user, client) serialise on the unique index and the loser merges into the winner's row, so
//! no granted scope is ever lost. Scopes are stored as a sorted, de-duplicated jsonb array
//! (byte order, `COLLATE "C"`, matching Rust's `str` ordering); RFC 8707 resources the same way.

use anvil_core::model::{
    ConsentGrant, ConsentId, NewConsent, RevokeReason, TenantId, UserId, normalize_resources,
};
use anvil_core::ports::StorageError;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{from_json, map_err, to_json};

struct ConsentRow {
    id: Uuid,
    user_id: Uuid,
    client_id: String,
    scopes: serde_json::Value,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    resources: serde_json::Value,
}

impl ConsentRow {
    fn into_model(self) -> Result<ConsentGrant, StorageError> {
        Ok(ConsentGrant {
            id: ConsentId(self.id),
            user_id: UserId(self.user_id),
            client_id: self.client_id,
            scopes: from_json("consent_grant.scopes", self.scopes)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            revoked_at: self.revoked_at,
            resources: from_json("consent_grant.resources", self.resources)?,
        })
    }
}

pub(crate) async fn consent(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    client_id: &str,
) -> Result<Option<ConsentGrant>, StorageError> {
    sqlx::query_as!(
        ConsentRow,
        "SELECT id, user_id, client_id, scopes, created_at, updated_at, revoked_at, resources
           FROM consent_grant
          WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 AND revoked_at IS NULL",
        tenant.0,
        user.0,
        client_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(map_err)?
    .map(ConsentRow::into_model)
    .transpose()
}

pub(crate) async fn list_consents(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
) -> Result<Vec<ConsentGrant>, StorageError> {
    sqlx::query_as!(
        ConsentRow,
        "SELECT id, user_id, client_id, scopes, created_at, updated_at, revoked_at, resources
           FROM consent_grant
          WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL
          ORDER BY client_id COLLATE \"C\"",
        tenant.0,
        user.0,
    )
    .fetch_all(pool)
    .await
    .map_err(map_err)?
    .into_iter()
    .map(ConsentRow::into_model)
    .collect()
}

pub(crate) async fn upsert_consent(
    pool: &PgPool,
    tenant: TenantId,
    c: &NewConsent,
    now: OffsetDateTime,
) -> Result<ConsentGrant, StorageError> {
    let mut scopes = c.scopes.clone();
    scopes.sort();
    scopes.dedup();
    let scopes = to_json("consent_grant.scopes", &scopes)?;
    let resources = to_json(
        "consent_grant.resources",
        &normalize_resources(&c.resources),
    )?;
    // Active grant: union of stored and new scopes. Revoked grant: re-activated with exactly the
    // new scopes. The user must belong to the tenant: the composite (tenant_id, user_id) FK
    // enforces it in the schema; the EXISTS pre-check is defense in depth with a clearer error.
    sqlx::query_as!(
        ConsentRow,
        "INSERT INTO consent_grant
             (id, tenant_id, user_id, client_id, scopes, created_at, updated_at, resources)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8
          WHERE EXISTS (SELECT 1 FROM \"user\" WHERE tenant_id = $2 AND id = $3)
         ON CONFLICT (tenant_id, user_id, client_id) DO UPDATE
            SET scopes = CASE
                  WHEN consent_grant.revoked_at IS NULL THEN COALESCE(
                    (SELECT jsonb_agg(u.s ORDER BY u.s)
                       FROM (SELECT DISTINCT e COLLATE \"C\" AS s
                               FROM jsonb_array_elements_text(
                                      consent_grant.scopes || EXCLUDED.scopes) AS e) AS u),
                    '[]'::jsonb)
                  ELSE EXCLUDED.scopes
                END,
                resources = CASE
                  WHEN consent_grant.revoked_at IS NULL THEN COALESCE(
                    (SELECT jsonb_agg(u.r ORDER BY u.r)
                       FROM (SELECT DISTINCT e COLLATE \"C\" AS r
                               FROM jsonb_array_elements_text(
                                      consent_grant.resources || EXCLUDED.resources) AS e) AS u),
                    '[]'::jsonb)
                  ELSE EXCLUDED.resources
                END,
                updated_at = EXCLUDED.updated_at,
                revoked_at = NULL
      RETURNING id, user_id, client_id, scopes, created_at, updated_at, revoked_at, resources",
        c.id.0,
        tenant.0,
        c.user_id.0,
        c.client_id,
        scopes,
        c.created_at,
        now,
        resources,
    )
    .fetch_optional(pool)
    .await
    .map_err(map_err)?
    .ok_or_else(|| StorageError::Backend("consent owner is not a user of this tenant".into()))?
    .into_model()
}

pub(crate) async fn revoke_consent(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    client_id: &str,
    now: OffsetDateTime,
) -> Result<bool, StorageError> {
    let mut tx = pool.begin().await.map_err(map_err)?;
    let done = sqlx::query!(
        "UPDATE consent_grant SET revoked_at = $4
          WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 AND revoked_at IS NULL",
        tenant.0,
        user.0,
        client_id,
        now,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    if done.rows_affected() == 0 {
        return Ok(false);
    }
    sqlx::query!(
        "UPDATE token_family SET revoked_at = $4, revoked_reason = $5
          WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 AND revoked_at IS NULL",
        tenant.0,
        user.0,
        client_id,
        now,
        RevokeReason::ConsentRevoked.as_str(),
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    tx.commit().await.map_err(map_err)?;
    Ok(true)
}
