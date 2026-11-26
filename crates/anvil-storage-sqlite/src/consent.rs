//! Consent grants on SQLite (the `GrantRepo` consent methods delegate here).

use std::collections::BTreeSet;

use anvil_core::model::{ConsentGrant, ConsentId, NewConsent, RevokeReason, TenantId, UserId};
use anvil_core::ports::StorageError;
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{from_json, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, to_json};

struct ConsentRow {
    id: uuid::Uuid,
    user_id: uuid::Uuid,
    client_id: String,
    scopes: String,
    created_at: i64,
    updated_at: i64,
    revoked_at: Option<i64>,
    resources: String,
}

impl TryFrom<ConsentRow> for ConsentGrant {
    type Error = StorageError;

    fn try_from(r: ConsentRow) -> Result<Self, StorageError> {
        Ok(ConsentGrant {
            id: ConsentId(r.id),
            user_id: UserId(r.user_id),
            client_id: r.client_id,
            scopes: from_json(&r.scopes, "consent_grant.scopes")?,
            created_at: ms_to_odt(r.created_at)?,
            updated_at: ms_to_odt(r.updated_at)?,
            revoked_at: opt_ms_to_odt(r.revoked_at)?,
            resources: from_json(&r.resources, "consent_grant.resources")?,
        })
    }
}

/// The grant of (user, client) in any state, read on `conn`.
async fn grant_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    user: UserId,
    client_id: &str,
) -> Result<Option<ConsentGrant>, StorageError> {
    sqlx::query_as!(
        ConsentRow,
        r#"SELECT id AS "id!: uuid::Uuid", user_id AS "user_id!: uuid::Uuid",
                  client_id AS "client_id!", scopes AS "scopes!", created_at AS "created_at!",
                  updated_at AS "updated_at!", revoked_at AS "revoked_at?",
                  resources AS "resources!"
             FROM consent_grant WHERE tenant_id = ?1 AND user_id = ?2 AND client_id = ?3"#,
        tenant.0,
        user.0,
        client_id,
    )
    .fetch_optional(conn)
    .await
    .map_err(map_err)?
    .map(ConsentGrant::try_from)
    .transpose()
}

/// The active consent of (user, client).
pub(crate) async fn active(
    reader: &SqlitePool,
    tenant: TenantId,
    user: UserId,
    client_id: &str,
) -> Result<Option<ConsentGrant>, StorageError> {
    let mut conn = reader.acquire().await.map_err(map_err)?;
    Ok(grant_on(&mut conn, tenant, user, client_id)
        .await?
        .filter(|g| g.revoked_at.is_none()))
}

/// The user's active consents in client id order.
pub(crate) async fn list_active(
    reader: &SqlitePool,
    tenant: TenantId,
    user: UserId,
) -> Result<Vec<ConsentGrant>, StorageError> {
    sqlx::query_as!(
        ConsentRow,
        r#"SELECT id AS "id!: uuid::Uuid", user_id AS "user_id!: uuid::Uuid",
                  client_id AS "client_id!", scopes AS "scopes!", created_at AS "created_at!",
                  updated_at AS "updated_at!", revoked_at AS "revoked_at?",
                  resources AS "resources!"
             FROM consent_grant
            WHERE tenant_id = ?1 AND user_id = ?2 AND revoked_at IS NULL
            ORDER BY client_id"#,
        tenant.0,
        user.0,
    )
    .fetch_all(reader)
    .await
    .map_err(map_err)?
    .into_iter()
    .map(ConsentGrant::try_from)
    .collect()
}

/// Creates or merges a grant in one transaction on the writer. The read-then-write is
/// serialised by the single writer connection; the write itself is still an upsert on the
/// unique (tenant, user, client) index.
pub(crate) async fn upsert(
    writer: &SqlitePool,
    tenant: TenantId,
    consent: &NewConsent,
    now: OffsetDateTime,
) -> Result<ConsentGrant, StorageError> {
    let mut tx = writer.begin().await.map_err(map_err)?;
    let existing = grant_on(&mut tx, tenant, consent.user_id, &consent.client_id).await?;
    let mut merged: BTreeSet<String> = consent.scopes.iter().cloned().collect();
    let mut resources: BTreeSet<String> = consent.resources.iter().cloned().collect();
    if let Some(active) = existing.as_ref().filter(|g| g.revoked_at.is_none()) {
        merged.extend(active.scopes.iter().cloned());
        resources.extend(active.resources.iter().cloned());
    }
    let scopes = to_json(
        &merged.into_iter().collect::<Vec<_>>(),
        "consent_grant.scopes",
    )?;
    // A BTreeSet iterates sorted and de-duplicated: the stored form of `normalize_resources`.
    let resources = to_json(
        &resources.into_iter().collect::<Vec<_>>(),
        "consent_grant.resources",
    )?;
    let created_at = odt_to_ms(consent.created_at);
    let now_ms = odt_to_ms(now);
    let row = sqlx::query_as!(
        ConsentRow,
        r#"INSERT INTO consent_grant
               (id, tenant_id, user_id, client_id, scopes, created_at, updated_at, revoked_at,
                resources)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)
           ON CONFLICT (tenant_id, user_id, client_id)
           DO UPDATE SET scopes = excluded.scopes, updated_at = excluded.updated_at,
                         revoked_at = NULL, resources = excluded.resources
           RETURNING id AS "id!: uuid::Uuid", user_id AS "user_id!: uuid::Uuid",
                     client_id AS "client_id!", scopes AS "scopes!", created_at AS "created_at!",
                     updated_at AS "updated_at!", revoked_at AS "revoked_at?",
                  resources AS "resources!""#,
        consent.id.0,
        tenant.0,
        consent.user_id.0,
        consent.client_id,
        scopes,
        created_at,
        now_ms,
        resources,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(map_err)?;
    let grant = ConsentGrant::try_from(row)?;
    tx.commit().await.map_err(map_err)?;
    Ok(grant)
}

/// Revokes the active consent of (user, client) and the user's unrevoked families of that
/// client, in one transaction. `false` (nothing changed) without an active consent.
pub(crate) async fn revoke(
    writer: &SqlitePool,
    tenant: TenantId,
    user: UserId,
    client_id: &str,
    now: OffsetDateTime,
) -> Result<bool, StorageError> {
    let now_ms = odt_to_ms(now);
    let reason = RevokeReason::ConsentRevoked.as_str();
    let mut tx = writer.begin().await.map_err(map_err)?;
    let done = sqlx::query!(
        "UPDATE consent_grant SET revoked_at = ?4
          WHERE tenant_id = ?1 AND user_id = ?2 AND client_id = ?3 AND revoked_at IS NULL",
        tenant.0,
        user.0,
        client_id,
        now_ms,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    if done.rows_affected() == 0 {
        tx.rollback().await.map_err(map_err)?;
        return Ok(false);
    }
    sqlx::query!(
        "UPDATE token_family SET revoked_at = ?4, revoked_reason = ?5
          WHERE tenant_id = ?1 AND user_id = ?2 AND client_id = ?3 AND revoked_at IS NULL",
        tenant.0,
        user.0,
        client_id,
        now_ms,
        reason,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    tx.commit().await.map_err(map_err)?;
    Ok(true)
}
