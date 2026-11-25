//! Passkeys, TOTP and recovery codes on Postgres (the `UserRepo` credential methods; the trait
//! impl in `users.rs` delegates here).
//!
//! Every race is decided by one conditional statement: the passkey counter and the TOTP step
//! move with `UPDATE … WHERE counter < $new` (concurrent updaters block on the row lock and
//! re-evaluate the predicate against the committed row, so the stored value never moves
//! backwards and a step is accepted once), a recovery code is consumed with `UPDATE … WHERE
//! used_at IS NULL`. Multi-row changes (TOTP enrolment with its codes, TOTP removal, code
//! replacement) run in one transaction.

use anvil_core::model::{
    CounterOutcome, CredentialId, CredentialKind, CredentialSummary, NewEmail, NewPasskey, NewTotp,
    PasskeyCredential, RecoveryCodeHash, TenantId, TotpCredential, UserId,
};
use anvil_core::ports::StorageError;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{bigint_to_u32, bigint_to_u64, enum_from, from_hex, map_err, to_hex};
use crate::outbox::enqueue_email;

/// The insert matched no user of the tenant (the user id is unknown or belongs to another
/// tenant). Reported like the SQLite backend's composite foreign-key violation.
///
/// The schema enforces this too (migration 0003: composite `(tenant_id, user_id)` foreign keys,
/// a violation of which surfaces as `Backend`); the `WHERE EXISTS` pre-checks in the inserts
/// below are kept as defense in depth and for this clearer error.
fn unknown_user() -> StorageError {
    StorageError::Backend("credential owner is not a user of this tenant".into())
}

fn step_param(step: u64) -> Result<i64, StorageError> {
    i64::try_from(step).map_err(|_| StorageError::Backend("TOTP step out of range".into()))
}

fn code_params(codes: &[RecoveryCodeHash]) -> Vec<Vec<u8>> {
    codes.iter().map(|c| c.0.to_vec()).collect()
}

struct PasskeyRow {
    id: Uuid,
    user_id: Uuid,
    external_id: Option<Vec<u8>>,
    data: String,
    counter: Option<i64>,
    backup_eligible: bool,
    label: String,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
}

impl PasskeyRow {
    fn into_model(self) -> Result<PasskeyCredential, StorageError> {
        Ok(PasskeyCredential {
            id: CredentialId(self.id),
            user_id: UserId(self.user_id),
            credential_id: self.external_id.ok_or_else(|| {
                StorageError::Corrupt("credential.external_id: missing on a passkey".to_owned())
            })?,
            passkey_json: self.data,
            counter: bigint_to_u32("credential.counter", self.counter.unwrap_or(0))?,
            backup_eligible: self.backup_eligible,
            label: self.label,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        })
    }
}

pub(crate) async fn list_credentials(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
) -> Result<Vec<CredentialSummary>, StorageError> {
    let rows = sqlx::query!(
        "SELECT id, kind, label, created_at, last_used_at
           FROM credential
          WHERE tenant_id = $1 AND user_id = $2
          ORDER BY created_at, id",
        tenant.0,
        user.0,
    )
    .fetch_all(pool)
    .await
    .map_err(map_err)?;
    rows.into_iter()
        .map(|r| {
            Ok(CredentialSummary {
                id: CredentialId(r.id),
                kind: enum_from("credential.kind", &r.kind, CredentialKind::parse)?,
                label: r.label,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
            })
        })
        .collect()
}

pub(crate) async fn create_passkey(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    p: &NewPasskey,
) -> Result<(), StorageError> {
    // The partial unique index on (tenant_id, external_id) rejects a credential id that is
    // registered anywhere in the tenant with `Conflict`.
    let done = sqlx::query!(
        "INSERT INTO credential
             (id, tenant_id, user_id, kind, data, external_id, counter, backup_eligible, label,
              created_at, updated_at)
         SELECT $1, $2, $3, 'webauthn', $4, $5, $6, $7, $8, $9, $9
          WHERE EXISTS (SELECT 1 FROM \"user\" WHERE tenant_id = $2 AND id = $3)",
        p.id.0,
        tenant.0,
        user.0,
        p.passkey_json,
        p.credential_id,
        i64::from(p.counter),
        p.backup_eligible,
        p.label,
        p.created_at,
    )
    .execute(pool)
    .await
    .map_err(map_err)?;
    if done.rows_affected() == 0 {
        return Err(unknown_user());
    }
    Ok(())
}

pub(crate) async fn passkeys(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
) -> Result<Vec<PasskeyCredential>, StorageError> {
    sqlx::query_as!(
        PasskeyRow,
        "SELECT id, user_id, external_id, data, counter, backup_eligible, label, created_at,
                last_used_at
           FROM credential
          WHERE tenant_id = $1 AND user_id = $2 AND kind = 'webauthn'
          ORDER BY created_at, id",
        tenant.0,
        user.0,
    )
    .fetch_all(pool)
    .await
    .map_err(map_err)?
    .into_iter()
    .map(PasskeyRow::into_model)
    .collect()
}

pub(crate) async fn find_passkey(
    pool: &PgPool,
    tenant: TenantId,
    credential_id: &[u8],
) -> Result<Option<PasskeyCredential>, StorageError> {
    sqlx::query_as!(
        PasskeyRow,
        "SELECT id, user_id, external_id, data, counter, backup_eligible, label, created_at,
                last_used_at
           FROM credential
          WHERE tenant_id = $1 AND external_id = $2 AND kind = 'webauthn'",
        tenant.0,
        credential_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(map_err)?
    .map(PasskeyRow::into_model)
    .transpose()
}

pub(crate) async fn update_passkey(
    pool: &PgPool,
    tenant: TenantId,
    id: CredentialId,
    passkey_json: &str,
    counter: u32,
    now: OffsetDateTime,
) -> Result<CounterOutcome, StorageError> {
    let done = sqlx::query!(
        "UPDATE credential
            SET data = $3, counter = $4, last_used_at = $5, updated_at = $5
          WHERE tenant_id = $1 AND id = $2 AND kind = 'webauthn'
            AND (counter < $4 OR ($4 = 0 AND counter = 0))",
        tenant.0,
        id.0,
        passkey_json,
        i64::from(counter),
        now,
    )
    .execute(pool)
    .await
    .map_err(map_err)?;
    Ok(if done.rows_affected() > 0 {
        CounterOutcome::Advanced
    } else {
        CounterOutcome::Stale
    })
}

pub(crate) async fn totp(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
) -> Result<Option<TotpCredential>, StorageError> {
    let Some(r) = sqlx::query!(
        "SELECT id, user_id, data, counter, created_at, last_used_at
           FROM credential
          WHERE tenant_id = $1 AND user_id = $2 AND kind = 'totp'",
        tenant.0,
        user.0,
    )
    .fetch_optional(pool)
    .await
    .map_err(map_err)?
    else {
        return Ok(None);
    };
    Ok(Some(TotpCredential {
        id: CredentialId(r.id),
        user_id: UserId(r.user_id),
        secret_enc: from_hex("credential.data", &r.data)?,
        last_step: r
            .counter
            .map(|c| bigint_to_u64("credential.counter", c))
            .transpose()?,
        created_at: r.created_at,
        last_used_at: r.last_used_at,
    }))
}

/// Replaces the user's recovery-code set on any executor (inside the caller's transaction).
async fn put_recovery_codes(
    tx: &mut sqlx::PgConnection,
    tenant: TenantId,
    user: UserId,
    codes: &[RecoveryCodeHash],
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    sqlx::query!(
        "DELETE FROM recovery_code WHERE tenant_id = $1 AND user_id = $2",
        tenant.0,
        user.0,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    if codes.is_empty() {
        return Ok(());
    }
    let done = sqlx::query!(
        "INSERT INTO recovery_code (tenant_id, user_id, code_hash, created_at)
         SELECT $1, $2, c, $4 FROM unnest($3::bytea[]) AS c
          WHERE EXISTS (SELECT 1 FROM \"user\" WHERE tenant_id = $1 AND id = $2)",
        tenant.0,
        user.0,
        &code_params(codes),
        now,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    if done.rows_affected() == 0 {
        return Err(unknown_user());
    }
    Ok(())
}

pub(crate) async fn create_totp(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    t: &NewTotp,
    codes: &[RecoveryCodeHash],
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let mut tx = pool.begin().await.map_err(map_err)?;
    // A second TOTP credential hits the partial unique index (Conflict) and rolls back the
    // transaction before the recovery codes are touched.
    let done = sqlx::query!(
        "INSERT INTO credential (id, tenant_id, user_id, kind, data, created_at, updated_at)
         SELECT $1, $2, $3, 'totp', $4, $5, $5
          WHERE EXISTS (SELECT 1 FROM \"user\" WHERE tenant_id = $2 AND id = $3)",
        t.id.0,
        tenant.0,
        user.0,
        to_hex(&t.secret_enc),
        t.created_at,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    if done.rows_affected() == 0 {
        return Err(unknown_user());
    }
    put_recovery_codes(&mut tx, tenant, user, codes, now).await?;
    tx.commit().await.map_err(map_err)
}

pub(crate) async fn advance_totp_step(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    step: u64,
    now: OffsetDateTime,
) -> Result<CounterOutcome, StorageError> {
    let done = sqlx::query!(
        "UPDATE credential SET counter = $3, last_used_at = $4, updated_at = $4
          WHERE tenant_id = $1 AND user_id = $2 AND kind = 'totp'
            AND (counter IS NULL OR counter < $3)",
        tenant.0,
        user.0,
        step_param(step)?,
        now,
    )
    .execute(pool)
    .await
    .map_err(map_err)?;
    Ok(if done.rows_affected() > 0 {
        CounterOutcome::Advanced
    } else {
        CounterOutcome::Stale
    })
}

pub(crate) async fn delete_credential(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    id: CredentialId,
) -> Result<bool, StorageError> {
    let mut tx = pool.begin().await.map_err(map_err)?;
    let Some(kind) = sqlx::query_scalar!(
        "DELETE FROM credential
          WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND kind IN ('webauthn', 'totp')
      RETURNING kind",
        tenant.0,
        user.0,
        id.0,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_err)?
    else {
        return Ok(false);
    };
    if kind == CredentialKind::Totp.as_str() {
        sqlx::query!(
            "DELETE FROM recovery_code WHERE tenant_id = $1 AND user_id = $2",
            tenant.0,
            user.0,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
    }
    tx.commit().await.map_err(map_err)?;
    Ok(true)
}

pub(crate) async fn replace_recovery_codes(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    codes: &[RecoveryCodeHash],
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let mut tx = pool.begin().await.map_err(map_err)?;
    put_recovery_codes(&mut tx, tenant, user, codes, now).await?;
    tx.commit().await.map_err(map_err)
}

pub(crate) async fn consume_recovery_code(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    hash: &RecoveryCodeHash,
    now: OffsetDateTime,
    notice: Option<&NewEmail>,
) -> Result<bool, StorageError> {
    let mut tx = pool.begin().await.map_err(map_err)?;
    let done = sqlx::query!(
        "UPDATE recovery_code SET used_at = $4
          WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL",
        tenant.0,
        user.0,
        hash.0.as_slice(),
        now,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    if done.rows_affected() == 0 {
        return Ok(false);
    }
    if let Some(email) = notice {
        enqueue_email(&mut *tx, tenant, email).await?;
    }
    tx.commit().await.map_err(map_err)?;
    Ok(true)
}

pub(crate) async fn recovery_codes_remaining(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
) -> Result<u32, StorageError> {
    let n = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM recovery_code
          WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL",
        tenant.0,
        user.0,
    )
    .fetch_one(pool)
    .await
    .map_err(map_err)?;
    u32::try_from(n)
        .map_err(|_| StorageError::Corrupt(format!("recovery_code: count out of range {n}")))
}
