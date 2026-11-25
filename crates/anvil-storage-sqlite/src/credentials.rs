//! Passkey, TOTP and recovery-code persistence on SQLite (the `UserRepo` credential methods
//! delegate here).
//!
//! Storage format in `credential`: passkeys keep the webauthn-rs JSON in `secret`, the WebAuthn
//! credential id in `external_id` and the signature counter in `counter`; a TOTP row keeps the
//! base64url of the KEK-sealed seed in `secret` and the last accepted time step in `counter`.
//! Monotonic counters only move through single conditional UPDATEs, so concurrent callers never
//! move them backwards or accept a step twice.

use anvil_core::model::{
    CounterOutcome, CredentialId, CredentialKind, CredentialSummary, NewEmail, NewPasskey, NewTotp,
    PasskeyCredential, RecoveryCodeHash, TenantId, TotpCredential, UserId,
};
use anvil_core::ports::StorageError;
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{
    i64_to_u32, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, parse_enum, sealed_from_text,
};
use crate::outbox::insert_email;

const WEBAUTHN_KIND: &str = "webauthn";
const TOTP_KIND: &str = "totp";

/// A TOTP step as stored (INTEGER is signed 64-bit). Steps beyond `i64::MAX` cannot occur for
/// real clocks; they are refused rather than wrapped.
fn step_to_i64(step: u64) -> Result<i64, StorageError> {
    i64::try_from(step)
        .map_err(|_| StorageError::Backend(format!("TOTP step {step} out of range").into()))
}

pub(crate) async fn list(
    reader: &SqlitePool,
    tenant: TenantId,
    user: UserId,
) -> Result<Vec<CredentialSummary>, StorageError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!: uuid::Uuid", kind AS "kind!", label AS "label!",
                  created_at AS "created_at!", last_used_at AS "last_used_at?"
             FROM credential WHERE tenant_id = ?1 AND user_id = ?2
            ORDER BY created_at, id"#,
        tenant.0,
        user.0,
    )
    .fetch_all(reader)
    .await
    .map_err(map_err)?;
    rows.into_iter()
        .map(|r| {
            Ok(CredentialSummary {
                id: CredentialId(r.id),
                kind: parse_enum(&r.kind, CredentialKind::parse, "credential kind")?,
                label: r.label,
                created_at: ms_to_odt(r.created_at)?,
                last_used_at: opt_ms_to_odt(r.last_used_at)?,
            })
        })
        .collect()
}

struct PasskeyRow {
    id: uuid::Uuid,
    user_id: uuid::Uuid,
    external_id: Vec<u8>,
    secret: String,
    counter: i64,
    backup_eligible: bool,
    label: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

impl TryFrom<PasskeyRow> for PasskeyCredential {
    type Error = StorageError;

    fn try_from(r: PasskeyRow) -> Result<Self, StorageError> {
        Ok(PasskeyCredential {
            id: CredentialId(r.id),
            user_id: UserId(r.user_id),
            credential_id: r.external_id,
            passkey_json: r.secret,
            counter: i64_to_u32(r.counter, "passkey counter")?,
            backup_eligible: r.backup_eligible,
            label: r.label,
            created_at: ms_to_odt(r.created_at)?,
            last_used_at: opt_ms_to_odt(r.last_used_at)?,
        })
    }
}

/// `Conflict` if the WebAuthn credential id (unique per tenant) or the row id exists.
pub(crate) async fn create_passkey(
    writer: &SqlitePool,
    tenant: TenantId,
    user: UserId,
    passkey: &NewPasskey,
) -> Result<(), StorageError> {
    let counter = i64::from(passkey.counter);
    let created_at = odt_to_ms(passkey.created_at);
    sqlx::query!(
        "INSERT INTO credential
             (id, tenant_id, user_id, kind, secret, external_id, counter, backup_eligible, label,
              created_at, updated_at, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, NULL)",
        passkey.id.0,
        tenant.0,
        user.0,
        WEBAUTHN_KIND,
        passkey.passkey_json,
        passkey.credential_id,
        counter,
        passkey.backup_eligible,
        passkey.label,
        created_at,
    )
    .execute(writer)
    .await
    .map_err(map_err)?;
    Ok(())
}

pub(crate) async fn passkeys(
    reader: &SqlitePool,
    tenant: TenantId,
    user: UserId,
) -> Result<Vec<PasskeyCredential>, StorageError> {
    sqlx::query_as!(
        PasskeyRow,
        r#"SELECT id AS "id!: uuid::Uuid", user_id AS "user_id!: uuid::Uuid",
                  external_id AS "external_id!", secret AS "secret!", counter AS "counter!",
                  backup_eligible AS "backup_eligible!: bool", label AS "label!",
                  created_at AS "created_at!", last_used_at AS "last_used_at?"
             FROM credential
            WHERE tenant_id = ?1 AND user_id = ?2 AND kind = 'webauthn'
            ORDER BY created_at, id"#,
        tenant.0,
        user.0,
    )
    .fetch_all(reader)
    .await
    .map_err(map_err)?
    .into_iter()
    .map(PasskeyCredential::try_from)
    .collect()
}

pub(crate) async fn find_passkey(
    reader: &SqlitePool,
    tenant: TenantId,
    credential_id: &[u8],
) -> Result<Option<PasskeyCredential>, StorageError> {
    sqlx::query_as!(
        PasskeyRow,
        r#"SELECT id AS "id!: uuid::Uuid", user_id AS "user_id!: uuid::Uuid",
                  external_id AS "external_id!", secret AS "secret!", counter AS "counter!",
                  backup_eligible AS "backup_eligible!: bool", label AS "label!",
                  created_at AS "created_at!", last_used_at AS "last_used_at?"
             FROM credential
            WHERE tenant_id = ?1 AND external_id = ?2 AND kind = 'webauthn'"#,
        tenant.0,
        credential_id,
    )
    .fetch_optional(reader)
    .await
    .map_err(map_err)?
    .map(PasskeyCredential::try_from)
    .transpose()
}

/// Single conditional UPDATE: the counter only moves forward (0 → 0 is accepted for
/// authenticators without a counter).
pub(crate) async fn update_passkey(
    writer: &SqlitePool,
    tenant: TenantId,
    id: CredentialId,
    passkey_json: &str,
    counter: u32,
    now: OffsetDateTime,
) -> Result<CounterOutcome, StorageError> {
    let counter = i64::from(counter);
    let now_ms = odt_to_ms(now);
    let done = sqlx::query!(
        "UPDATE credential
            SET secret = ?3, counter = ?4, last_used_at = ?5, updated_at = ?5
          WHERE id = ?2 AND tenant_id = ?1 AND kind = 'webauthn'
            AND (counter < ?4 OR (?4 = 0 AND counter = 0))",
        tenant.0,
        id.0,
        passkey_json,
        counter,
        now_ms,
    )
    .execute(writer)
    .await
    .map_err(map_err)?;
    Ok(if done.rows_affected() == 1 {
        CounterOutcome::Advanced
    } else {
        CounterOutcome::Stale
    })
}

pub(crate) async fn totp(
    reader: &SqlitePool,
    tenant: TenantId,
    user: UserId,
) -> Result<Option<TotpCredential>, StorageError> {
    let row = sqlx::query!(
        r#"SELECT id AS "id!: uuid::Uuid", user_id AS "user_id!: uuid::Uuid",
                  secret AS "secret!", counter AS "counter?", created_at AS "created_at!",
                  last_used_at AS "last_used_at?"
             FROM credential WHERE tenant_id = ?1 AND user_id = ?2 AND kind = 'totp'"#,
        tenant.0,
        user.0,
    )
    .fetch_optional(reader)
    .await
    .map_err(map_err)?;
    row.map(|r| {
        Ok(TotpCredential {
            id: CredentialId(r.id),
            user_id: UserId(r.user_id),
            secret_enc: sealed_from_text(&r.secret, "credential.secret (totp)")?,
            last_step: r
                .counter
                .map(|c| {
                    u64::try_from(c)
                        .map_err(|_| StorageError::Corrupt(format!("TOTP step {c} out of range")))
                })
                .transpose()?,
            created_at: ms_to_odt(r.created_at)?,
            last_used_at: opt_ms_to_odt(r.last_used_at)?,
        })
    })
    .transpose()
}

/// Replaces the user's recovery codes on `conn` (caller holds the transaction).
async fn replace_codes_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    user: UserId,
    codes: &[RecoveryCodeHash],
    now_ms: i64,
) -> Result<(), StorageError> {
    sqlx::query!(
        "DELETE FROM recovery_code WHERE tenant_id = ?1 AND user_id = ?2",
        tenant.0,
        user.0,
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;
    for code in codes {
        let hash = code.0.as_slice();
        sqlx::query!(
            "INSERT INTO recovery_code (tenant_id, user_id, code_hash, created_at, used_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            tenant.0,
            user.0,
            hash,
            now_ms,
        )
        .execute(&mut *conn)
        .await
        .map_err(map_err)?;
    }
    Ok(())
}

/// One transaction: the TOTP row (`Conflict` on a second one) and the new recovery-code set.
pub(crate) async fn create_totp(
    writer: &SqlitePool,
    tenant: TenantId,
    user: UserId,
    totp: &NewTotp,
    codes: &[RecoveryCodeHash],
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let secret = anvil_jose::encoding::b64url(&totp.secret_enc);
    let created_at = odt_to_ms(totp.created_at);
    let now_ms = odt_to_ms(now);
    let mut tx = writer.begin().await.map_err(map_err)?;
    // Any error drops `tx` uncommitted: a conflicting TOTP leaves the old codes in place.
    sqlx::query!(
        "INSERT INTO credential
             (id, tenant_id, user_id, kind, secret, external_id, counter, backup_eligible, label,
              created_at, updated_at, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 0, '', ?6, ?6, NULL)",
        totp.id.0,
        tenant.0,
        user.0,
        TOTP_KIND,
        secret,
        created_at,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    replace_codes_on(&mut tx, tenant, user, codes, now_ms).await?;
    tx.commit().await.map_err(map_err)
}

/// Single conditional UPDATE `... AND (last_step IS NULL OR last_step < step)` (the last step
/// lives in `counter`): a step is accepted at most once.
pub(crate) async fn advance_totp_step(
    writer: &SqlitePool,
    tenant: TenantId,
    user: UserId,
    step: u64,
    now: OffsetDateTime,
) -> Result<CounterOutcome, StorageError> {
    let step = step_to_i64(step)?;
    let now_ms = odt_to_ms(now);
    let done = sqlx::query!(
        "UPDATE credential SET counter = ?3, last_used_at = ?4, updated_at = ?4
          WHERE tenant_id = ?1 AND user_id = ?2 AND kind = 'totp'
            AND (counter IS NULL OR counter < ?3)",
        tenant.0,
        user.0,
        step,
        now_ms,
    )
    .execute(writer)
    .await
    .map_err(map_err)?;
    Ok(if done.rows_affected() == 1 {
        CounterOutcome::Advanced
    } else {
        CounterOutcome::Stale
    })
}

/// Deletes a passkey or TOTP credential of `user` (never a password); deleting the TOTP also
/// deletes the recovery codes, in the same transaction.
pub(crate) async fn delete(
    writer: &SqlitePool,
    tenant: TenantId,
    user: UserId,
    id: CredentialId,
) -> Result<bool, StorageError> {
    let mut tx = writer.begin().await.map_err(map_err)?;
    let deleted = sqlx::query!(
        r#"DELETE FROM credential
            WHERE tenant_id = ?1 AND user_id = ?2 AND id = ?3 AND kind IN ('webauthn', 'totp')
        RETURNING kind AS "kind!""#,
        tenant.0,
        user.0,
        id.0,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_err)?;
    let Some(row) = deleted else {
        tx.rollback().await.map_err(map_err)?;
        return Ok(false);
    };
    if row.kind == TOTP_KIND {
        sqlx::query!(
            "DELETE FROM recovery_code WHERE tenant_id = ?1 AND user_id = ?2",
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
    writer: &SqlitePool,
    tenant: TenantId,
    user: UserId,
    codes: &[RecoveryCodeHash],
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let now_ms = odt_to_ms(now);
    let mut tx = writer.begin().await.map_err(map_err)?;
    replace_codes_on(&mut tx, tenant, user, codes, now_ms).await?;
    tx.commit().await.map_err(map_err)
}

/// Single conditional UPDATE; the notice is enqueued in the same transaction only if this call
/// consumed the code.
pub(crate) async fn consume_recovery_code(
    writer: &SqlitePool,
    tenant: TenantId,
    user: UserId,
    hash: &RecoveryCodeHash,
    now: OffsetDateTime,
    notice: Option<&NewEmail>,
) -> Result<bool, StorageError> {
    let code = hash.0.as_slice();
    let now_ms = odt_to_ms(now);
    let mut tx = writer.begin().await.map_err(map_err)?;
    let done = sqlx::query!(
        "UPDATE recovery_code SET used_at = ?4
          WHERE tenant_id = ?1 AND user_id = ?2 AND code_hash = ?3 AND used_at IS NULL",
        tenant.0,
        user.0,
        code,
        now_ms,
    )
    .execute(&mut *tx)
    .await
    .map_err(map_err)?;
    if done.rows_affected() != 1 {
        tx.rollback().await.map_err(map_err)?;
        return Ok(false);
    }
    if let Some(email) = notice {
        insert_email(&mut tx, tenant, email).await?;
    }
    tx.commit().await.map_err(map_err)?;
    Ok(true)
}

pub(crate) async fn recovery_codes_remaining(
    reader: &SqlitePool,
    tenant: TenantId,
    user: UserId,
) -> Result<u32, StorageError> {
    let row = sqlx::query!(
        r#"SELECT count(*) AS "n!: i64" FROM recovery_code
            WHERE tenant_id = ?1 AND user_id = ?2 AND used_at IS NULL"#,
        tenant.0,
        user.0,
    )
    .fetch_one(reader)
    .await
    .map_err(map_err)?;
    i64_to_u32(row.n, "recovery code count")
}
