//! `PasswordProfileRepo` on SQLite: per-tenant legacy password hash profiles. The signer key is
//! stored KEK-sealed only (`signer_key_enc`); this module never sees it in clear.

use anvil_core::model::{NewPasswordHashProfile, PasswordHashProfile, ProfileKind, TenantId};
use anvil_core::ports::{PasswordProfileRepo, StorageError};
use sqlx::SqlitePool;

use crate::convert::{i64_to_u32, map_err, ms_to_odt, odt_to_ms, parse_enum};

#[derive(Debug, Clone)]
pub(crate) struct SqlitePasswordProfiles {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

/// Password credential kind (same value as `users::PASSWORD_KIND`).
const PASSWORD_KIND: &str = crate::users::PASSWORD_KIND;

struct ProfileRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    name: String,
    kind: String,
    salt_separator: Vec<u8>,
    rounds: i64,
    mem_cost: i64,
    signer_key_enc: Vec<u8>,
    created_at: i64,
}

impl TryFrom<ProfileRow> for PasswordHashProfile {
    type Error = StorageError;

    fn try_from(r: ProfileRow) -> Result<Self, StorageError> {
        let mem_cost = u8::try_from(r.mem_cost).map_err(|_| {
            StorageError::Corrupt(format!(
                "password_hash_profile.mem_cost {} out of range",
                r.mem_cost
            ))
        })?;
        Ok(PasswordHashProfile {
            id: r.id,
            tenant_id: TenantId(r.tenant_id),
            name: r.name,
            kind: parse_enum(&r.kind, ProfileKind::parse, "password_hash_profile.kind")?,
            salt_separator: r.salt_separator,
            rounds: i64_to_u32(r.rounds, "password_hash_profile.rounds")?,
            mem_cost,
            signer_key_sealed: r.signer_key_enc,
            created_at: ms_to_odt(r.created_at)?,
        })
    }
}

/// `$anvil-firebase-scrypt$profile=<id>$`, the PHC prefix of credentials that use the profile.
fn reference_prefix(id: uuid::Uuid) -> String {
    format!("$anvil-firebase-scrypt$profile={}$", id.hyphenated())
}

#[async_trait::async_trait]
impl PasswordProfileRepo for SqlitePasswordProfiles {
    async fn create(
        &self,
        tenant: TenantId,
        profile: &NewPasswordHashProfile,
    ) -> Result<PasswordHashProfile, StorageError> {
        let kind = profile.kind.as_str();
        let rounds = i64::from(profile.rounds);
        let mem_cost = i64::from(profile.mem_cost);
        let created_at = odt_to_ms(profile.created_at);
        sqlx::query!(
            "INSERT INTO password_hash_profile
                 (id, tenant_id, name, kind, salt_separator, rounds, mem_cost, signer_key_enc,
                  created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            profile.id,
            tenant.0,
            profile.name,
            kind,
            profile.salt_separator,
            rounds,
            mem_cost,
            profile.signer_key_sealed,
            created_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(PasswordHashProfile {
            id: profile.id,
            tenant_id: tenant,
            name: profile.name.clone(),
            kind: profile.kind,
            salt_separator: profile.salt_separator.clone(),
            rounds: profile.rounds,
            mem_cost: profile.mem_cost,
            signer_key_sealed: profile.signer_key_sealed.clone(),
            created_at: profile.created_at,
        })
    }

    async fn get(
        &self,
        tenant: TenantId,
        id: uuid::Uuid,
    ) -> Result<Option<PasswordHashProfile>, StorageError> {
        sqlx::query_as!(
            ProfileRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      name AS "name!", kind AS "kind!", salt_separator AS "salt_separator!",
                      rounds AS "rounds!", mem_cost AS "mem_cost!",
                      signer_key_enc AS "signer_key_enc!", created_at AS "created_at!"
                 FROM password_hash_profile WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            id,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(PasswordHashProfile::try_from)
        .transpose()
    }

    async fn list(&self, tenant: TenantId) -> Result<Vec<PasswordHashProfile>, StorageError> {
        sqlx::query_as!(
            ProfileRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      name AS "name!", kind AS "kind!", salt_separator AS "salt_separator!",
                      rounds AS "rounds!", mem_cost AS "mem_cost!",
                      signer_key_enc AS "signer_key_enc!", created_at AS "created_at!"
                 FROM password_hash_profile WHERE tenant_id = ?1
                ORDER BY name"#,
            tenant.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(PasswordHashProfile::try_from)
        .collect()
    }

    async fn delete(&self, tenant: TenantId, id: uuid::Uuid) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM password_hash_profile WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn count_references(
        &self,
        tenant: TenantId,
        id: uuid::Uuid,
    ) -> Result<u64, StorageError> {
        let prefix = reference_prefix(id);
        // Exact, case-sensitive prefix comparison (LIKE would be case-insensitive in SQLite).
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "count!: i64" FROM credential
                WHERE tenant_id = ?1 AND kind = ?2
                  AND substr(secret, 1, length(?3)) = ?3"#,
            tenant.0,
            PASSWORD_KIND,
            prefix,
        )
        .fetch_one(&self.reader)
        .await
        .map_err(map_err)?;
        u64::try_from(count)
            .map_err(|_| StorageError::Corrupt(format!("negative reference count {count}")))
    }
}
