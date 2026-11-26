//! `PasswordProfileRepo` on Postgres: per-tenant legacy password hash profiles. The signer key is
//! stored KEK-sealed only (`signer_key_enc`); this module never sees it in clear.

use anvil_core::model::{NewPasswordHashProfile, PasswordHashProfile, ProfileKind, TenantId};
use anvil_core::ports::{PasswordProfileRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{enum_from, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgPasswordProfiles {
    pub(crate) pool: PgPool,
}

struct ProfileRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    kind: String,
    salt_separator: Vec<u8>,
    rounds: i64,
    mem_cost: i32,
    signer_key_enc: Vec<u8>,
    created_at: OffsetDateTime,
}

impl ProfileRow {
    fn into_model(self) -> Result<PasswordHashProfile, StorageError> {
        let rounds = u32::try_from(self.rounds).map_err(|_| {
            StorageError::Corrupt(format!(
                "password_hash_profile.rounds {} out of range",
                self.rounds
            ))
        })?;
        let mem_cost = u8::try_from(self.mem_cost).map_err(|_| {
            StorageError::Corrupt(format!(
                "password_hash_profile.mem_cost {} out of range",
                self.mem_cost
            ))
        })?;
        Ok(PasswordHashProfile {
            id: self.id,
            tenant_id: TenantId(self.tenant_id),
            name: self.name,
            kind: enum_from("password_hash_profile.kind", &self.kind, ProfileKind::parse)?,
            salt_separator: self.salt_separator,
            rounds,
            mem_cost,
            signer_key_sealed: self.signer_key_enc,
            created_at: self.created_at,
        })
    }
}

/// `$anvil-firebase-scrypt$profile=<id>$`, the PHC prefix of credentials that use the profile.
fn reference_prefix(id: Uuid) -> String {
    format!("$anvil-firebase-scrypt$profile={}$", id.hyphenated())
}

#[async_trait::async_trait]
impl PasswordProfileRepo for PgPasswordProfiles {
    async fn create(
        &self,
        tenant: TenantId,
        profile: &NewPasswordHashProfile,
    ) -> Result<PasswordHashProfile, StorageError> {
        // `Conflict` on a duplicate id or (tenant, name).
        sqlx::query!(
            "INSERT INTO password_hash_profile
                 (id, tenant_id, name, kind, salt_separator, rounds, mem_cost, signer_key_enc,
                  created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            profile.id,
            tenant.0,
            profile.name,
            profile.kind.as_str(),
            profile.salt_separator,
            i64::from(profile.rounds),
            i32::from(profile.mem_cost),
            profile.signer_key_sealed,
            profile.created_at,
        )
        .execute(&self.pool)
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
        id: Uuid,
    ) -> Result<Option<PasswordHashProfile>, StorageError> {
        sqlx::query_as!(
            ProfileRow,
            "SELECT id, tenant_id, name, kind, salt_separator, rounds, mem_cost, signer_key_enc,
                    created_at
               FROM password_hash_profile
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(ProfileRow::into_model)
        .transpose()
    }

    async fn list(&self, tenant: TenantId) -> Result<Vec<PasswordHashProfile>, StorageError> {
        sqlx::query_as!(
            ProfileRow,
            "SELECT id, tenant_id, name, kind, salt_separator, rounds, mem_cost, signer_key_enc,
                    created_at
               FROM password_hash_profile
              WHERE tenant_id = $1
              ORDER BY name COLLATE \"C\"",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(ProfileRow::into_model)
        .collect()
    }

    async fn delete(&self, tenant: TenantId, id: Uuid) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM password_hash_profile WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn count_references(&self, tenant: TenantId, id: Uuid) -> Result<u64, StorageError> {
        let prefix = reference_prefix(id);
        // Exact, case-sensitive prefix comparison (never LIKE: `_` and `%` are not wildcards
        // here).
        let count = sqlx::query_scalar!(
            r#"SELECT count(*) AS "count!" FROM credential
                WHERE tenant_id = $1 AND kind = 'password' AND starts_with(data, $2)"#,
            tenant.0,
            prefix,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        u64::try_from(count)
            .map_err(|_| StorageError::Corrupt(format!("negative reference count {count}")))
    }
}
