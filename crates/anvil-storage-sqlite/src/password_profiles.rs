//! `PasswordProfileRepo` on SQLite (TRANSITIONAL(07-08) placeholder, replaced in task 2).

use anvil_core::model::{NewPasswordHashProfile, PasswordHashProfile, TenantId};
use anvil_core::ports::{PasswordProfileRepo, StorageError};
use sqlx::SqlitePool;

#[derive(Debug, Clone)]
pub(crate) struct SqlitePasswordProfiles {
    #[allow(dead_code)]
    pub(crate) writer: SqlitePool,
    #[allow(dead_code)]
    pub(crate) reader: SqlitePool,
}

#[async_trait::async_trait]
impl PasswordProfileRepo for SqlitePasswordProfiles {
    async fn create(
        &self,
        _tenant: TenantId,
        _profile: &NewPasswordHashProfile,
    ) -> Result<PasswordHashProfile, StorageError> {
        Err(StorageError::Unsupported("TRANSITIONAL(07-08): create"))
    }
    async fn get(
        &self,
        _tenant: TenantId,
        _id: uuid::Uuid,
    ) -> Result<Option<PasswordHashProfile>, StorageError> {
        Err(StorageError::Unsupported("TRANSITIONAL(07-08): get"))
    }
    async fn list(&self, _tenant: TenantId) -> Result<Vec<PasswordHashProfile>, StorageError> {
        Err(StorageError::Unsupported("TRANSITIONAL(07-08): list"))
    }
    async fn delete(&self, _tenant: TenantId, _id: uuid::Uuid) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported("TRANSITIONAL(07-08): delete"))
    }
    async fn count_references(
        &self,
        _tenant: TenantId,
        _id: uuid::Uuid,
    ) -> Result<u64, StorageError> {
        Err(StorageError::Unsupported(
            "TRANSITIONAL(07-08): count_references",
        ))
    }
}
