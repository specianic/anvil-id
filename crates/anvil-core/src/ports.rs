//! Storage ports. Implemented by the `anvil-storage-*` crates; protocol logic and handlers use
//! them only through these traits.
//!
//! Only the operations the M0 spikes implement exist here. Further repositories and transactions
//! are added with the milestones that need them.

use time::OffsetDateTime;

use crate::model::{
    AuthorizationCode, CodeHash, NewAuthorizationCode, NewTenant, Tenant, TenantId, TokenFamilyId,
};

/// Entry point to all repositories of one storage backend.
pub trait Storage: Send + Sync + 'static {
    fn tenants(&self) -> &dyn TenantRepo;
    fn grants(&self) -> &dyn GrantRepo;
}

/// Tenant persistence.
#[async_trait::async_trait]
pub trait TenantRepo: Send + Sync {
    /// Persists a tenant. `Err(StorageError::Conflict)` on duplicate slug (enforced by a unique
    /// index; never check-then-insert).
    async fn create(&self, tenant: &NewTenant) -> Result<Tenant, StorageError>;

    async fn get(&self, id: TenantId) -> Result<Option<Tenant>, StorageError>;

    /// Tenant resolution: the only lookup that does not take a `TenantId`.
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, StorageError>;
}

/// Authorization grant persistence (authorization codes in M0).
#[async_trait::async_trait]
pub trait GrantRepo: Send + Sync {
    /// Stores a code for a tenant. `Err(StorageError::Conflict)` on duplicate `code_hash`.
    async fn create_code(
        &self,
        tenant: TenantId,
        code: &NewAuthorizationCode,
    ) -> Result<(), StorageError>;

    /// Atomically consumes a code: a single
    /// `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now RETURNING ...`.
    /// Exactly one concurrent caller can receive [`ConsumeOutcome::Consumed`].
    async fn consume_code(
        &self,
        tenant: TenantId,
        code_hash: &CodeHash,
        now: OffsetDateTime,
    ) -> Result<ConsumeOutcome, StorageError>;
}

/// Result of [`GrantRepo::consume_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// This call consumed the code.
    Consumed(AuthorizationCode),
    /// The code had already been consumed (replay). Carries the token family so callers can
    /// revoke tokens issued from it.
    AlreadyConsumed { family_id: Option<TokenFamilyId> },
    /// Unknown, expired, or belongs to another tenant. Callers map all of these to `invalid_grant`.
    NotFound,
}

/// Errors returned by storage backends.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A uniqueness constraint was violated.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Stored data could not be decoded into the domain model.
    #[error("corrupt stored data: {0}")]
    Corrupt(String),
    /// Any other backend failure (connection, I/O, driver error).
    #[error("storage backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}
