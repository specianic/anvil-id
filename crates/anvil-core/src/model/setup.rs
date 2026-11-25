//! First-start installation and the setup token.

use time::OffsetDateTime;

use super::ids::{SecretHash, TenantId};
use super::key::NewSigningKey;
use super::tenant::NewTenant;

/// A one-time setup token (installation-wide, looked up by hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSetupToken {
    pub token_hash: SecretHash,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Everything first start writes, in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    pub tenants: Vec<NewTenant>,
    pub keys: Vec<(TenantId, NewSigningKey)>,
    pub setup_token: NewSetupToken,
}
