//! Browser sessions.

use time::OffsetDateTime;

use super::ids::{SecretHash, SessionId, TenantId, UserId};

/// The single 0.1 authentication context class (password).
pub const ACR_PWD: &str = "urn:anvilid:acr:pwd";
/// RFC 8176 authentication method reference for a password.
pub const AMR_PWD: &str = "pwd";

/// A persisted browser session, looked up by the hash of its cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSession {
    pub id: SessionId,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub token_hash: SecretHash,
    pub auth_time: OffsetDateTime,
    pub acr: String,
    pub amr: Vec<String>,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub idle_expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

/// A browser session to be created. `last_seen_at` starts equal to `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBrowserSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: SecretHash,
    pub auth_time: OffsetDateTime,
    pub acr: String,
    pub amr: Vec<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub idle_expires_at: OffsetDateTime,
}
