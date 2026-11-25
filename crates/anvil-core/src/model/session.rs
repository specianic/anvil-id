//! Browser sessions.

use time::OffsetDateTime;

use super::ids::{SecretHash, SessionId, TenantId, UserId};

/// The single 0.1 authentication context class (password).
pub const ACR_PWD: &str = "urn:anvilid:acr:pwd";
/// RFC 8176 authentication method reference for a password.
pub const AMR_PWD: &str = "pwd";
/// Authentication context class for multi-factor or passkey sign-in.
pub const ACR_MFA: &str = "urn:anvilid:acr:mfa";
/// RFC 8176: proof of possession of a hardware-secured key (device-bound passkey).
pub const AMR_HWK: &str = "hwk";
/// RFC 8176: proof of possession of a software-secured key (synced / backup-eligible passkey).
pub const AMR_SWK: &str = "swk";
/// RFC 8176: user presence/verification test (passkey user verification).
pub const AMR_USER: &str = "user";
/// RFC 8176: one-time password (TOTP or recovery code).
pub const AMR_OTP: &str = "otp";
/// RFC 8176: multiple-factor authentication.
pub const AMR_MFA: &str = "mfa";
/// Federated sign-in through an upstream identity provider (not RFC 8176-registered; documented).
pub const AMR_FED: &str = "fed";

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
    /// Client IP at sign-in (shown on the sessions page).
    pub ip: Option<String>,
    /// User agent at sign-in, truncated.
    pub user_agent: Option<String>,
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
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}
