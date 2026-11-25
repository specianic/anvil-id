//! Users, standard claims and password credentials.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::{TenantId, UserId, str_enum};
use crate::error::CoreError;

/// OIDC Core §5.1.1 address claim.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Address {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

/// OIDC Core §5.1 standard claims other than `sub`, `email` and `email_verified` (those live on
/// [`User`]). Backends store this struct as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StandardClaims {
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
    pub address: Option<Address>,
}

/// Whether a user may sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Blocked,
}

str_enum!(UserStatus {
    Active => "active",
    Blocked => "blocked",
});

/// A persisted user. `email` is stored normalised ([`normalize_email`]) and is unique per tenant,
/// as is `username`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub tenant_id: TenantId,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub claims: StandardClaims,
    pub status: UserStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
}

/// A user to be created. `updated_at` starts equal to `created_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewUser {
    pub id: UserId,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub claims: StandardClaims,
    pub status: UserStatus,
    pub created_at: OffsetDateTime,
}

/// Partial user update; `None` leaves a field unchanged. `username: Some(None)` clears it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UserUpdate {
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<Option<String>>,
    pub claims: Option<StandardClaims>,
    pub status: Option<UserStatus>,
}

/// A user's password, as a PHC string (Argon2id).
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordCredential {
    pub user_id: UserId,
    pub phc: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl std::fmt::Debug for PasswordCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordCredential")
            .field("user_id", &self.user_id)
            .field("phc", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// A password credential to be stored with a new user.
#[derive(Clone, PartialEq, Eq)]
pub struct NewPasswordCredential {
    pub phc: String,
    pub created_at: OffsetDateTime,
}

impl std::fmt::Debug for NewPasswordCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewPasswordCredential")
            .field("phc", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Maximum email length (RFC 5321 path limit).
pub const MAX_EMAIL_LEN: usize = 254;

/// Normalises an email address for storage and lookup: trimmed and lowercased, exactly one `@`
/// with non-empty local and domain parts, no inner whitespace, at most 254 characters.
pub fn normalize_email(raw: &str) -> Result<String, CoreError> {
    let invalid = |message: &str| CoreError::Validation {
        field: "email",
        message: message.to_owned(),
    };
    let email = raw.trim().to_lowercase();
    if email.is_empty() {
        return Err(invalid("email is required"));
    }
    if email.chars().count() > MAX_EMAIL_LEN {
        return Err(invalid("email is too long"));
    }
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid("email must not contain whitespace"));
    }
    let mut parts = email.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) if !local.is_empty() && !domain.is_empty() => Ok(email),
        _ => Err(invalid("email must have the form local@domain")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(
            normalize_email(" Alice@Example.COM ").unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn normalize_email_rejects_bad_input() {
        let long = format!("{}@example.com", "a".repeat(250));
        for bad in [
            "",
            "   ",
            "a",
            "a@",
            "@b",
            "a@@b",
            "a@b@c",
            "a b@c",
            long.as_str(),
        ] {
            match normalize_email(bad) {
                Err(CoreError::Validation { field: "email", .. }) => {}
                other => panic!("{bad:?} must be rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn password_credential_debug_redacts_phc() {
        let c = PasswordCredential {
            user_id: UserId::new_v7(),
            phc: "$argon2id$secret".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(!format!("{c:?}").contains("argon2id"));
        let n = NewPasswordCredential {
            phc: "$argon2id$secret".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(!format!("{n:?}").contains("argon2id"));
    }
}
