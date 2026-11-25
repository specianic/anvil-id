//! Second-factor and passwordless credentials: passkeys (WebAuthn), TOTP and recovery codes.
//!
//! Passwords live in [`super::PasswordCredential`]. Secrets never appear here in plaintext: the
//! TOTP seed is sealed with the KEK ([`TOTP_SEED_PURPOSE`], AAD [`credential_aad`]), recovery
//! codes are stored as SHA-256 digests ([`RecoveryCodeHash`]) and a passkey holds public data
//! only.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::{CredentialId, UserId, str_enum};

/// KEK purpose for sealed TOTP seeds.
pub const TOTP_SEED_PURPOSE: &str = "anvilid/totp-seed/v1";

/// AAD for a sealed TOTP seed: `credential:{id}`. Generate the credential id before sealing.
pub fn credential_aad(id: CredentialId) -> Vec<u8> {
    format!("credential:{id}").into_bytes()
}

/// Kind of a credential row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    Webauthn,
    Totp,
}

str_enum!(CredentialKind {
    Password => "password",
    Webauthn => "webauthn",
    Totp => "totp",
});

/// A registered passkey. `passkey_json` is the serialised webauthn-rs `Passkey` (public key,
/// counter, flags; no private material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCredential {
    pub id: CredentialId,
    pub user_id: UserId,
    /// WebAuthn raw credential id (unique per tenant).
    pub credential_id: Vec<u8>,
    pub passkey_json: String,
    pub counter: u32,
    pub backup_eligible: bool,
    pub label: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

/// A passkey to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    pub id: CredentialId,
    pub credential_id: Vec<u8>,
    pub passkey_json: String,
    pub counter: u32,
    pub backup_eligible: bool,
    pub label: String,
    pub created_at: OffsetDateTime,
}

/// A TOTP credential. `secret_enc` is the seed sealed with the KEK; `last_step` is the last
/// accepted time step (replay protection, advanced with a compare-and-swap).
#[derive(Clone, PartialEq, Eq)]
pub struct TotpCredential {
    pub id: CredentialId,
    pub user_id: UserId,
    pub secret_enc: Vec<u8>,
    pub last_step: Option<u64>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for TotpCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpCredential")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("secret_enc", &"<redacted>")
            .field("last_step", &self.last_step)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

/// A TOTP credential to be stored (no step accepted yet).
#[derive(Clone, PartialEq, Eq)]
pub struct NewTotp {
    pub id: CredentialId,
    pub secret_enc: Vec<u8>,
    pub created_at: OffsetDateTime,
}

impl std::fmt::Debug for NewTotp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewTotp")
            .field("id", &self.id)
            .field("secret_enc", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// One credential as listed on the account page and in the admin API. No secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSummary {
    pub id: CredentialId,
    pub kind: CredentialKind,
    pub label: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

/// SHA-256 digest of a normalised recovery code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryCodeHash(pub [u8; 32]);

/// Result of a compare-and-swap on a monotonic counter (passkey signature counter, TOTP step).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterOutcome {
    /// The stored value moved forward to the presented one.
    Advanced,
    /// The presented value was not ahead of the stored one (replay or possible clone); nothing
    /// changed.
    Stale,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_round_trip() {
        for v in CredentialKind::ALL {
            assert_eq!(CredentialKind::parse(v.as_str()), Some(*v));
        }
        assert_eq!(
            CredentialKind::parse("webauthn"),
            Some(CredentialKind::Webauthn)
        );
    }

    #[test]
    fn aad_binds_the_id() {
        let a = CredentialId::new_v7();
        let b = CredentialId::new_v7();
        assert_eq!(credential_aad(a), format!("credential:{a}").into_bytes());
        assert_ne!(credential_aad(a), credential_aad(b));
    }

    #[test]
    fn totp_debug_redacts_the_sealed_seed() {
        let t = TotpCredential {
            id: CredentialId::new_v7(),
            user_id: UserId::new_v7(),
            secret_enc: vec![0xAB; 8],
            last_step: Some(1),
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("171"), "{dbg}");
    }
}
