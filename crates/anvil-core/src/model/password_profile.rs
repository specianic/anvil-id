//! Tenant password hash profiles: parameter sets for verifying password hashes imported from
//! other systems (ADM-08), e.g. Firebase Authentication's modified scrypt.
//!
//! The Firebase signer key is a secret. It is stored only sealed with the KEK
//! ([`PasswordHashProfile::signer_key_sealed`]): purpose [`PROFILE_SIGNER_KEY_PURPOSE`], AAD
//! [`profile_signer_key_aad`] (tenant id bytes followed by profile id bytes). Sealing and
//! unsealing live in the profile service; the hasher receives the unsealed
//! [`HashProfileMaterial`], whose `Debug` never prints the key.

use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::ids::{TenantId, str_enum};

/// KEK purpose for a sealed hash-profile signer key (AAD = [`profile_signer_key_aad`]).
pub const PROFILE_SIGNER_KEY_PURPOSE: &str = "anvilid/password-profile-signer-key/v1";

/// AAD for a sealed signer key: the tenant id bytes followed by the profile id bytes, so a
/// sealed key copied to another profile or tenant does not open.
pub fn profile_signer_key_aad(tenant_id: TenantId, profile_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(tenant_id.0.as_bytes());
    aad.extend_from_slice(profile_id.as_bytes());
    aad
}

/// Hash algorithm family of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// Firebase Authentication's modified scrypt (signer key, salt separator, rounds, memory
    /// cost).
    FirebaseScrypt,
}

str_enum!(ProfileKind {
    FirebaseScrypt => "firebase_scrypt",
});

/// A stored hash profile. Only the sealed signer key is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHashProfile {
    pub id: Uuid,
    pub tenant_id: TenantId,
    /// Name unique per tenant, referenced by import records.
    pub name: String,
    pub kind: ProfileKind,
    pub salt_separator: Vec<u8>,
    pub rounds: u32,
    pub mem_cost: u8,
    /// `Kek::seal(PROFILE_SIGNER_KEY_PURPOSE, profile_signer_key_aad(..), signer key)`. A KEK
    /// blob, not a secret.
    pub signer_key_sealed: Vec<u8>,
    pub created_at: OffsetDateTime,
}

/// A hash profile to be stored. The caller seals the signer key before building it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasswordHashProfile {
    pub id: Uuid,
    pub name: String,
    pub kind: ProfileKind,
    pub salt_separator: Vec<u8>,
    pub rounds: u32,
    pub mem_cost: u8,
    /// See [`PasswordHashProfile::signer_key_sealed`].
    pub signer_key_sealed: Vec<u8>,
    pub created_at: OffsetDateTime,
}

/// Unsealed parameters handed to the password hasher to verify a legacy hash. The signer key is
/// zeroed on drop and redacted from `Debug`.
pub struct HashProfileMaterial {
    pub salt_separator: Vec<u8>,
    pub signer_key: SecretBox<[u8]>,
    pub rounds: u32,
    pub mem_cost: u8,
}

impl HashProfileMaterial {
    /// The raw signer key bytes (only for the hash computation).
    pub fn signer_key(&self) -> &[u8] {
        self.signer_key.expose_secret()
    }
}

impl std::fmt::Debug for HashProfileMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashProfileMaterial")
            .field("salt_separator", &self.salt_separator)
            .field("signer_key", &"[redacted]")
            .field("rounds", &self.rounds)
            .field("mem_cost", &self.mem_cost)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_profile_material_debug_redacts() {
        let m = HashProfileMaterial {
            salt_separator: vec![1, 2],
            signer_key: SecretBox::from(vec![0xAB_u8; 8].into_boxed_slice()),
            rounds: 8,
            mem_cost: 14,
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("[redacted]"), "{dbg}");
        assert!(!dbg.contains("171"), "{dbg}");
        assert!(!dbg.to_lowercase().contains("ab, ab"), "{dbg}");
        assert_eq!(m.signer_key(), &[0xAB_u8; 8]);
    }

    #[test]
    fn profile_kind_round_trips() {
        for k in ProfileKind::ALL {
            assert_eq!(ProfileKind::parse(k.as_str()), Some(*k));
        }
        assert_eq!(ProfileKind::parse("bcrypt"), None);
    }

    #[test]
    fn signer_key_aad_binds_tenant_and_profile() {
        let t = TenantId::new_v7();
        let p = Uuid::now_v7();
        let aad = profile_signer_key_aad(t, p);
        assert_eq!(aad.len(), 32);
        assert_eq!(&aad[..16], t.0.as_bytes());
        assert_eq!(&aad[16..], p.as_bytes());
        assert_ne!(aad, profile_signer_key_aad(t, Uuid::now_v7()));
    }
}
