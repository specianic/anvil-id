//! Signing keys.

use time::OffsetDateTime;

use super::ids::{SigningKeyId, TenantId, str_enum};

/// Lifecycle state of a signing key: `Next` (published, not yet signing), `Active` (signing,
/// at most one per tenant and algorithm), `Retired` (published until `expires_at`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyState {
    Next,
    Active,
    Retired,
}

str_enum!(KeyState {
    Next => "next",
    Active => "active",
    Retired => "retired",
});

/// A persisted signing key. The private key is sealed with the KEK (envelope encryption);
/// `public_jwk` is the public JWK JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKey {
    pub id: SigningKeyId,
    pub tenant_id: TenantId,
    pub kid: String,
    pub alg: String,
    pub state: KeyState,
    pub private_key_enc: Vec<u8>,
    pub public_jwk: String,
    pub created_at: OffsetDateTime,
    pub activated_at: Option<OffsetDateTime>,
    pub retired_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
}

/// A signing key to be stored.
#[derive(Clone, PartialEq, Eq)]
pub struct NewSigningKey {
    pub id: SigningKeyId,
    pub kid: String,
    pub alg: String,
    pub state: KeyState,
    pub private_key_enc: Vec<u8>,
    pub public_jwk: String,
    pub created_at: OffsetDateTime,
    pub activated_at: Option<OffsetDateTime>,
    pub retired_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
}

macro_rules! redacted_key_debug {
    ($name:ident { $($field:ident),+ }) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($field), &self.$field))+
                    .field("private_key_enc", &"<redacted>")
                    .finish()
            }
        }
    };
}

redacted_key_debug!(SigningKey {
    id,
    tenant_id,
    kid,
    alg,
    state,
    public_jwk,
    created_at,
    activated_at,
    retired_at,
    expires_at
});
redacted_key_debug!(NewSigningKey {
    id,
    kid,
    alg,
    state,
    public_jwk,
    created_at,
    activated_at,
    retired_at,
    expires_at
});

/// KEK envelope purpose for signing keys.
pub const SIGNING_KEY_PURPOSE: &str = "signing_key";

/// Additional authenticated data binding a sealed private key to its row:
/// `b"signing_key:{uuid}"`. Shared by the sealing (bootstrap) and opening (key service) sides.
pub fn signing_key_aad(id: SigningKeyId) -> Vec<u8> {
    format!("{SIGNING_KEY_PURPOSE}:{}", id.0).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn aad_format() {
        let id = SigningKeyId(Uuid::nil());
        assert_eq!(
            signing_key_aad(id),
            b"signing_key:00000000-0000-0000-0000-000000000000".to_vec()
        );
    }

    #[test]
    fn debug_redacts_private_key() {
        let k = NewSigningKey {
            id: SigningKeyId::new_v7(),
            kid: "k1".into(),
            alg: "RS256".into(),
            state: KeyState::Active,
            private_key_enc: b"TOPSECRET".to_vec(),
            public_jwk: "{}".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            activated_at: None,
            retired_at: None,
            expires_at: None,
        };
        let s = format!("{k:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("84, 79, 80")); // "TOP" as bytes
    }

    #[test]
    fn key_state_names_round_trip() {
        for v in KeyState::ALL {
            assert_eq!(KeyState::parse(v.as_str()), Some(*v));
        }
    }
}
