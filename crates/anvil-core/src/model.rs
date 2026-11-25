//! Domain model: identifiers and records shared by the protocol logic and the storage ports.
//!
//! Pure data. Callers generate identifiers and timestamps; repositories only persist them.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Identifier of a tenant (realm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub Uuid);

impl TenantId {
    /// A new time-ordered (UUIDv7) tenant id.
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

/// Identifier of a refresh-token family (used for reuse detection and revocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenFamilyId(pub Uuid);

impl TokenFamilyId {
    /// A new time-ordered (UUIDv7) token family id.
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

/// SHA-256 hash of an authorization code. Codes are stored and looked up only by hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeHash(pub [u8; 32]);

/// A byte slice did not have the required length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid length: expected {expected} bytes, got {actual}")]
pub struct InvalidLength {
    pub expected: usize,
    pub actual: usize,
}

impl CodeHash {
    /// Builds a hash from a slice, rejecting any slice that is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidLength> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| InvalidLength {
                expected: 32,
                actual: bytes.len(),
            })
    }

    /// The raw 32 hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for CodeHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A persisted tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: TenantId,
    pub slug: String,
    pub display_name: String,
    pub created_at: OffsetDateTime,
}

/// A tenant to be created. The caller generates the id and timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewTenant {
    pub id: TenantId,
    pub slug: String,
    pub display_name: String,
    pub created_at: OffsetDateTime,
}

/// An authorization code to be stored. The tenant is passed separately to the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuthorizationCode {
    pub code_hash: CodeHash,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub token_family_id: Option<TokenFamilyId>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// A stored authorization code, as returned when it is consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCode {
    pub tenant_id: TenantId,
    pub code_hash: CodeHash,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub token_family_id: Option<TokenFamilyId>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// Truncates a timestamp to whole milliseconds.
///
/// The storage contract is **millisecond precision**: SQLite stores timestamps as integer
/// milliseconds since the Unix epoch, while Postgres `timestamptz` keeps microseconds. Callers
/// truncate timestamps with this function before persisting them so a stored value round-trips
/// unchanged on every backend.
pub fn truncate_to_ms(t: OffsetDateTime) -> OffsetDateTime {
    let millis = t.millisecond();
    t.replace_millisecond(millis)
        .expect("a millisecond value read from a valid timestamp is always in range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn truncate_to_ms_drops_sub_millisecond_precision() {
        let t = datetime!(2026-11-25 12:00:00.123456789 UTC);
        assert_eq!(truncate_to_ms(t), datetime!(2026-11-25 12:00:00.123 UTC));
    }

    #[test]
    fn truncate_to_ms_keeps_whole_milliseconds_and_offset() {
        let t = datetime!(2026-11-25 12:00:00.5 +02:00);
        assert_eq!(truncate_to_ms(t), t);
        assert_eq!(truncate_to_ms(t).offset(), t.offset());
    }

    #[test]
    fn tenant_id_new_v7_is_distinct_and_version_7() {
        let a = TenantId::new_v7();
        let b = TenantId::new_v7();
        assert_ne!(a, b);
        assert_eq!(a.0.get_version_num(), 7);
        assert_eq!(b.0.get_version_num(), 7);
    }

    #[test]
    fn token_family_id_new_v7_is_version_7() {
        assert_eq!(TokenFamilyId::new_v7().0.get_version_num(), 7);
    }

    #[test]
    fn code_hash_round_trips_from_and_to_array() {
        let bytes = [7u8; 32];
        let h = CodeHash::from(bytes);
        assert_eq!(h.as_bytes(), &bytes);
        assert_eq!(CodeHash::from_slice(&bytes), Ok(h));
    }

    #[test]
    fn code_hash_from_slice_rejects_wrong_lengths() {
        for len in [0usize, 1, 31, 33, 64] {
            let v = vec![0u8; len];
            assert_eq!(
                CodeHash::from_slice(&v),
                Err(InvalidLength {
                    expected: 32,
                    actual: len
                }),
                "length {len} must be rejected"
            );
        }
    }
}
