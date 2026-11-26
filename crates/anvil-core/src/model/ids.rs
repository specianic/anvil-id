//! Identifiers, secret hashes and pagination types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! v7_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// A new time-ordered (UUIDv7) id.
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

v7_id!(
    /// Identifier of a tenant (realm).
    TenantId
);
v7_id!(
    /// Identifier of a user.
    UserId
);
v7_id!(
    /// Row id of a client. The OAuth `client_id` is a separate string ([`super::Client::client_id`]).
    ClientId
);
v7_id!(
    /// Identifier of a signing key row (the JWK `kid` is a separate string).
    SigningKeyId
);
v7_id!(
    /// Identifier of a browser session.
    SessionId
);
v7_id!(
    /// Identifier of a self-service flow.
    FlowId
);
v7_id!(
    /// Identifier of a stored authorization request.
    AuthRequestId
);
v7_id!(
    /// Identifier of a token family (refresh rotation, reuse detection and revocation).
    TokenFamilyId
);
v7_id!(
    /// Identifier of an outbox email.
    OutboxId
);
v7_id!(
    /// Identifier of a credential row (password, passkey or TOTP). Generated before a TOTP seed
    /// is sealed, because the seal's AAD binds the id ([`super::credential_aad`]).
    CredentialId
);
v7_id!(
    /// Identifier of a consent grant.
    ConsentId
);
v7_id!(
    /// Identifier of an audit event. UUIDv7, so id order is time order (audit query cursor).
    AuditEventId
);

v7_id!(
    /// Identifier of an upstream identity-provider connection (social, OIDC, OAuth2).
    ConnectionId
);
v7_id!(
    /// Identifier of a link between a user and an upstream identity.
    IdentityLinkId
);
v7_id!(
    /// Identifier of a queued back-channel logout delivery.
    LogoutDeliveryId
);
v7_id!(
    /// Identifier of a tenant-scoped role (RBAC).
    RoleId
);
v7_id!(
    /// Identifier of a webhook endpoint.
    WebhookEndpointId
);
v7_id!(
    /// Identifier of a queued webhook delivery.
    WebhookDeliveryId
);
v7_id!(
    /// Identifier of an initial access token for dynamic client registration (RFC 7591 §3).
    InitialAccessTokenId
);
v7_id!(
    /// Identifier of an organization (a business customer inside a tenant).
    OrgId
);
v7_id!(
    /// Identifier of an organization invitation.
    OrgInvitationId
);
v7_id!(
    /// Identifier of a domain claimed by an organization (DNS TXT verification, home-realm
    /// discovery).
    OrgDomainId
);

/// SHA-256 hash of a secret (authorization code, refresh token, session cookie, flow CSRF token,
/// self-service token, setup token, client secret digest). Secrets are stored and looked up only
/// by hash. A hash is not a secret, so it derives `Debug`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretHash(pub [u8; 32]);

/// Hash of an authorization code.
pub type CodeHash = SecretHash;

/// A byte slice did not have the required length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid length: expected {expected} bytes, got {actual}")]
pub struct InvalidLength {
    pub expected: usize,
    pub actual: usize,
}

impl SecretHash {
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

impl From<[u8; 32]> for SecretHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Keyset pagination request. Callers clamp `limit` to `1..=200`
/// ([`PageRequest::clamped_limit`]); backends return items in UUIDv7 id order after `after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PageRequest {
    pub after: Option<Uuid>,
    pub limit: u32,
}

impl PageRequest {
    /// Largest page size.
    pub const MAX_LIMIT: u32 = 200;

    /// `limit` clamped to `1..=MAX_LIMIT`.
    pub fn clamped_limit(&self) -> u32 {
        self.limit.clamp(1, Self::MAX_LIMIT)
    }
}

/// One page of results in UUIDv7 id order. `next_cursor` is the id of the last item if and only
/// if at least one more item follows (backends fetch `limit + 1` rows); `None` on the last page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<Uuid>,
}

/// Generates `as_str()` / `parse()` for a fieldless enum with stable storage names.
macro_rules! str_enum {
    ($name:ident { $($variant:ident => $s:literal),+ $(,)? }) => {
        impl $name {
            /// Stable storage/wire name.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $s,)+
                }
            }

            /// Inverse of [`Self::as_str`]; `None` for unknown names.
            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $($s => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// Every variant.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}
pub(crate) use str_enum;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_new_v7_are_distinct_and_version_7() {
        let a = TenantId::new_v7();
        let b = TenantId::new_v7();
        assert_ne!(a, b);
        assert_eq!(a.0.get_version_num(), 7);
        assert_eq!(TokenFamilyId::new_v7().0.get_version_num(), 7);
        assert_eq!(UserId::new_v7().0.get_version_num(), 7);
        assert_eq!(OutboxId::new_v7().0.get_version_num(), 7);
        assert_eq!(CredentialId::new_v7().0.get_version_num(), 7);
        assert_eq!(ConsentId::new_v7().0.get_version_num(), 7);
        assert_eq!(AuditEventId::new_v7().0.get_version_num(), 7);
        assert_eq!(ConnectionId::new_v7().0.get_version_num(), 7);
        assert_eq!(IdentityLinkId::new_v7().0.get_version_num(), 7);
        assert_eq!(LogoutDeliveryId::new_v7().0.get_version_num(), 7);
        assert_eq!(RoleId::new_v7().0.get_version_num(), 7);
        assert_eq!(WebhookEndpointId::new_v7().0.get_version_num(), 7);
        assert_eq!(WebhookDeliveryId::new_v7().0.get_version_num(), 7);
        assert_eq!(InitialAccessTokenId::new_v7().0.get_version_num(), 7);
        assert_eq!(OrgId::new_v7().0.get_version_num(), 7);
        assert_eq!(OrgInvitationId::new_v7().0.get_version_num(), 7);
        assert_eq!(OrgDomainId::new_v7().0.get_version_num(), 7);
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

    #[test]
    fn page_request_clamps_limit() {
        let p = |limit| PageRequest { after: None, limit };
        assert_eq!(p(0).clamped_limit(), 1);
        assert_eq!(p(50).clamped_limit(), 50);
        assert_eq!(p(10_000).clamped_limit(), 200);
    }
}
