//! Pushed authorization requests (RFC 9126).
//!
//! A client pushes its authorization parameters to the PAR endpoint and receives a one-time
//! `request_uri`. Only the SHA-256 hash of the `request_uri` is stored ([`RequestUriHash`]),
//! like authorization codes; the urn format lives with the PAR endpoint. A pushed request is
//! consumed once at the authorization endpoint.

use serde_json::Value;
use time::OffsetDateTime;

use super::ids::SecretHash;

/// SHA-256 hash of a pushed request's `request_uri` (32 bytes), the lookup key.
pub type RequestUriHash = SecretHash;

/// A pushed request to be stored. The caller hashes the `request_uri` and validates the
/// parameters before storing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPushedRequest {
    pub request_uri_hash: RequestUriHash,
    /// The OAuth `client_id` that pushed the request (authenticated at the PAR endpoint).
    pub client_id: String,
    /// The validated `AuthorizationParams` as JSON.
    pub params: Value,
    pub created_at: OffsetDateTime,
    /// RFC 9126 §2.2 `expires_in` deadline.
    pub expires_at: OffsetDateTime,
}

/// A stored pushed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedRequest {
    pub client_id: String,
    /// The validated `AuthorizationParams` as JSON.
    pub params: Value,
    pub expires_at: OffsetDateTime,
    /// Set when the authorization endpoint used the request; a consumed request is never
    /// accepted again.
    pub consumed_at: Option<OffsetDateTime>,
}

impl PushedRequest {
    /// Whether the request may still be used at `now`: not consumed and not expired.
    pub fn is_usable(&self, now: OffsetDateTime) -> bool {
        self.consumed_at.is_none() && now < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn pushed_request_usable_only_unconsumed_before_expiry() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let mut r = PushedRequest {
            client_id: "app".into(),
            params: serde_json::json!({"redirect_uri": "https://app.example/cb"}),
            expires_at: now + Duration::seconds(60),
            consumed_at: None,
        };
        assert!(r.is_usable(now));
        assert!(!r.is_usable(now + Duration::seconds(60)));
        r.consumed_at = Some(now);
        assert!(!r.is_usable(now));
    }

    #[test]
    fn request_uri_hash_is_32_bytes() {
        assert!(RequestUriHash::from_slice(&[0u8; 32]).is_ok());
        assert!(RequestUriHash::from_slice(&[0u8; 31]).is_err());
    }
}
