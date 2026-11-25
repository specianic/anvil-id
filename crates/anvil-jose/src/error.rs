//! Error type shared by every JOSE operation.
//!
//! Messages are static or bounded: nothing attacker-controlled is echoed in full, and no key
//! material ever appears in an error.

/// Errors from parsing, signing and verifying JOSE objects.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JoseError {
    /// Structurally invalid input (segments, base64url, JSON, size, forbidden members).
    #[error("malformed JOSE object: {0}")]
    Malformed(&'static str),
    /// The algorithm is unknown, not allowed in this context, or not supported for the key.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlg(String),
    /// No (single) key matches the token's kid / algorithm.
    #[error("unknown key")]
    UnknownKey,
    /// The signature does not verify.
    #[error("bad signature")]
    BadSignature,
    /// A claim or header value fails validation.
    #[error("invalid claim: {0}")]
    InvalidClaim(&'static str),
    /// The token has expired.
    #[error("token expired")]
    Expired,
    /// A cryptographic primitive failed (key generation, encryption, decryption, bad key bytes).
    #[error("crypto failure: {0}")]
    Crypto(&'static str),
}

impl JoseError {
    /// Build an [`JoseError::UnsupportedAlg`] from an untrusted value, bounded in length.
    pub(crate) fn unsupported_alg(alg: &str) -> Self {
        let bounded: String = alg.chars().take(32).collect();
        JoseError::UnsupportedAlg(bounded)
    }
}
