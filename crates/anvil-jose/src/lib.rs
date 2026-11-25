//! JOSE (JWS/JWK/JWKS), signing keys, the KEK envelope and protocol hash helpers
//! (ARCHITECTURE.md §4, §8.1).
//!
//! - [`encoding`]: randomness, SHA-256, constant-time compare, strict base64url, `at_hash`.
//! - [`pkce`]: RFC 7636 S256 verification.
//! - [`kek`]: AES-256-GCM envelope with HKDF-derived per-purpose keys.
//! - [`jwk`]: public JWKs, JWK Sets, RFC 7638 thumbprints.
//! - [`keys`]: RS256 key generation and JWT signing.
//!
//! Single crypto backend: aws-lc-rs (directly and through jsonwebtoken's `aws_lc_rs` feature).
//! This crate performs no I/O.

pub mod encoding;
pub mod error;
pub mod jwk;
pub mod kek;
pub mod keys;
pub mod pkce;

pub use error::JoseError;
pub use jwk::{Jwk, Jwks, thumbprint};
pub use kek::Kek;
pub use keys::{Alg, GeneratedKey, SigningKey, generate_rs256};
