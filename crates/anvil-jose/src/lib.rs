//! JOSE (JWS/JWK/JWKS), signing keys, the KEK envelope and protocol hash helpers
//! (ARCHITECTURE.md §4, §8.1).
//!
//! - [`encoding`]: randomness, SHA-256, constant-time compare, strict base64url, `at_hash`.
//! - [`pkce`]: RFC 7636 S256 verification.
//! - [`kek`]: AES-256-GCM envelope with HKDF-derived per-purpose keys.
//! - [`jwk`]: public JWKs, JWK Sets, RFC 7638 thumbprints.
//! - [`keys`]: RS256 key generation and JWT signing.
//! - [`jws`]: strict compact-JWS parsing and signature verification against a JWK Set.
//! - [`client_assertion`]: `private_key_jwt` client assertion rules.
//! - [`op_token`]: verification of tokens this OP issued (access tokens, `id_token_hint`).
//!
//! Single crypto backend: aws-lc-rs (directly and through jsonwebtoken's `aws_lc_rs` feature).
//! This crate performs no I/O.

pub mod client_assertion;
pub mod encoding;
pub mod error;
pub mod jwk;
pub mod jws;
pub mod kek;
pub mod keys;
pub mod op_token;
pub mod pkce;

pub use client_assertion::{AssertionRules, VerifiedAssertion, verify_client_assertion};
pub use error::JoseError;
pub use jwk::{Jwk, Jwks, thumbprint};
pub use jws::{JoseHeader, VerifiedJwt, decode_header, verify_jwt};
pub use kek::Kek;
pub use keys::{Alg, GeneratedKey, SigningKey, generate_rs256};
pub use op_token::{ExpiryCheck, verify_op_token};
