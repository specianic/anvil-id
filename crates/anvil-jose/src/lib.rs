//! JOSE (JWS/JWK/JWKS), signing keys, the KEK envelope and protocol hash helpers
//! (ARCHITECTURE.md §4, §8.1).
//!
//! - [`encoding`]: randomness, SHA-256, constant-time compare, strict base64url, `at_hash`.
//! - [`pkce`]: RFC 7636 S256 verification.
//! - [`kek`]: AES-256-GCM envelope with HKDF-derived per-purpose keys.
//! - [`jwk`]: public JWKs, JWK Sets, RFC 7638 thumbprints.
//! - [`keys`]: RS256/ES256/Ed25519 key generation and JWT signing.
//! - [`hmac`]: THE HMAC-SHA-256 ([`hmac_sha256`]).
//! - [`hash`]: per-algorithm `at_hash`/`c_hash`.
//! - [`otp`]: TOTP secrets, `otpauth://` URIs and code checks (totp-rs).
//! - [`recovery_code`]: MFA recovery-code generation, normalisation and peppered hashing.
//! - [`email_code`]: one-time email sign-in codes and their flow-bound peppered hash.
//! - [`pem`]: THE PKCS#8 `PRIVATE KEY` PEM parser (Apple `.p8` keys).
//! - [`jws`]: strict compact-JWS parsing and signature verification against a JWK Set.
//! - [`client_assertion`]: `private_key_jwt` client assertion rules.
//! - [`op_token`]: verification of tokens this OP issued (access tokens, `id_token_hint`).
//! - [`webhook`]: Standard Webhooks v1 signatures and `whsec_` signing secrets.
//!
//! Single crypto backend: aws-lc-rs (directly and through jsonwebtoken's `aws_lc_rs` feature).
//! This crate performs no I/O.

pub mod client_assertion;
pub mod email_code;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod hmac;
pub mod jwk;
pub mod jws;
pub mod kek;
pub mod keys;
pub mod op_token;
pub mod otp;
pub mod pem;
pub mod pkce;
pub mod recovery_code;
pub mod webhook;

pub use client_assertion::{AssertionRules, VerifiedAssertion, verify_client_assertion};
pub use email_code::{
    EMAIL_OTP_PEPPER_INFO, email_code_hash, generate_email_code, normalize_email_code,
};
pub use error::JoseError;
pub use hash::token_hash;
pub use hmac::hmac_sha256;
pub use jwk::{Jwk, Jwks, thumbprint};
pub use jws::{JoseHeader, VerifiedJwt, decode_header, verify_jwt};
pub use kek::Kek;
pub use keys::{
    Alg, GeneratedKey, SigningKey, generate, generate_ed25519, generate_es256, generate_rs256,
};
pub use op_token::{ExpiryCheck, verify_op_token, verify_op_token_algs};
pub use otp::{TotpSecret, check_code, otpauth_uri};
pub use pem::pkcs8_der_from_pem;
pub use recovery_code::{generate_recovery_codes, normalize_recovery_code, recovery_code_hash};
pub use webhook::{generate_webhook_secret, parse_webhook_secret, signature_v1};
