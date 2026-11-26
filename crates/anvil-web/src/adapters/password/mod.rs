//! Legacy password-hash verifiers for imported credentials (ADM-08).
//!
//! One pure, synchronous function per legacy scheme. They take primitive arguments (the dispatcher in
//! a later plan parses the stored `$anvil-…$` / MCF string and resolves hash profiles) and answer
//! "does this password match": `Ok(true)` / `Ok(false)`, or an error when the parameters cannot be
//! evaluated at all.
//!
//! - Every derived-versus-expected comparison is constant time (`subtle::ConstantTimeEq`, or the
//!   `bcrypt` crate's own `subtle` compare). Unequal lengths compare as "not equal".
//! - These functions do NOT apply the import caps and floors. The single implementation of those is
//!   `anvil_core::policy::password_import`; the dispatcher applies it before calling in here and runs
//!   the call inside the bounded hashing pool.
//! - Nothing here logs, formats or returns the password, the salt or the hash. [`LegacyVerifyError`]
//!   carries a reason code only.
//!
//! Crypto backends (ARCHITECTURE.md §2): PBKDF2, SHA-2 and the AES-256-CTR step of Firebase scrypt
//! run on aws-lc-rs. scrypt and bcrypt are the only RustCrypto primitives, a scoped
//! verification-only exception (deny.toml wrappers for `salsa20` and `blowfish`).

pub mod bcrypt;
pub mod firebase;
pub mod pbkdf2;
pub mod scrypt;
pub mod sha2;

/// Why a legacy hash could not be evaluated. Reason codes only, never input material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LegacyVerifyError {
    /// A cost/size parameter is outside what the algorithm can evaluate (e.g. scrypt `r = 0`).
    #[error("invalid_parameters")]
    InvalidParameters,
    /// The stored hash string is not well formed for its scheme.
    #[error("malformed_hash")]
    Malformed,
    /// A known but deliberately refused variant (bcrypt `$2x$`).
    #[error("refused_variant")]
    RefusedVariant,
}

/// Upper bound on the length of a stored derived key the KDF verifiers accept. Real schemes store
/// 16..=64 bytes; anything longer is not a password hash and would only make the KDF do more work.
pub(crate) const MAX_DERIVED_LEN: usize = 1024;

/// Constant-time equality; unequal lengths are "not equal" (the length is not secret).
pub(crate) fn ct_eq(derived: &[u8], expected: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    derived.ct_eq(expected).into()
}

#[cfg(test)]
pub(crate) mod test_util {
    /// Decodes a lowercase/uppercase hex string (test vectors only).
    pub(crate) fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// Returns a copy with the last byte flipped.
    pub(crate) fn flip_last(v: &[u8]) -> Vec<u8> {
        let mut out = v.to_vec();
        if let Some(b) = out.last_mut() {
            *b ^= 0x01;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::LegacyVerifyError;

    #[test]
    fn legacy_verify_error_debug_has_no_input() {
        let cases = [
            (
                LegacyVerifyError::InvalidParameters,
                "InvalidParameters",
                "invalid_parameters",
            ),
            (LegacyVerifyError::Malformed, "Malformed", "malformed_hash"),
            (
                LegacyVerifyError::RefusedVariant,
                "RefusedVariant",
                "refused_variant",
            ),
        ];
        for (err, debug, display) in cases {
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(err.to_string(), display);
        }
    }

    #[test]
    fn ct_eq_folds_length_into_the_result() {
        assert!(super::ct_eq(b"abc", b"abc"));
        assert!(!super::ct_eq(b"abc", b"abd"));
        assert!(!super::ct_eq(b"abc", b"ab"));
        assert!(!super::ct_eq(b"", b"a"));
    }
}
