//! PBKDF2-HMAC-SHA1/256/512 verification of imported hashes (ADM-08).
//!
//! Primary source: RFC 8018 §5.2 (PBKDF2). Test vectors: RFC 6070 (HMAC-SHA1; RFC 8018 has none)
//! and RFC 7914 §11 (HMAC-SHA256). Runs on aws-lc-rs (`aws_lc_rs::pbkdf2::derive`).
//!
//! The derived-key length is the stored hash length, with a floor of the PRF output size: a stored
//! hash shorter than the PRF output (e.g. a truncated SHA-1 value under 20 bytes) never verifies.

use std::num::NonZeroU32;

use aws_lc_rs::pbkdf2::{self as lc, Algorithm};
use zeroize::Zeroizing;

use super::{LegacyVerifyError, MAX_DERIVED_LEN, ct_eq};

/// The HMAC hash function used as the PBKDF2 PRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf {
    /// HMAC-SHA1 (Django `pbkdf2_sha1`, passlib, many older systems).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl Prf {
    fn algorithm(self) -> Algorithm {
        match self {
            Self::Sha1 => lc::PBKDF2_HMAC_SHA1,
            Self::Sha256 => lc::PBKDF2_HMAC_SHA256,
            Self::Sha512 => lc::PBKDF2_HMAC_SHA512,
        }
    }

    fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Verifies `password` against a PBKDF2 output.
///
/// # Errors
/// [`LegacyVerifyError::InvalidParameters`] if `iterations = 0` or `expected` is empty or longer than
/// 1024 bytes.
pub fn verify(
    prf: Prf,
    iterations: u32,
    password: &[u8],
    salt: &[u8],
    expected: &[u8],
) -> Result<bool, LegacyVerifyError> {
    let iterations = NonZeroU32::new(iterations).ok_or(LegacyVerifyError::InvalidParameters)?;
    if expected.is_empty() || expected.len() > MAX_DERIVED_LEN {
        return Err(LegacyVerifyError::InvalidParameters);
    }
    let len = expected.len().max(prf.output_len());
    let mut dk = Zeroizing::new(vec![0u8; len]);
    lc::derive(prf.algorithm(), iterations, salt, password, &mut dk);
    Ok(ct_eq(&dk, expected))
}

#[cfg(test)]
mod tests {
    use super::{Prf, verify};
    use crate::adapters::password::LegacyVerifyError;
    use crate::adapters::password::test_util::{flip_last, hex};

    // Source: RFC 6070 §2, P = "password", S = "salt", c = 1, dkLen = 20.
    const RFC6070_C1: &str = "0c60c80f961f0e71f3a9b524af6012062fe037a6";
    // Source: RFC 6070 §2, P = "password", S = "salt", c = 4096, dkLen = 20.
    const RFC6070_C4096: &str = "4b007901b765489abead49d926f721d065a429c1";
    // Source: RFC 7914 §11, PBKDF2-HMAC-SHA256, P = "passwd", S = "salt", c = 1, dkLen = 64.
    const RFC7914_SHA256: &str = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
                                  49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";

    #[test]
    fn pbkdf2_rfc6070_sha1_vectors_verify() {
        assert_eq!(
            verify(Prf::Sha1, 1, b"password", b"salt", &hex(RFC6070_C1)),
            Ok(true)
        );
        assert_eq!(
            verify(Prf::Sha1, 4096, b"password", b"salt", &hex(RFC6070_C4096)),
            Ok(true)
        );
    }

    #[test]
    fn pbkdf2_rfc7914_sha256_vector_verifies() {
        assert_eq!(
            verify(Prf::Sha256, 1, b"passwd", b"salt", &hex(RFC7914_SHA256)),
            Ok(true)
        );
    }

    #[test]
    fn pbkdf2_sha512_round_trip_against_aws_lc_derive() {
        // No primary-source SHA-512 vector in RFC 6070/7914; check the PRF wiring by deriving once.
        let mut dk = [0u8; 64];
        aws_lc_rs::pbkdf2::derive(
            aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA512,
            std::num::NonZeroU32::new(2).expect("nonzero"),
            b"saltsalt",
            b"pw",
            &mut dk,
        );
        assert_eq!(verify(Prf::Sha512, 2, b"pw", b"saltsalt", &dk), Ok(true));
        assert_eq!(verify(Prf::Sha256, 2, b"pw", b"saltsalt", &dk), Ok(false));
    }

    #[test]
    fn pbkdf2_flipped_byte_is_false() {
        assert_eq!(
            verify(
                Prf::Sha1,
                1,
                b"password",
                b"salt",
                &flip_last(&hex(RFC6070_C1))
            ),
            Ok(false)
        );
    }

    #[test]
    fn pbkdf2_truncated_expected_is_false() {
        let full = hex(RFC6070_C1);
        assert_eq!(
            verify(Prf::Sha1, 1, b"password", b"salt", &full[..19]),
            Ok(false)
        );
    }

    #[test]
    fn pbkdf2_wrong_iterations_or_prf_is_false() {
        assert_eq!(
            verify(Prf::Sha1, 2, b"password", b"salt", &hex(RFC6070_C1)),
            Ok(false)
        );
        assert_eq!(
            verify(Prf::Sha256, 1, b"password", b"salt", &hex(RFC6070_C1)),
            Ok(false)
        );
    }

    #[test]
    fn pbkdf2_zero_iterations_is_invalid_parameters() {
        assert_eq!(
            verify(Prf::Sha1, 0, b"password", b"salt", &hex(RFC6070_C1)),
            Err(LegacyVerifyError::InvalidParameters)
        );
        assert_eq!(
            verify(Prf::Sha1, 1, b"password", b"salt", &[]),
            Err(LegacyVerifyError::InvalidParameters)
        );
    }
}
