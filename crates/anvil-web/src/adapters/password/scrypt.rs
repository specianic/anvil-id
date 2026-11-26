//! scrypt verification of imported hashes (ADM-08).
//!
//! Primary source: RFC 7914 (The scrypt Password-Based Key Derivation Function); test vectors from
//! §12. The memory-hard core comes from RustCrypto `scrypt` (`scrypt::scrypt`), the only RustCrypto
//! KDF in the graph besides bcrypt (ARCHITECTURE.md §2).
//!
//! The derived-key length follows the stored hash length (that is how scrypt hashes are stored), with
//! a floor of [`MIN_DERIVED_LEN`]: a stored hash shorter than that never verifies.

use zeroize::Zeroizing;

use super::{LegacyVerifyError, MAX_DERIVED_LEN, ct_eq};

/// Shortest stored scrypt output that can ever verify (128 bits).
pub const MIN_DERIVED_LEN: usize = 16;

/// Verifies `password` against an scrypt output with `N = 2^log_n`, block size `r` and
/// parallelism `p`.
///
/// # Errors
/// [`LegacyVerifyError::InvalidParameters`] if `log_n = 0`, `r = 0`, `p = 0`, `r·p ≥ 2^30`, the
/// memory size overflows, or `expected` is empty or longer than 1024 bytes.
pub fn verify(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    expected: &[u8],
) -> Result<bool, LegacyVerifyError> {
    let params = params(log_n, r, p)?;
    if expected.is_empty() || expected.len() > MAX_DERIVED_LEN {
        return Err(LegacyVerifyError::InvalidParameters);
    }
    let len = expected.len().max(MIN_DERIVED_LEN);
    let mut dk = Zeroizing::new(vec![0u8; len]);
    ::scrypt::scrypt(password, salt, &params, &mut dk)
        .map_err(|_| LegacyVerifyError::InvalidParameters)?;
    Ok(ct_eq(&dk, expected))
}

/// Validates scrypt parameters without panicking (the crate computes `r·p` in `u32`).
pub(crate) fn params(log_n: u8, r: u32, p: u32) -> Result<::scrypt::Params, LegacyVerifyError> {
    if log_n == 0 || r == 0 || p == 0 {
        return Err(LegacyVerifyError::InvalidParameters);
    }
    match r.checked_mul(p) {
        Some(rp) if rp < 0x4000_0000 => {}
        _ => return Err(LegacyVerifyError::InvalidParameters),
    }
    ::scrypt::Params::new(log_n, r, p).map_err(|_| LegacyVerifyError::InvalidParameters)
}

#[cfg(test)]
mod tests {
    use super::verify;
    use crate::adapters::password::LegacyVerifyError;
    use crate::adapters::password::test_util::{flip_last, hex};

    // Source: RFC 7914 §12, first vector: P = "", S = "", N = 16, r = 1, p = 1, dkLen = 64.
    const RFC7914_EMPTY: &str = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
                                 fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906";
    // Source: RFC 7914 §12, second vector: P = "password", S = "NaCl", N = 1024, r = 8, p = 16, dkLen = 64.
    const RFC7914_NACL: &str = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
                                2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";

    #[test]
    fn scrypt_rfc7914_empty_vector_verifies() {
        assert_eq!(verify(b"", b"", 4, 1, 1, &hex(RFC7914_EMPTY)), Ok(true));
    }

    #[test]
    fn scrypt_rfc7914_nacl_vector_verifies() {
        assert_eq!(
            verify(b"password", b"NaCl", 10, 8, 16, &hex(RFC7914_NACL)),
            Ok(true)
        );
    }

    #[test]
    fn scrypt_flipped_byte_is_false() {
        assert_eq!(
            verify(b"", b"", 4, 1, 1, &flip_last(&hex(RFC7914_EMPTY))),
            Ok(false)
        );
    }

    #[test]
    fn scrypt_wrong_password_is_false() {
        assert_eq!(verify(b"x", b"", 4, 1, 1, &hex(RFC7914_EMPTY)), Ok(false));
    }

    #[test]
    fn scrypt_stored_hash_below_floor_never_verifies() {
        let full = hex(RFC7914_EMPTY);
        assert_eq!(verify(b"", b"", 4, 1, 1, &full[..8]), Ok(false));
    }

    #[test]
    fn scrypt_invalid_parameters_are_rejected() {
        let e = hex(RFC7914_EMPTY);
        assert_eq!(
            verify(b"", b"", 0, 1, 1, &e),
            Err(LegacyVerifyError::InvalidParameters)
        );
        assert_eq!(
            verify(b"", b"", 4, 0, 1, &e),
            Err(LegacyVerifyError::InvalidParameters)
        );
        assert_eq!(
            verify(b"", b"", 4, 1, 0, &e),
            Err(LegacyVerifyError::InvalidParameters)
        );
        assert_eq!(
            verify(b"", b"", 4, u32::MAX, u32::MAX, &e),
            Err(LegacyVerifyError::InvalidParameters)
        );
        assert_eq!(
            verify(b"", b"", 4, 1, 1, &[]),
            Err(LegacyVerifyError::InvalidParameters)
        );
        assert_eq!(
            verify(b"", b"", 4, 1, 1, &vec![0u8; 1025]),
            Err(LegacyVerifyError::InvalidParameters)
        );
    }
}
