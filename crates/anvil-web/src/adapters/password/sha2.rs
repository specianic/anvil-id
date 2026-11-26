//! Salted single-iteration SHA-256 / SHA-512 verification of imported hashes (ADM-08).
//!
//! Primary source: FIPS 180-4 (Secure Hash Standard); vectors are built from the FIPS 180-4 "abc"
//! examples by splitting "abc" into salt and password. Runs on aws-lc-rs (`aws_lc_rs::digest`).
//!
//! Salted SHA-2 is weak by nature (one iteration). It is accepted for import because the source
//! systems used it, flagged as weak by the import policy, and re-hashed with Argon2id at first login.

use aws_lc_rs::digest;
use zeroize::Zeroizing;

use super::{LegacyVerifyError, ct_eq};

/// The digest function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// Where the salt sits relative to the password in the hashed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaltPosition {
    /// `H(salt || password)`.
    Prefix,
    /// `H(password || salt)`.
    Suffix,
}

/// Verifies `password` against `H(salt || password)` or `H(password || salt)`.
///
/// # Errors
/// Never fails for well-typed input today; the `Result` keeps the verifier signatures uniform.
pub fn verify(
    alg: Digest,
    pos: SaltPosition,
    password: &[u8],
    salt: &[u8],
    expected: &[u8],
) -> Result<bool, LegacyVerifyError> {
    let algorithm = match alg {
        Digest::Sha256 => &digest::SHA256,
        Digest::Sha512 => &digest::SHA512,
    };
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + salt.len()));
    match pos {
        SaltPosition::Prefix => {
            input.extend_from_slice(salt);
            input.extend_from_slice(password);
        }
        SaltPosition::Suffix => {
            input.extend_from_slice(password);
            input.extend_from_slice(salt);
        }
    }
    let out = digest::digest(algorithm, &input);
    Ok(ct_eq(out.as_ref(), expected))
}

#[cfg(test)]
mod tests {
    use super::{Digest, SaltPosition, verify};
    use crate::adapters::password::test_util::{flip_last, hex};

    // Source: FIPS 180-4 examples (NIST CSRC "SHA256.pdf"/"SHA512.pdf"), message "abc".
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                              2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    #[test]
    fn sha256_prefix_and_suffix_vectors_verify() {
        let e = hex(SHA256_ABC);
        assert_eq!(
            verify(Digest::Sha256, SaltPosition::Prefix, b"bc", b"a", &e),
            Ok(true)
        );
        assert_eq!(
            verify(Digest::Sha256, SaltPosition::Suffix, b"ab", b"c", &e),
            Ok(true)
        );
    }

    #[test]
    fn sha512_prefix_and_suffix_vectors_verify() {
        let e = hex(SHA512_ABC);
        assert_eq!(
            verify(Digest::Sha512, SaltPosition::Prefix, b"bc", b"a", &e),
            Ok(true)
        );
        assert_eq!(
            verify(Digest::Sha512, SaltPosition::Suffix, b"ab", b"c", &e),
            Ok(true)
        );
    }

    #[test]
    fn sha2_swapped_salt_position_is_false() {
        let e256 = hex(SHA256_ABC);
        let e512 = hex(SHA512_ABC);
        assert_eq!(
            verify(Digest::Sha256, SaltPosition::Suffix, b"bc", b"a", &e256),
            Ok(false)
        );
        assert_eq!(
            verify(Digest::Sha256, SaltPosition::Prefix, b"ab", b"c", &e256),
            Ok(false)
        );
        assert_eq!(
            verify(Digest::Sha512, SaltPosition::Suffix, b"bc", b"a", &e512),
            Ok(false)
        );
        assert_eq!(
            verify(Digest::Sha512, SaltPosition::Prefix, b"ab", b"c", &e512),
            Ok(false)
        );
    }

    #[test]
    fn sha2_flipped_byte_and_wrong_digest_are_false() {
        let e256 = hex(SHA256_ABC);
        assert_eq!(
            verify(
                Digest::Sha256,
                SaltPosition::Prefix,
                b"bc",
                b"a",
                &flip_last(&e256)
            ),
            Ok(false)
        );
        assert_eq!(
            verify(Digest::Sha512, SaltPosition::Prefix, b"bc", b"a", &e256),
            Ok(false)
        );
        assert_eq!(
            verify(
                Digest::Sha256,
                SaltPosition::Prefix,
                b"bc",
                b"a",
                &e256[..31]
            ),
            Ok(false)
        );
    }
}
