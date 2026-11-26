//! bcrypt verification of imported `$2a$` / `$2b$` / `$2y$` hashes (ADM-08).
//!
//! Primary source: the OpenBSD bcrypt algorithm as implemented and tested by Openwall
//! crypt_blowfish (test vectors in `wrapper.c`). The `bcrypt` crate does the EksBlowfish work and
//! its own constant-time (`subtle`) compare.
//!
//! - `$2a$`, `$2b$` and `$2y$` are the same algorithm for every password this crate can hash; they
//!   differ only in how historic C implementations treated 8-bit characters and length wrap-around.
//! - `$2x$` is crypt_blowfish's marker for hashes produced by the sign-extension bug (CVE-2011-2483).
//!   The crate accepts it, so it is refused here before the crate is called.
//! - Passwords longer than 72 bytes are truncated to 72 bytes, exactly like the source systems that
//!   produced these hashes (`bcrypt::verify`, not `non_truncating_verify`). After the first login the
//!   password is re-hashed with Argon2id over the full input.

use super::LegacyVerifyError;

/// Verifies `password` against a 60-character bcrypt MCF string.
///
/// # Errors
/// [`LegacyVerifyError::RefusedVariant`] for `$2x$`, [`LegacyVerifyError::InvalidParameters`] for a
/// cost outside 4..=31, [`LegacyVerifyError::Malformed`] for anything else that is not a bcrypt hash.
pub fn verify(password: &[u8], mcf: &str) -> Result<bool, LegacyVerifyError> {
    if mcf.starts_with("$2x$") {
        return Err(LegacyVerifyError::RefusedVariant);
    }
    match ::bcrypt::verify(password, mcf) {
        Ok(valid) => Ok(valid),
        Err(::bcrypt::BcryptError::CostNotAllowed(_)) => Err(LegacyVerifyError::InvalidParameters),
        Err(_) => Err(LegacyVerifyError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::verify;
    use crate::adapters::password::LegacyVerifyError;

    // Source: Openwall crypt_blowfish 1.3, wrapper.c test vectors ("U*U", cost 05, salt "CCC…").
    const OPENWALL_2A: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";

    #[test]
    fn bcrypt_openwall_vector_verifies() {
        assert_eq!(verify(b"U*U", OPENWALL_2A), Ok(true));
    }

    #[test]
    fn bcrypt_wrong_password_is_false() {
        assert_eq!(verify(b"U*V", OPENWALL_2A), Ok(false));
    }

    #[test]
    fn bcrypt_2b_and_2y_prefixes_are_the_same_algorithm() {
        let b = OPENWALL_2A.replacen("$2a$", "$2b$", 1);
        let y = OPENWALL_2A.replacen("$2a$", "$2y$", 1);
        assert_eq!(verify(b"U*U", &b), Ok(true));
        assert_eq!(verify(b"U*U", &y), Ok(true));
        assert_eq!(verify(b"U*V", &y), Ok(false));
    }

    #[test]
    fn bcrypt_refuses_2x_variant() {
        let x = OPENWALL_2A.replacen("$2a$", "$2x$", 1);
        assert_eq!(verify(b"U*U", &x), Err(LegacyVerifyError::RefusedVariant));
    }

    #[test]
    fn bcrypt_malformed_strings_are_rejected() {
        assert_eq!(
            verify(b"U*U", &OPENWALL_2A[..59]),
            Err(LegacyVerifyError::Malformed)
        );
        assert_eq!(verify(b"U*U", ""), Err(LegacyVerifyError::Malformed));
        let not_bcrypt = OPENWALL_2A.replacen("$2a$", "$1a$", 1);
        assert_eq!(
            verify(b"U*U", &not_bcrypt),
            Err(LegacyVerifyError::Malformed)
        );
    }

    #[test]
    fn bcrypt_cost_out_of_range_is_invalid_parameters() {
        let low = OPENWALL_2A.replacen("$05$", "$03$", 1);
        assert_eq!(
            verify(b"U*U", &low),
            Err(LegacyVerifyError::InvalidParameters)
        );
    }

    #[test]
    fn bcrypt_truncates_passwords_at_72_bytes_like_the_source_systems() {
        // Hash a 72-byte password at the minimum cost; any longer password sharing those 72 bytes
        // verifies too (documented behaviour, research Pitfall 3).
        let base = [b'a'; 72];
        let hash = ::bcrypt::hash_with_salt(base, 4, [7u8; 16])
            .expect("hash")
            .format_for_version(::bcrypt::Version::TwoB);
        assert_eq!(verify(&base, &hash), Ok(true));
        let mut longer = base.to_vec();
        longer.extend_from_slice(b"anything after byte 72");
        assert_eq!(verify(&longer, &hash), Ok(true));
        let mut changed = base;
        changed[71] = b'b';
        assert_eq!(verify(&changed, &hash), Ok(false));
    }
}
