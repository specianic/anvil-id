//! Firebase Authentication "modified scrypt" verification of imported hashes (ADM-08).
//!
//! Primary source: github.com/firebase/scrypt (`main.c`, `lib/scryptenc/scryptenc.c`); vectors from
//! its README and `tests/01-known-value.sh`. The algorithm:
//!
//! ```text
//! salt'  = user_salt || salt_separator
//! dk     = scrypt(password, salt', N = 2^mem_cost, r = rounds, p = 1, dkLen = 64)
//! hash   = AES-256-CTR(key = dk[0..32], counter block = 16 zero bytes) applied to signer_key
//! valid  = ct_eq(hash, stored_hash)
//! ```
//!
//! libcperciva's `crypto_aesctr` uses an 8-byte nonce (zero) followed by an 8-byte big-endian block
//! counter, which equals standard AES-CTR with a zero 128-bit IV for inputs under 2^64 blocks. The
//! AES step runs on aws-lc-rs (`DecryptingKey::ctr`; CTR decryption equals encryption); only the
//! scrypt step uses RustCrypto.

use aws_lc_rs::cipher::{AES_256, DecryptingKey, DecryptionContext, UnboundCipherKey};
use aws_lc_rs::iv::FixedLength;
use zeroize::Zeroizing;

use super::{LegacyVerifyError, MAX_DERIVED_LEN, ct_eq};

/// Verifies `password` against a Firebase scrypt hash, given the project's hash profile
/// (`salt_separator`, `signer_key`, `rounds`, `mem_cost`) and the user's salt.
///
/// # Errors
/// [`LegacyVerifyError::InvalidParameters`] for an empty or oversized signer key, `rounds = 0`,
/// `mem_cost = 0` or scrypt parameters the algorithm cannot evaluate.
pub fn verify(
    password: &[u8],
    salt: &[u8],
    salt_separator: &[u8],
    signer_key: &[u8],
    rounds: u32,
    mem_cost: u8,
    expected: &[u8],
) -> Result<bool, LegacyVerifyError> {
    if signer_key.is_empty() || signer_key.len() > MAX_DERIVED_LEN {
        return Err(LegacyVerifyError::InvalidParameters);
    }
    let params = super::scrypt::params(mem_cost, rounds, 1)?;

    let mut salted = Zeroizing::new(Vec::with_capacity(salt.len() + salt_separator.len()));
    salted.extend_from_slice(salt);
    salted.extend_from_slice(salt_separator);

    let mut dk = Zeroizing::new([0u8; 64]);
    ::scrypt::scrypt(password, &salted, &params, dk.as_mut_slice())
        .map_err(|_| LegacyVerifyError::InvalidParameters)?;

    let key = UnboundCipherKey::new(&AES_256, &dk[..32])
        .map_err(|_| LegacyVerifyError::InvalidParameters)?;
    let ctr = DecryptingKey::ctr(key).map_err(|_| LegacyVerifyError::InvalidParameters)?;
    let mut buf = Zeroizing::new(signer_key.to_vec());
    let hash = ctr
        .decrypt(
            &mut buf,
            DecryptionContext::Iv128(FixedLength::from([0u8; 16])),
        )
        .map_err(|_| LegacyVerifyError::InvalidParameters)?;
    Ok(ct_eq(hash, expected))
}

#[cfg(test)]
mod tests {
    use anvil_jose::encoding::b64std_decode;

    use super::verify;
    use crate::adapters::password::LegacyVerifyError;
    use crate::adapters::password::test_util::flip_last;

    // Source: firebase/scrypt README and tests/01-known-value.sh (published demo hash profile).
    const SIGNER_KEY: &str =
        "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    const SEPARATOR: &str = "Bw==";
    const ROUNDS: u32 = 8;
    const MEM_COST: u8 = 14;
    const SALT: &str = "42xEC+ixf3L2lw==";
    // Source: firebase/scrypt README, password "user1password".
    const USER1_HASH: &str =
        "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";
    // Source: firebase/scrypt tests/01-known-value.sh, password "hunter2".
    const HUNTER2_HASH: &str =
        "70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A==";

    fn d(s: &str) -> Vec<u8> {
        b64std_decode(s).expect("vector base64")
    }

    fn check(
        password: &[u8],
        separator: &[u8],
        expected: &[u8],
    ) -> Result<bool, LegacyVerifyError> {
        verify(
            password,
            &d(SALT),
            separator,
            &d(SIGNER_KEY),
            ROUNDS,
            MEM_COST,
            expected,
        )
    }

    #[test]
    fn firebase_readme_vector_verifies() {
        assert_eq!(
            check(b"user1password", &d(SEPARATOR), &d(USER1_HASH)),
            Ok(true)
        );
    }

    #[test]
    fn firebase_known_value_test_vector_verifies() {
        assert_eq!(check(b"hunter2", &d(SEPARATOR), &d(HUNTER2_HASH)), Ok(true));
    }

    #[test]
    fn firebase_wrong_password_is_false() {
        assert_eq!(
            check(b"hunter3", &d(SEPARATOR), &d(HUNTER2_HASH)),
            Ok(false)
        );
    }

    #[test]
    fn firebase_wrong_separator_is_false() {
        assert_eq!(check(b"hunter2", b"\x08", &d(HUNTER2_HASH)), Ok(false));
        assert_eq!(check(b"hunter2", b"", &d(HUNTER2_HASH)), Ok(false));
    }

    #[test]
    fn firebase_flipped_byte_is_false() {
        assert_eq!(
            check(b"hunter2", &d(SEPARATOR), &flip_last(&d(HUNTER2_HASH))),
            Ok(false)
        );
    }

    #[test]
    fn firebase_empty_signer_key_is_invalid_parameters() {
        let r = verify(
            b"hunter2",
            &d(SALT),
            &d(SEPARATOR),
            &[],
            ROUNDS,
            MEM_COST,
            &d(HUNTER2_HASH),
        );
        assert_eq!(r, Err(LegacyVerifyError::InvalidParameters));
    }

    #[test]
    fn firebase_zero_rounds_or_mem_cost_is_invalid_parameters() {
        let sk = d(SIGNER_KEY);
        let h = d(HUNTER2_HASH);
        assert_eq!(
            verify(b"hunter2", &d(SALT), &d(SEPARATOR), &sk, 0, MEM_COST, &h),
            Err(LegacyVerifyError::InvalidParameters)
        );
        assert_eq!(
            verify(b"hunter2", &d(SALT), &d(SEPARATOR), &sk, ROUNDS, 0, &h),
            Err(LegacyVerifyError::InvalidParameters)
        );
    }
}
