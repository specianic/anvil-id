//! One-time email sign-in codes (AUTH-06): generation, normalisation and peppered hashing.
//!
//! A code is 6 decimal digits drawn from the aws-lc-rs RNG by rejection sampling (no modulo
//! bias). Only a hash is stored: HMAC-SHA-256 keyed with a pepper derived from the KEK
//! (`Kek::derive_key("anvilid/email-otp/v1")`) over `flow_id || 0x00 || code`, so a code is bound
//! to the flow it was sent for and a database dump alone cannot be brute-forced offline over the
//! small code space. Same structure as [`crate::recovery_code::recovery_code_hash`].

use zeroize::Zeroizing;

use crate::encoding::random_bytes;
use crate::hmac::hmac_sha256;
use crate::kek::Kek;

/// HKDF info string for the email-code pepper.
pub const EMAIL_OTP_PEPPER_INFO: &str = "anvilid/email-otp/v1";
/// Digits in a code.
pub const EMAIL_CODE_LEN: usize = 6;
/// 10^6: number of distinct codes.
const SPACE: u32 = 1_000_000;
/// Largest multiple of `SPACE` that fits in a u32; samples at or above it are rejected.
const LIMIT: u32 = u32::MAX - (u32::MAX % SPACE);

/// A fresh 6-digit code (leading zeros kept).
#[must_use]
pub fn generate_email_code() -> Zeroizing<String> {
    loop {
        let raw = Zeroizing::new(random_bytes::<4>());
        let n = u32::from_be_bytes(*raw);
        if n < LIMIT {
            return Zeroizing::new(format!("{:06}", n % SPACE));
        }
    }
}

/// Normalise user input: drop ASCII whitespace, then require exactly 6 ASCII digits.
#[must_use]
pub fn normalize_email_code(input: &str) -> Option<String> {
    // Bound work on hostile input before allocating.
    if input.len() > 32 {
        return None;
    }
    let out: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    (out.len() == EMAIL_CODE_LEN && out.bytes().all(|b| b.is_ascii_digit())).then_some(out)
}

/// HMAC-SHA-256 of `flow_id || 0x00 || code` under the KEK-derived pepper. Deterministic, so the
/// stored hash can be compared; a different KEK or flow id gives a different hash.
#[must_use]
pub fn email_code_hash(kek: &Kek, flow_id: &str, code: &str) -> [u8; 32] {
    let pepper = kek.derive_key(EMAIL_OTP_PEPPER_INFO);
    hmac_sha256(
        pepper.as_ref(),
        &[flow_id.as_bytes(), &[0u8], code.as_bytes()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Independent oracle: aws-lc-rs directly, not crate::hmac_sha256.
    use aws_lc_rs::hmac;

    #[test]
    fn email_code_generation_is_six_digits() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let c = generate_email_code();
            assert_eq!(c.len(), EMAIL_CODE_LEN, "{}", c.as_str());
            assert!(c.bytes().all(|b| b.is_ascii_digit()));
            assert_eq!(normalize_email_code(&c).as_deref(), Some(c.as_str()));
            seen.insert(c.to_string());
        }
        // 2000 draws from 10^6 values: collisions are possible but rare.
        assert!(seen.len() > 1900);
        assert_eq!(LIMIT % SPACE, 0);
    }

    #[test]
    fn email_code_normalisation() {
        assert_eq!(normalize_email_code("123456").as_deref(), Some("123456"));
        assert_eq!(normalize_email_code(" 123 456 ").as_deref(), Some("123456"));
        assert_eq!(normalize_email_code("000000").as_deref(), Some("000000"));
        for bad in [
            "",
            "12345",
            "1234567",
            "12345a",
            "123-456",
            "１２３４５６", // full-width digits
            "12345\u{0663}",
            &"1".repeat(40),
        ] {
            assert_eq!(normalize_email_code(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn email_code_hash_is_bound_to_flow_and_kek() {
        let kek = Kek::from_bytes(&[1u8; 32]).unwrap();
        let other = Kek::from_bytes(&[2u8; 32]).unwrap();
        let h = email_code_hash(&kek, "flow-a", "123456");
        assert_eq!(h, email_code_hash(&kek, "flow-a", "123456"));
        assert_ne!(h, email_code_hash(&kek, "flow-b", "123456"));
        assert_ne!(h, email_code_hash(&other, "flow-a", "123456"));
        assert_ne!(h, email_code_hash(&kek, "flow-a", "123457"));
        // The separator prevents ambiguous concatenations.
        assert_ne!(
            email_code_hash(&kek, "flow-a1", "23456"),
            email_code_hash(&kek, "flow-a", "123456")
        );
        // HMAC under the documented derivation and input layout.
        let pepper = kek.derive_key("anvilid/email-otp/v1");
        let expected = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, pepper.as_ref()),
            b"flow-a\x00123456",
        );
        assert_eq!(h.as_slice(), expected.as_ref());
        // Distinct from the recovery-code pepper.
        assert_ne!(
            kek.derive_key(EMAIL_OTP_PEPPER_INFO).as_ref(),
            kek.derive_key(crate::recovery_code::RECOVERY_CODE_PEPPER_INFO)
                .as_ref()
        );
    }
}
