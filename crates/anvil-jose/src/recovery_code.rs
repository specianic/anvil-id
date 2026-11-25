//! MFA recovery codes: generation, normalisation and peppered hashing.
//!
//! A code is 16 RFC 4648 base32 characters (80 random bits from the aws-lc-rs RNG), shown as
//! `XXXX-XXXX-XXXX-XXXX`. Only a hash is stored: HMAC-SHA-256 keyed with a pepper derived from the
//! KEK (`Kek::derive_key("anvilid/recovery-code/v1")`), so a database dump alone cannot be used to
//! brute-force the 80-bit codes offline.
//!
//! Normalisation uppercases and strips whitespace and dashes. Lookalike characters are NOT mapped
//! (`0`, `1`, `8`, `9` are simply outside the base32 alphabet and rejected); users type what they
//! were shown.

use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::JoseError;
use crate::encoding::random_bytes;
use crate::kek::Kek;

/// HKDF info string for the recovery-code pepper.
pub const RECOVERY_CODE_PEPPER_INFO: &str = "anvilid/recovery-code/v1";
/// Characters in a normalised code.
pub const RECOVERY_CODE_LEN: usize = 16;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Upper bound on codes per call (recovery sets are small; this caps accidental huge requests).
const MAX_CODES: usize = 64;

/// 10 random bytes -> 16 base32 characters (5 bits each, no padding needed).
fn encode(bytes: &[u8; 10]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(RECOVERY_CODE_LEN));
    let mut acc: u16 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u16::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[usize::from((acc >> bits) & 0x1f)]));
        }
        acc &= (1 << bits) - 1;
    }
    out
}

fn display(normalized: &str) -> String {
    let mut s = String::with_capacity(RECOVERY_CODE_LEN + 3);
    for (i, c) in normalized.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            s.push('-');
        }
        s.push(c);
    }
    s
}

/// `n` distinct recovery codes formatted `XXXX-XXXX-XXXX-XXXX`. `n` must be 1..=64.
pub fn generate_recovery_codes(n: usize) -> Result<Vec<Zeroizing<String>>, JoseError> {
    if n == 0 || n > MAX_CODES {
        return Err(JoseError::Malformed("recovery code count must be 1 to 64"));
    }
    let mut codes: Vec<Zeroizing<String>> = Vec::with_capacity(n);
    while codes.len() < n {
        let raw = Zeroizing::new(random_bytes::<10>());
        let code = Zeroizing::new(display(&encode(&raw)));
        if !codes.iter().any(|c| **c == *code) {
            codes.push(code);
        }
    }
    Ok(codes)
}

/// Normalise user input: uppercase, drop ASCII whitespace and `-`, then require exactly 16
/// base32 characters.
pub fn normalize_recovery_code(input: &str) -> Result<Zeroizing<String>, JoseError> {
    // Bound work on hostile input before allocating.
    if input.len() > 64 {
        return Err(JoseError::Malformed("recovery code has the wrong length"));
    }
    let out: Zeroizing<String> = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    if out.len() != RECOVERY_CODE_LEN || out.chars().count() != RECOVERY_CODE_LEN {
        return Err(JoseError::Malformed("recovery code has the wrong length"));
    }
    if !out.bytes().all(|b| ALPHABET.contains(&b)) {
        return Err(JoseError::Malformed("recovery code has invalid characters"));
    }
    Ok(out)
}

/// HMAC-SHA-256 of a normalised code under the KEK-derived pepper. Deterministic, so the stored
/// hash can be looked up; a different KEK gives a different hash.
#[must_use]
pub fn recovery_code_hash(kek: &Kek, normalized: &str) -> [u8; 32] {
    let pepper = kek.derive_key(RECOVERY_CODE_PEPPER_INFO);
    let key = hmac::Key::new(hmac::HMAC_SHA256, pepper.as_ref());
    let tag = hmac::sign(&key, normalized.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_encoding_vector() {
        // RFC 4648 §10: BASE32("fooba") = "MZXW6YTB"; 10 bytes "foobafooba" -> 16 chars.
        assert_eq!(encode(b"foobafooba").as_str(), "MZXW6YTBMZXW6YTB");
        assert_eq!(encode(&[0u8; 10]).as_str(), "AAAAAAAAAAAAAAAA");
        assert_eq!(encode(&[0xff; 10]).as_str(), "7777777777777777");
    }

    #[test]
    fn generated_codes_are_distinct_and_formatted() {
        let codes = generate_recovery_codes(10).unwrap();
        assert_eq!(codes.len(), 10);
        for c in &codes {
            assert_eq!(c.len(), 19);
            let groups: Vec<&str> = c.split('-').collect();
            assert_eq!(groups.len(), 4);
            assert!(groups.iter().all(|g| g.len() == 4));
            assert!(c.bytes().all(|b| b == b'-' || ALPHABET.contains(&b)));
            assert_eq!(
                normalize_recovery_code(c).unwrap().as_str(),
                c.replace('-', "")
            );
        }
        let mut uniq: Vec<&str> = codes.iter().map(|c| c.as_str()).collect();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), 10);
        assert!(generate_recovery_codes(0).is_err());
        assert!(generate_recovery_codes(65).is_err());
    }

    #[test]
    fn normalisation() {
        let want = "ABCDEFGHIJKLMNOP";
        for input in [
            "ABCD-EFGH-IJKL-MNOP",
            "abcd-efgh-ijkl-mnop",
            " abcd efgh\tijkl-mnop ",
            "ABCDEFGHIJKLMNOP",
        ] {
            assert_eq!(
                normalize_recovery_code(input).unwrap().as_str(),
                want,
                "{input:?}"
            );
        }
        for bad in [
            "",
            "ABCD-EFGH-IJKL-MNO",
            "ABCD-EFGH-IJKL-MNOPQ",
            "ABCD-EFGH-IJKL-MN0P", // zero is not mapped to O
            "ABCD-EFGH-IJKL-MN1P",
            "ABCD_EFGH_IJKL_MNOP",
            "ÀBCD-EFGH-IJKL-MNOP",
            &"A".repeat(100),
        ] {
            assert!(normalize_recovery_code(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hash_is_peppered_with_the_kek() {
        let kek = Kek::from_bytes(&[1u8; 32]).unwrap();
        let other = Kek::from_bytes(&[2u8; 32]).unwrap();
        let code = "ABCDEFGHIJKLMNOP";
        let h = recovery_code_hash(&kek, code);
        assert_eq!(h, recovery_code_hash(&kek, code));
        assert_ne!(h, recovery_code_hash(&other, code));
        assert_ne!(h, recovery_code_hash(&kek, "ABCDEFGHIJKLMNOQ"));
        // HMAC under the documented derivation, not a bare hash.
        let pepper = kek.derive_key("anvilid/recovery-code/v1");
        let expected = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, pepper.as_ref()),
            code.as_bytes(),
        );
        assert_eq!(h.as_slice(), expected.as_ref());
        assert_ne!(h, crate::encoding::sha256(code.as_bytes()));
    }
}
