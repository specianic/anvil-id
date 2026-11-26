//! THE HMAC-SHA-256 of the workspace (aws-lc-rs).
//!
//! Every keyed SHA-256 MAC in AnvilID goes through [`hmac_sha256`]: email-code and recovery-code
//! hashes, Standard Webhooks signatures and the shared rate limiter's Redis key names. One
//! implementation per concern (CLAUDE.md); no other crate computes HMAC.

use aws_lc_rs::hmac;

/// HMAC-SHA-256 of the concatenation of `parts` (in order) under `key`.
///
/// Feeding the message in parts is equivalent to one concatenated input; it only saves the
/// caller an allocation. Keys of any length are accepted (RFC 2104: longer than the block size
/// are hashed first).
#[must_use]
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    for part in parts {
        ctx.update(part);
    }
    let tag = ctx.sign();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_test_case_2() {
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want for nothing?"]);
        assert_eq!(
            hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_test_case_6() {
        // 131-byte key: longer than the SHA-256 block size, so it is hashed first.
        let key = [0xaau8; 131];
        let tag = hmac_sha256(
            &key,
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"],
        );
        assert_eq!(
            hex(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn multi_part_input_equals_the_concatenated_input() {
        let key = b"k";
        let whole = hmac_sha256(key, &[b"what do ya want for nothing?"]);
        assert_eq!(
            whole,
            hmac_sha256(key, &[b"what do ", b"", b"ya want", b" for nothing?"])
        );
        assert_eq!(
            whole,
            hmac_sha256(key, &[b"what do ya want for nothing?", b""])
        );
        assert_ne!(whole, hmac_sha256(key, &[b"what do ya want for nothing"]));
        assert_eq!(hmac_sha256(key, &[]), hmac_sha256(key, &[b""]));
    }
}
