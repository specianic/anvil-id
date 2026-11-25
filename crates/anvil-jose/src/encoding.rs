//! Randomness, hashing, constant-time comparison and strict base64url helpers.
//!
//! aws-lc-rs is the only RNG and digest implementation (ARCHITECTURE.md §2).

use aws_lc_rs::{digest, rand};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq as _;

use crate::JoseError;

/// `N` bytes from the system CSPRNG (aws-lc-rs).
///
/// # Panics
/// Panics if the operating system RNG fails. There is no safe way to continue without
/// randomness, and returning predictable bytes would be a vulnerability.
#[must_use]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::fill(&mut out).expect("system RNG failure");
    out
}

/// 32 random bytes, base64url without padding (43 characters). Used for codes, tokens and secrets.
#[must_use]
pub fn random_token() -> String {
    let bytes = zeroize::Zeroizing::new(random_bytes::<32>());
    b64url(bytes.as_ref())
}

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Storage key for a high-entropy secret (authorization code, token, client secret): SHA-256 of
/// the token bytes. Only this hash is persisted.
#[must_use]
pub fn secret_hash(token: &str) -> [u8; 32] {
    sha256(token.as_bytes())
}

/// Constant-time equality. Different lengths compare unequal (length is not secret).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// base64url without padding (RFC 7515 §2).
#[must_use]
pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Strict base64url decoding: rejects padding, the standard alphabet (`+`, `/`), whitespace and
/// non-canonical trailing bits.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, JoseError> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| JoseError::Malformed("invalid base64url"))
}

/// OIDC `at_hash`: left-most 128 bits of SHA-256 of the access token, base64url (RS256/ES256/PS256).
#[must_use]
pub fn at_hash(access_token: &str) -> String {
    let d = sha256(access_token.as_bytes());
    b64url(&d[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn random_token_shape() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_ne!(a, b);
        assert_eq!(b64url_decode(&a).unwrap().len(), 32);
    }

    #[test]
    fn sha256_known_vector() {
        // FIPS 180-2 "abc".
        assert_eq!(
            b64url(&sha256(b"abc")),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
        assert_eq!(secret_hash("abc"), sha256(b"abc"));
    }

    #[test]
    fn at_hash_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223 b00361a396177a9cb410ff61f20015ad;
        // left half base64url-encoded by hand.
        assert_eq!(at_hash("abc"), "ungWv48Bz-pBQUDeXa4iIw");
        // OpenID Connect Core 1.0 Appendix A.3 example access token and at_hash.
        assert_eq!(
            at_hash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"),
            "77QmUPtjPfzWtF2AnpK9RQ"
        );
    }

    #[test]
    fn b64url_decode_is_strict() {
        assert_eq!(b64url_decode("YWJj").unwrap(), b"abc");
        assert!(b64url_decode("YWI=").is_err(), "padding rejected");
        assert!(b64url_decode("YWI").is_ok());
        assert!(b64url_decode("+/8").is_err(), "standard alphabet rejected");
        assert!(b64url_decode("-_8").is_ok());
        assert!(b64url_decode("YW J").is_err(), "whitespace rejected");
        assert!(
            b64url_decode("YWJ").is_err(),
            "non-canonical trailing bits rejected"
        );
        assert!(
            b64url_decode("Zh").is_err(),
            "non-canonical trailing bits rejected"
        );
        assert!(
            b64url_decode("Zm9vY").is_err(),
            "impossible length rejected"
        );
        assert_eq!(b64url_decode("").unwrap(), b"");
        assert_eq!(b64url(b"\xfb\xff"), "-_8");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn ct_eq_behaviour() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    proptest! {
        #[test]
        fn b64url_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            prop_assert_eq!(b64url_decode(&b64url(&data)).unwrap(), data);
        }
    }
}
