//! Per-algorithm OIDC token hashes (`at_hash`, `c_hash`; OIDC Core §3.1.3.6, §3.3.2.11).
//!
//! The hash is the left-most half of the digest the JWS algorithm uses: SHA-256 for RS256, PS256
//! and ES256; SHA-512 for Ed25519 (the digest Ed25519 is defined over, as for `EdDSA`).

use aws_lc_rs::digest;

use crate::encoding::b64url;
use crate::keys::Alg;

/// `at_hash` / `c_hash` of `value` for an ID token signed with `alg`, base64url without padding.
#[must_use]
pub fn token_hash(alg: Alg, value: &str) -> String {
    let (algorithm, half) = match alg {
        Alg::RS256 | Alg::PS256 | Alg::ES256 => (&digest::SHA256, 16),
        Alg::Ed25519 => (&digest::SHA512, 32),
    };
    let d = digest::digest(algorithm, value.as_bytes());
    b64url(&d.as_ref()[..half])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{at_hash, b64url_decode};

    #[test]
    fn sha256_family_left_128_bits() {
        // OpenID Connect Core 1.0 Appendix A.3 example access token and at_hash.
        let at = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
        for alg in [Alg::RS256, Alg::PS256, Alg::ES256] {
            assert_eq!(token_hash(alg, at), "77QmUPtjPfzWtF2AnpK9RQ");
            assert_eq!(token_hash(alg, "abc"), at_hash("abc"));
        }
    }

    #[test]
    fn ed25519_left_half_of_sha512() {
        // SHA-512("abc") = ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a ...
        let h = token_hash(Alg::Ed25519, "abc");
        let bytes = b64url_decode(&h).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(
            bytes[..16],
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31
            ]
        );
        let full = digest::digest(&digest::SHA512, b"abc");
        assert_eq!(bytes, full.as_ref()[..32]);
        assert_ne!(h, token_hash(Alg::RS256, "abc"));
    }
}
