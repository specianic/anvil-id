//! PKCE (RFC 7636) S256 helpers. `plain` is never supported (RFC 9700 §2.1.1).

use crate::encoding::{b64url, ct_eq, sha256};

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// A valid S256 `code_challenge`: exactly 43 base64url characters (32 bytes, no padding).
#[must_use]
pub fn is_valid_challenge(c: &str) -> bool {
    c.len() == 43
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A valid `code_verifier` (RFC 7636 §4.1): 43..=128 characters of `[A-Za-z0-9-._~]`.
#[must_use]
pub fn is_valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len()) && v.bytes().all(is_unreserved)
}

/// `BASE64URL(SHA256(verifier)) == challenge`, with both inputs validated first and the final
/// comparison in constant time.
#[must_use]
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    if !is_valid_verifier(verifier) || !is_valid_challenge(challenge) {
        return false;
    }
    let computed = b64url(&sha256(verifier.as_bytes()));
    ct_eq(computed.as_bytes(), challenge.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn rfc7636_appendix_b_vector_verifies() {
        assert!(verify_s256(VERIFIER, CHALLENGE));
    }

    #[test]
    fn wrong_verifier_rejected() {
        let wrong = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl";
        assert!(!verify_s256(wrong, CHALLENGE));
    }

    #[test]
    fn verifier_length_bounds() {
        let v42 = "a".repeat(42);
        let v43 = "a".repeat(43);
        let v128 = "a".repeat(128);
        let v129 = "a".repeat(129);
        assert!(!is_valid_verifier(&v42));
        assert!(is_valid_verifier(&v43));
        assert!(is_valid_verifier(&v128));
        assert!(!is_valid_verifier(&v129));
        // Even if the challenge matched, out-of-range verifiers are rejected.
        let c42 = b64url(&sha256(v42.as_bytes()));
        let c129 = b64url(&sha256(v129.as_bytes()));
        assert!(!verify_s256(&v42, &c42));
        assert!(!verify_s256(&v129, &c129));
        let c43 = b64url(&sha256(v43.as_bytes()));
        assert!(verify_s256(&v43, &c43));
    }

    #[test]
    fn verifier_charset() {
        let plus = format!("{}+", "a".repeat(42));
        let slash = format!("{}/", "a".repeat(42));
        let space = format!("{} ", "a".repeat(42));
        assert!(!is_valid_verifier(&plus));
        assert!(!is_valid_verifier(&slash));
        assert!(!is_valid_verifier(&space));
        let c = b64url(&sha256(plus.as_bytes()));
        assert!(!verify_s256(&plus, &c));
        assert!(is_valid_verifier(&format!("{}-._~", "a".repeat(40))));
    }

    #[test]
    fn challenge_shape() {
        assert!(is_valid_challenge(CHALLENGE));
        assert!(!is_valid_challenge(&CHALLENGE[..42]));
        assert!(!is_valid_challenge(&format!("{CHALLENGE}A")));
        assert!(!is_valid_challenge(&format!("{}=", &CHALLENGE[..42])));
        assert!(!is_valid_challenge(&format!("{}+", &CHALLENGE[..42])));
        // A 44-char padded value is not accepted either.
        assert!(!is_valid_challenge(&format!("{CHALLENGE}=")));
        assert!(!verify_s256(VERIFIER, &format!("{CHALLENGE}=")));
    }
}
