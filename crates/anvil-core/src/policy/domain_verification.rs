//! DNS TXT domain verification record format (ORG-04).
//!
//! Follows draft-ietf-dnsop-domain-verification-techniques (BCP-intended, not yet an RFC): a
//! provider-specific underscore label and a provider-prefixed value carrying a random token.
//!
//! - Name: `_anvilid-challenge.{domain}.` (fully qualified, so resolvers never append search
//!   domains).
//! - Value: `anvilid-domain-verification={token}`, the token being 128 random bits encoded as
//!   RFC 4648 base32 without padding (26 characters).
//! - A TXT RRset verifies when any single record, its character-strings joined, equals the
//!   expected value exactly.
//!
//! Pure: randomness comes from the caller as bytes; the lookup is the `DomainTxtLookup` port.

/// Underscore label in front of the claimed domain.
pub const RECORD_LABEL: &str = "_anvilid-challenge";

/// Prefix of the TXT value.
pub const VALUE_PREFIX: &str = "anvilid-domain-verification=";

/// Length of an encoded token: 128 bits in 5-bit base32 characters.
pub const TOKEN_LEN: usize = 26;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The fully qualified record name for a normalised domain.
pub fn record_name(domain: &str) -> String {
    format!("{RECORD_LABEL}.{domain}.")
}

/// The TXT value an organization publishes for `token`.
pub fn record_value(token: &str) -> String {
    format!("{VALUE_PREFIX}{token}")
}

/// A new challenge token from 16 random bytes: RFC 4648 base32, no padding, 26 characters.
pub fn new_token(bytes: [u8; 16]) -> String {
    let mut out = String::with_capacity(TOKEN_LEN);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Inverse of [`new_token`]; `None` unless `token` is exactly 26 characters of the base32
/// alphabet with zero trailing bits (the canonical encoding).
pub fn token_bytes(token: &str) -> Option<[u8; 16]> {
    if token.len() != TOKEN_LEN {
        return None;
    }
    let mut out = [0u8; 16];
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut i = 0;
    for c in token.bytes() {
        let v = BASE32.iter().position(|a| *a == c)? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(i)? = ((buffer >> bits) & 0xFF) as u8;
            i += 1;
        }
    }
    // 26 * 5 = 130 bits: 2 trailing bits, which must be zero.
    if i != 16 || buffer & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// Whether a TXT RRset verifies: each record is its list of character-strings, joined before
/// comparing; any single record equal to `expected` byte for byte matches. A value split over
/// two records does not.
pub fn matches(records: &[Vec<Vec<u8>>], expected: &str) -> bool {
    records.iter().any(|rr| {
        let joined: Vec<u8> = rr.iter().flatten().copied().collect();
        joined == expected.as_bytes()
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn rr(parts: &[&str]) -> Vec<Vec<u8>> {
        parts.iter().map(|p| p.as_bytes().to_vec()).collect()
    }

    #[test]
    fn record_name_and_value() {
        assert_eq!(
            record_name("example.com"),
            "_anvilid-challenge.example.com."
        );
        assert_eq!(record_value("ABC"), "anvilid-domain-verification=ABC");
    }

    #[test]
    fn token_known_vectors() {
        assert_eq!(new_token([0; 16]), "AAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(new_token([0xFF; 16]), "77777777777777777777777774");
        // RFC 4648 §10 "foobar" prefix behaviour on the first bytes.
        let mut b = [0u8; 16];
        b[..6].copy_from_slice(b"foobar");
        assert!(new_token(b).starts_with("MZXW6YTBOI"));
    }

    #[test]
    fn token_bytes_refuses_non_canonical() {
        assert_eq!(token_bytes("AAAAAAAAAAAAAAAAAAAAAAAAAA"), Some([0; 16]));
        assert_eq!(
            token_bytes("AAAAAAAAAAAAAAAAAAAAAAAAAB"),
            None,
            "trailing bits set"
        );
        assert_eq!(token_bytes("aaaaaaaaaaaaaaaaaaaaaaaaaa"), None, "lowercase");
        assert_eq!(token_bytes("AAAAAAAAAAAAAAAAAAAAAAAAA"), None, "short");
        assert_eq!(token_bytes("AAAAAAAAAAAAAAAAAAAAAAAAA="), None, "padding");
        assert_eq!(token_bytes("AAAAAAAAAAAAAAAAAAAAAAAAA1"), None, "alphabet");
    }

    #[test]
    fn matches_an_exact_record() {
        let v = record_value("TOKEN");
        assert!(matches(&[rr(&[&v])], &v));
        assert!(
            matches(&[rr(&["v=spf1 -all"]), rr(&[&v])], &v),
            "any RR of the set"
        );
        assert!(
            matches(&[rr(&["anvilid-domain-", "verification=TOKEN"])], &v),
            "character-strings of one RR are joined"
        );
    }

    #[test]
    fn matches_refuses_near_misses() {
        let v = record_value("TOKEN");
        assert!(!matches(&[], &v), "empty RRset");
        assert!(!matches(&[rr(&[&format!("{v}X")])], &v), "suffix");
        assert!(!matches(&[rr(&[&format!("X{v}")])], &v), "prefix");
        assert!(!matches(&[rr(&[&format!(" {v}")])], &v), "whitespace");
        assert!(
            !matches(&[rr(&["anvilid-domain-verification=token"])], &v),
            "case"
        );
        assert!(
            !matches(&[rr(&["anvilid-domain-verification="])], &v),
            "empty token"
        );
        assert!(
            !matches(&[rr(&["anvilid-domain-"]), rr(&["verification=TOKEN"])], &v),
            "split over two RRs"
        );
    }

    proptest! {
        #[test]
        fn token_is_26_base32_chars_and_round_trips(bytes in any::<[u8; 16]>()) {
            let t = new_token(bytes);
            prop_assert_eq!(t.len(), TOKEN_LEN);
            prop_assert!(t.bytes().all(|c| BASE32.contains(&c)));
            prop_assert_eq!(token_bytes(&t), Some(bytes));
        }
    }
}
