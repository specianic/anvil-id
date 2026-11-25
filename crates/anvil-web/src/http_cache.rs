//! HTTP validator helpers shared by every handler that serves cacheable bodies (embedded theme
//! assets, the embedded console, the JWK Set): one strong-`ETag` format and one `If-None-Match`
//! evaluation.

use axum::http::{HeaderMap, header};

/// Quoted lowercase hex of a SHA-256 digest: the strong entity tag format used everywhere.
pub(crate) fn etag_from_digest(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tag = String::with_capacity(digest.len() * 2 + 2);
    tag.push('"');
    for &b in digest {
        tag.push(char::from(HEX[usize::from(b >> 4)]));
        tag.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    tag.push('"');
    tag
}

/// Strong entity tag of a body: quoted hex SHA-256 of `data`.
pub(crate) fn strong_etag(data: &[u8]) -> String {
    etag_from_digest(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data).as_ref())
}

/// `If-None-Match` evaluation (RFC 9110 §13.1.2): `*`, or any listed tag across all header
/// values that matches `etag` under the weak comparison the RFC prescribes for this header.
pub(crate) fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|c| c == "*" || c.strip_prefix("W/").unwrap_or(c) == etag)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn with(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(header::IF_NONE_MATCH, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn strong_etag_is_quoted_hex_sha256() {
        assert_eq!(
            strong_etag(b""),
            "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\""
        );
    }

    #[test]
    fn digest_etag_format() {
        let tag = etag_from_digest(&[0xab; 32]);
        assert_eq!(tag.len(), 66);
        assert!(tag.starts_with("\"abab") && tag.ends_with("ab\""));
    }

    #[test]
    fn weak_comparison_variants() {
        let tag = "\"abc\"";
        assert!(if_none_match(&with(&["\"abc\""]), tag));
        assert!(if_none_match(&with(&["W/\"abc\""]), tag));
        assert!(if_none_match(&with(&["\"x\", \"abc\""]), tag));
        assert!(if_none_match(&with(&["*"]), tag));
        assert!(!if_none_match(&with(&["\"abcd\""]), tag));
        assert!(!if_none_match(&with(&["\"abd\""]), tag));
        assert!(!if_none_match(&with(&["abc"]), tag));
        assert!(!if_none_match(&HeaderMap::new(), tag));
    }

    #[test]
    fn multiple_header_lines_are_all_considered() {
        assert!(if_none_match(&with(&["\"x\"", "\"abc\""]), "\"abc\""));
    }

    #[test]
    fn full_length_tags() {
        let tag = etag_from_digest(&[0xab; 32]);
        assert!(if_none_match(&with(&[&tag]), &tag));
        assert!(if_none_match(&with(&[&format!("W/{tag}")]), &tag));
        assert!(if_none_match(&with(&[&format!("\"x\", {tag}")]), &tag));
        assert!(!if_none_match(&with(&["\"abab\""]), &tag));
    }
}
