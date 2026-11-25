//! Embedded static theme assets served under `/assets/`.

use axum::body::Body;
use axum::extract::Path;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::Embed)]
#[folder = "../../themes/default/static/"]
struct Assets;

const CACHE_CONTROL: &str = "public, max-age=3600";

pub(crate) async fn handler(Path(path): Path<String>, headers: HeaderMap) -> Response {
    if !is_safe_path(&path) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(file) = Assets::get(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let etag = format!("\"{}\"", sha256_hex(&file.data));
    let etag_value = HeaderValue::from_str(&etag).expect("quoted hex is a valid header value");

    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| if_none_match_hits(v, &etag))
    {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag_value),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(CACHE_CONTROL),
                ),
            ],
        )
            .into_response();
    }

    let content_type = HeaderValue::from_str(file.metadata.mimetype())
        .unwrap_or(HeaderValue::from_static("application/octet-stream"));
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::ETAG, etag_value),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(CACHE_CONTROL),
            ),
        ],
        Body::from(file.data),
    )
        .into_response()
}

/// Defence in depth on top of rust-embed's own folder confinement: only plain relative segments are allowed.
fn is_safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Weak comparison as required for `If-None-Match` (RFC 9110 section 13.1.2).
fn if_none_match_hits(header: &str, etag: &str) -> bool {
    header.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut out = String::with_capacity(digest.as_ref().len() * 2);
    for &b in digest.as_ref() {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_of_empty_sha256() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rejects_unsafe_paths() {
        for p in [
            "",
            "..",
            "../x",
            "a/../b",
            "./a",
            "a//b",
            "a\\..\\b",
            "/etc/passwd",
        ] {
            assert!(!is_safe_path(p), "{p}");
        }
        assert!(is_safe_path("anvil.css"));
        assert!(is_safe_path("img/logo.svg"));
    }

    #[test]
    fn if_none_match_variants() {
        let etag = "\"abc\"";
        assert!(if_none_match_hits("\"abc\"", etag));
        assert!(if_none_match_hits("W/\"abc\"", etag));
        assert!(if_none_match_hits("\"x\", \"abc\"", etag));
        assert!(if_none_match_hits("*", etag));
        assert!(!if_none_match_hits("\"abcd\"", etag));
        assert!(!if_none_match_hits("abc", etag));
    }
}
