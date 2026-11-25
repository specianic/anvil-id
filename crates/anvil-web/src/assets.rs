//! Embedded static theme assets served under `/assets/`.

use axum::body::Body;
use axum::extract::Path;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::http_cache::{if_none_match, strong_etag};

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

    let etag = strong_etag(&file.data);
    let etag_value = HeaderValue::from_str(&etag).expect("quoted hex is a valid header value");

    if if_none_match(&headers, &etag) {
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


#[cfg(test)]
mod tests {
    use super::*;


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
}
