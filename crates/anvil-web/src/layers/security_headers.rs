//! Security headers on every response (SEC-04, UI-01).
//!
//! The CSP deliberately has no `form-action`: Chromium applies it to the redirects that follow a
//! form POST, which would block the 303 → `/authorize/continue` → client `redirect_uri` chain.
//! Headers a handler already set are kept (e.g. the public `Cache-Control` of static assets).

use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::response::Response;

/// The Content-Security-Policy of every response. No `unsafe-inline`, no external sources; fonts only
/// from our origin (the default theme self-hosts its fonts under `/assets/fonts/`).
pub const CSP: &str = "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'";

/// HSTS value sent when the public URL is https.
pub const HSTS: &str = "max-age=31536000";

/// Whether HSTS is sent (the public URL is https).
#[derive(Debug, Clone, Copy)]
pub struct SecurityHeaders {
    pub hsts: bool,
}

fn set_default(headers: &mut HeaderMap, name: HeaderName, value: &'static str) {
    if !headers.contains_key(&name) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

/// Adds the security headers that are not already present.
pub fn apply_headers(headers: &mut HeaderMap, cfg: SecurityHeaders) {
    set_default(headers, header::CONTENT_SECURITY_POLICY, CSP);
    set_default(headers, header::REFERRER_POLICY, "no-referrer");
    set_default(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_default(headers, header::X_FRAME_OPTIONS, "DENY");
    set_default(headers, header::CACHE_CONTROL, "no-store");
    if cfg.hsts {
        set_default(headers, header::STRICT_TRANSPORT_SECURITY, HSTS);
    }
}

/// Response mapper for `axum::middleware::map_response_with_state`.
pub async fn security_headers(State(cfg): State<SecurityHeaders>, mut resp: Response) -> Response {
    apply_headers(resp.headers_mut(), cfg);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_is_strict() {
        assert_eq!(
            CSP,
            "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        );
        assert!(!CSP.contains("unsafe-inline"));
        assert!(!CSP.contains("unsafe-eval"));
        assert!(!CSP.contains("form-action"));
        assert!(CSP.contains("frame-ancestors 'none'"));
        // The self-hosted theme fonts load from our origin only.
        assert!(CSP.contains("font-src 'self';"));
        assert!(!CSP.contains("http:") && !CSP.contains("https:") && !CSP.contains('*'));
    }

    #[test]
    fn headers_with_and_without_hsts() {
        let mut h = HeaderMap::new();
        apply_headers(&mut h, SecurityHeaders { hsts: true });
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], CSP);
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert_eq!(h[header::STRICT_TRANSPORT_SECURITY], HSTS);

        let mut h = HeaderMap::new();
        apply_headers(&mut h, SecurityHeaders { hsts: false });
        assert!(h.get(header::STRICT_TRANSPORT_SECURITY).is_none());
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], CSP);
    }

    #[test]
    fn existing_cache_control_is_kept() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=3600"),
        );
        apply_headers(&mut h, SecurityHeaders { hsts: false });
        assert_eq!(h[header::CACHE_CONTROL], "public, max-age=3600");
    }
}
