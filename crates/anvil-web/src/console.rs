//! The admin console (`admin-ui/dist`) embedded in the binary and served at `/console/*`
//! (ARCHITECTURE §10.4).
//!
//! The console is installation-wide: it is mounted on the outer router, before tenant resolution,
//! on the same origin as the management API it calls.
//!
//! - Vite writes `.br`/`.gz` sidecars next to compressible files (`admin-ui/scripts/compress.mjs`).
//!   rust-embed's own `compression` feature does not negotiate, so `negotiate` picks the sidecar
//!   from `Accept-Encoding` here (`Content-Encoding` + `Vary: Accept-Encoding`).
//! - Hashed build output under `assets/` is immutable for a year; `index.html` and everything else
//!   is `no-cache`. The ETag is the quoted hex SHA-256 of the embedded file that is sent, so each
//!   encoding has its own validator; `If-None-Match` hits answer 304.
//! - Paths without a file extension fall back to `index.html` (client-side routing). Missing paths
//!   with an extension return 404 so a broken chunk load fails loudly instead of receiving HTML.
//! - When the console was not built (no Node at build time) the folder is missing, `cargo build`
//!   still succeeds (`allow_missing`) and every page shows a placeholder explaining how to build it.
//!   Release artifacts must contain the real console; CI enforces that, not `build.rs`.
//! - Every console response carries [`CONSOLE_CSP`]. The console needs no inline script or style
//!   (03-03), so `script-src` and `style-src` are both `'self'`.
//! - Before setup (no administrator yet) the index routes serve the server-rendered "Setup is not
//!   complete" page (`console_setup_pending.html`, naming `anvilid admin setup-url`) instead of
//!   the SPA or the placeholder: nobody can sign in yet. Assets are unaffected.

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

use crate::http_cache::{etag_from_digest, if_none_match};
use crate::root::console_setup_pending;
use crate::state::AppState;

#[derive(rust_embed::Embed)]
#[folder = "$CARGO_MANIFEST_DIR/../../admin-ui/dist"]
#[allow_missing = true]
struct ConsoleAssets;

/// Content-Security-Policy of every console response.
pub const CONSOLE_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
     connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'";

/// Cache-Control of content-hashed build output.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// Cache-Control of `index.html`, the placeholder and unhashed files: always revalidate.
pub const NO_CACHE: &str = "no-cache";

const INDEX: &str = "index.html";

/// Routes of the console, merged into the outer (installation-wide) router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/console", get(redirect_to_root))
        .route("/console/", get(root))
        .route("/console/{*path}", get(handler))
}

async fn redirect_to_root() -> Redirect {
    Redirect::permanent("/console/")
}

async fn root(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    serve(&state, String::new(), &headers, query.as_deref()).await
}

async fn handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    serve(&state, path, &headers, query.as_deref()).await
}

async fn serve(
    state: &AppState,
    path: String,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Response {
    let built = ConsoleAssets::get(INDEX).is_some();
    match resolve_path(&path, |p| ConsoleAssets::get(p).is_some()) {
        PathTarget::NotFound => not_found(),
        PathTarget::Index => match state.ui_bootstrap_service().setup_complete().await {
            Ok(true) if built => serve_file(INDEX, headers),
            Ok(true) => placeholder(),
            Ok(false) => setup_pending(state, headers, query),
            Err(e) => {
                tracing::error!(error = %e, "console: reading the setup state failed");
                server_error()
            }
        },
        PathTarget::Asset(p) => serve_file(&p, headers),
    }
}

/// The "Setup is not complete" page with the console's headers (CSP, `no-cache`).
fn setup_pending(state: &AppState, headers: &HeaderMap, query: Option<&str>) -> Response {
    let mut resp = console_setup_pending(state, headers, query);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONSOLE_CSP),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
    resp
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [
            csp(),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
        ],
        "internal server error",
    )
        .into_response()
}

/// What a request path below `/console/` maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathTarget {
    /// The SPA entry point (or the placeholder when the console was not built).
    Index,
    /// An embedded file.
    Asset(String),
    NotFound,
}

/// Path policy. `path` is the percent-decoded remainder after `/console/`, so encoded traversal
/// (`%2e%2e`, `%2f`) arrives here already decoded and is rejected by the segment check.
pub(crate) fn resolve_path(path: &str, exists: impl Fn(&str) -> bool) -> PathTarget {
    if path.is_empty() || path == INDEX {
        return PathTarget::Index;
    }
    let path = path.strip_suffix('/').unwrap_or(path);
    if !is_safe_path(path) {
        return PathTarget::NotFound;
    }
    if exists(path) {
        return PathTarget::Asset(path.to_owned());
    }
    let last = path.rsplit('/').next().unwrap_or(path);
    if last.contains('.') {
        PathTarget::NotFound
    } else {
        PathTarget::Index
    }
}

/// Only plain relative segments; no traversal, backslashes or control characters.
fn is_safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Cache policy: Vite's content-hashed output lives under `assets/`.
pub(crate) fn cache_control(path: &str) -> &'static str {
    if path.starts_with("assets/") {
        IMMUTABLE
    } else {
        NO_CACHE
    }
}

/// A content coding the client accepts and a sidecar exists for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Brotli,
    Gzip,
    Identity,
}

impl Encoding {
    fn suffix(self) -> &'static str {
        match self {
            Self::Brotli => ".br",
            Self::Gzip => ".gz",
            Self::Identity => "",
        }
    }

    fn token(self) -> Option<&'static str> {
        match self {
            Self::Brotli => Some("br"),
            Self::Gzip => Some("gzip"),
            Self::Identity => None,
        }
    }
}

/// Picks the best available encoding: `br` before `gzip`, each only if its sidecar exists and the
/// client accepts it with q > 0 (explicitly or through `*`); otherwise identity.
pub(crate) fn negotiate(has_br: bool, has_gzip: bool, accept_encoding: Option<&str>) -> Encoding {
    let Some(accept) = accept_encoding else {
        return Encoding::Identity;
    };
    if has_br && accepts(accept, "br") {
        Encoding::Brotli
    } else if has_gzip && accepts(accept, "gzip") {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

/// Whether `coding` has q > 0 in an `Accept-Encoding` value (RFC 9110 §12.5.3). An explicit entry
/// wins over `*`.
fn accepts(accept: &str, coding: &str) -> bool {
    let mut explicit = None;
    let mut wildcard = None;
    for item in accept.split(',') {
        let mut parts = item.split(';').map(str::trim);
        let name = parts.next().unwrap_or("");
        let q = parts
            .find_map(|p| {
                let (k, v) = p.split_once('=')?;
                k.trim()
                    .eq_ignore_ascii_case("q")
                    .then(|| v.trim().parse::<f32>().unwrap_or(0.0))
            })
            .unwrap_or(1.0);
        if name.eq_ignore_ascii_case(coding)
            || (coding == "gzip" && name.eq_ignore_ascii_case("x-gzip"))
        {
            explicit = Some(q);
        } else if name == "*" {
            wildcard = Some(q);
        }
    }
    explicit.or(wildcard).is_some_and(|q| q > 0.0)
}

fn csp() -> (header::HeaderName, HeaderValue) {
    (
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONSOLE_CSP),
    )
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [
            csp(),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
        ],
        "not found",
    )
        .into_response()
}

fn serve_file(path: &str, headers: &HeaderMap) -> Response {
    let Some(original) = ConsoleAssets::get(path) else {
        return not_found();
    };
    let accept = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok());
    let br = format!("{path}.br");
    let gz = format!("{path}.gz");
    let encoding = negotiate(
        ConsoleAssets::get(&br).is_some(),
        ConsoleAssets::get(&gz).is_some(),
        accept,
    );
    let file = match encoding {
        Encoding::Identity => original.clone(),
        coding => match ConsoleAssets::get(&format!("{path}{}", coding.suffix())) {
            Some(f) => f,
            None => return not_found(),
        },
    };

    let tag = etag_from_digest(&file.metadata.sha256_hash());
    let tag_value = HeaderValue::from_str(&tag).expect("quoted hex is a valid header value");
    let cache = HeaderValue::from_static(cache_control(path));
    let vary = HeaderValue::from_static("accept-encoding");

    if if_none_match(headers, &tag) {
        return (
            StatusCode::NOT_MODIFIED,
            [
                csp(),
                (header::ETAG, tag_value),
                (header::CACHE_CONTROL, cache),
                (header::VARY, vary),
            ],
        )
            .into_response();
    }

    let content_type = HeaderValue::from_str(original.metadata.mimetype())
        .unwrap_or(HeaderValue::from_static("application/octet-stream"));
    let mut resp = (
        StatusCode::OK,
        [
            csp(),
            (header::CONTENT_TYPE, content_type),
            (header::ETAG, tag_value),
            (header::CACHE_CONTROL, cache),
            (header::VARY, vary),
        ],
        Body::from(file.data),
    )
        .into_response();
    if let Some(token) = encoding.token() {
        resp.headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static(token));
    }
    resp
}

/// Shown at `/console/` when the binary was built without `admin-ui/dist`. Static HTML, no script,
/// no inline style (the theme stylesheet is same-origin).
pub(crate) const PLACEHOLDER_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>AnvilID console not built</title>
<link rel="stylesheet" href="/assets/anvil.css">
</head>
<body>
<main>
<h1>The admin console is not included in this build</h1>
<p>This binary was compiled without <code>admin-ui/dist</code>, usually because Node.js was not
available. Everything else works; only the web console is missing.</p>
<p>To include it, build the console (Node.js 22 or newer) and rebuild the binary:</p>
<pre><code>cd admin-ui &amp;&amp; npm ci &amp;&amp; npm run build
cd .. &amp;&amp; cargo build --release</code></pre>
<p>Release builds always contain the console.</p>
</main>
</body>
</html>
"#;

fn placeholder() -> Response {
    (
        StatusCode::OK,
        [
            csp(),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE)),
        ],
        PLACEHOLDER_HTML,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exists(p: &str) -> bool {
        matches!(p, "assets/app-abc123.js" | "favicon.svg")
    }

    #[test]
    fn path_policy() {
        assert_eq!(resolve_path("", exists), PathTarget::Index);
        assert_eq!(resolve_path("index.html", exists), PathTarget::Index);
        assert_eq!(resolve_path("users/123", exists), PathTarget::Index);
        assert_eq!(resolve_path("users/123/", exists), PathTarget::Index);
        assert_eq!(resolve_path("callback", exists), PathTarget::Index);
        assert_eq!(
            resolve_path("assets/app-abc123.js", exists),
            PathTarget::Asset("assets/app-abc123.js".into())
        );
        assert_eq!(
            resolve_path("favicon.svg", exists),
            PathTarget::Asset("favicon.svg".into())
        );
        assert_eq!(
            resolve_path("assets/app-missing.js", exists),
            PathTarget::NotFound
        );
        assert_eq!(resolve_path("robots.txt", exists), PathTarget::NotFound);
    }

    #[test]
    fn path_policy_rejects_traversal() {
        // Axum percent-decodes the wildcard, so `%2e%2e` and `%2f` arrive as `..` and `/`.
        for p in [
            "..",
            "../Cargo.toml",
            "assets/../../secret",
            "./index.html",
            "a//b",
            "a\\..\\b",
            "/etc/passwd",
            "assets/\0.js",
            "users/..",
        ] {
            assert_eq!(resolve_path(p, |_| true), PathTarget::NotFound, "{p:?}");
        }
    }

    #[test]
    fn cache_policy() {
        assert_eq!(cache_control("assets/app-abc123.js"), IMMUTABLE);
        assert_eq!(cache_control("assets/index-B650iFQZ.css"), IMMUTABLE);
        assert_eq!(cache_control("index.html"), NO_CACHE);
        assert_eq!(cache_control("favicon.svg"), NO_CACHE);
        assert_eq!(IMMUTABLE, "public, max-age=31536000, immutable");
    }

    #[test]
    fn negotiation() {
        use Encoding::*;
        assert_eq!(negotiate(true, true, None), Identity);
        assert_eq!(negotiate(true, true, Some("gzip, deflate, br")), Brotli);
        assert_eq!(negotiate(true, true, Some("br;q=0.1, gzip")), Brotli);
        assert_eq!(negotiate(true, true, Some("gzip")), Gzip);
        assert_eq!(negotiate(true, true, Some("x-gzip")), Gzip);
        assert_eq!(negotiate(false, true, Some("br, gzip")), Gzip);
        assert_eq!(negotiate(false, false, Some("br, gzip")), Identity);
        assert_eq!(negotiate(true, true, Some("br;q=0, gzip")), Gzip);
        assert_eq!(negotiate(true, true, Some("br;q=0, gzip;q=0.0")), Identity);
        assert_eq!(negotiate(true, true, Some("identity")), Identity);
        assert_eq!(negotiate(true, true, Some("*")), Brotli);
        assert_eq!(negotiate(true, true, Some("*;q=0")), Identity);
        assert_eq!(negotiate(true, true, Some("br;q=0, *")), Gzip);
        assert_eq!(negotiate(true, true, Some("BR")), Brotli);
        assert_eq!(negotiate(true, true, Some("br; q=0.000")), Identity);
    }

    #[test]
    fn csp_is_strict() {
        for d in [
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
        ] {
            assert!(CONSOLE_CSP.split("; ").any(|x| x == d), "{d}");
        }
        assert!(!CONSOLE_CSP.contains("unsafe"));
    }

    #[test]
    fn placeholder_explains_the_build_and_has_no_script_or_inline_style() {
        let html = PLACEHOLDER_HTML.to_ascii_lowercase();
        assert!(
            PLACEHOLDER_HTML.contains("cd admin-ui &amp;&amp; npm ci &amp;&amp; npm run build")
        );
        assert!(!html.contains("<script"));
        assert!(!html.contains("<style"));
        assert!(!html.contains("style="));
        assert!(!html.contains("http://") && !html.contains("https://"));
        let resp = placeholder();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_SECURITY_POLICY], CONSOLE_CSP);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], NO_CACHE);
    }
}
