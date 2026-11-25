//! The admin console served from the binary at `/console/*` (ADM-04, ARCHITECTURE §10.4).
//!
//! These tests pass with and without a console build. Debug builds read `admin-ui/dist` from disk
//! (rust-embed without `debug-embed`), so whether the real console is served depends on whether
//! `cd admin-ui && npm run build` has been run. HTML assertions accept the placeholder or the real
//! index; the asset assertions (negotiation, caching, 304, missing chunk) run only when the real
//! `index.html` is served, using the hashed asset names it references.
//! Selected backend via `ANVILID_TEST_DB`.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use support::{TestApp, TestResponse};

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'";
const PLACEHOLDER_MARKER: &str = "The admin console is not included in this build";

async fn get_with(app: &TestApp, path: &str, headers: &[(&str, &str)]) -> TestResponse {
    let mut req = Request::get(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    app.send(req.body(Body::empty()).expect("request")).await
}

/// Whether `/console/` served the real build (`true`) or the placeholder (`false`).
fn assert_console_html(name: &str, resp: &TestResponse) -> bool {
    assert_eq!(resp.status, StatusCode::OK, "{name}");
    assert_eq!(resp.header("content-security-policy"), Some(CSP), "{name}");
    assert!(
        resp.header("content-type")
            .is_some_and(|c| c.starts_with("text/html")),
        "{name}"
    );
    assert_eq!(resp.header("cache-control"), Some("no-cache"), "{name}");
    assert_eq!(resp.header("x-frame-options"), Some("DENY"), "{name}");
    assert_eq!(
        resp.header("x-content-type-options"),
        Some("nosniff"),
        "{name}"
    );
    // The index may be served brotli/gzip encoded only when asked; these requests do not ask.
    assert!(resp.header("content-encoding").is_none(), "{name}");
    let html = resp.text();
    if html.contains(PLACEHOLDER_MARKER) {
        assert!(html.contains("npm ci &amp;&amp; npm run build"), "{name}");
        assert!(!html.to_ascii_lowercase().contains("<script"), "{name}");
        false
    } else {
        assert!(html.contains("<div id=\"root\">"), "{name}: {html}");
        assert!(resp.header("etag").is_some(), "{name}");
        // Only external, same-origin scripts (the CSP has no 'unsafe-inline').
        assert!(!html.contains("<script>"), "{name}");
        assert!(html.contains("src=\"/console/assets/"), "{name}");
        true
    }
}

/// First `/console/assets/….js` referenced by the index.
fn entry_script(html: &str) -> String {
    let start = html.find("src=\"/console/assets/").expect("entry script") + "src=\"".len();
    let end = start + html[start..].find('"').expect("closing quote");
    html[start..end].to_owned()
}

#[tokio::test]
async fn bare_console_redirects_to_trailing_slash() {
    let app = TestApp::new().await;
    let resp = app.get("/console").await;
    assert_eq!(resp.status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(resp.header("location"), Some("/console/"));
}

#[tokio::test]
async fn console_root_and_deep_links_serve_the_index_or_placeholder() {
    let app = TestApp::new().await;
    let root = app.get("/console/").await;
    let built = assert_console_html("/console/", &root);

    for path in [
        "/console/users/123",
        "/console/clients/abc/",
        "/console/callback?code=x&state=y",
        "/console/index.html",
    ] {
        let resp = app.get(path).await;
        assert_eq!(assert_console_html(path, &resp), built, "{path}");
        assert_eq!(resp.body, root.body, "{path}: same document as /console/");
    }
}

#[tokio::test]
async fn console_works_before_installation() {
    // Installation-wide and outside tenant resolution: no tenant needed.
    let app = TestApp::uninstalled().await;
    let resp = app.get("/console/").await;
    assert_console_html("uninstalled /console/", &resp);
}

#[tokio::test]
async fn console_is_not_tenant_scoped() {
    let app = TestApp::new().await;
    let resp = app.get("/t/system/console/").await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_ne!(resp.header("content-security-policy"), Some(CSP));
    assert!(!resp.text().contains(PLACEHOLDER_MARKER));
    assert!(!resp.text().contains("<div id=\"root\">"));
}

#[tokio::test]
async fn missing_files_and_traversal_are_404() {
    let app = TestApp::new().await;
    for path in [
        "/console/assets/does-not-exist-abc123.js",
        "/console/assets/missing.css",
        "/console/favicon-missing.ico",
        "/console/%2e%2e/Cargo.toml",
        "/console/assets/%2e%2e/%2e%2e/Cargo.toml",
        "/console/..%2f..%2fCargo.toml",
        "/console/assets%5c..%5cindex.html",
    ] {
        let resp = app.get(path).await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND, "{path}");
        assert!(!resp.text().contains("<div id=\"root\">"), "{path}");
        assert!(!resp.text().contains("[package]"), "{path}");
    }
}

#[tokio::test]
async fn hashed_assets_are_negotiated_cached_and_revalidated() {
    let app = TestApp::new().await;
    let index = app.get("/console/").await;
    if !assert_console_html("/console/", &index) {
        // Placeholder build: no assets to check (run `cd admin-ui && npm run build` to cover them).
        return;
    }
    let script = entry_script(&index.text());

    let plain = app.get(&script).await;
    assert_eq!(plain.status, StatusCode::OK);
    assert!(
        plain
            .header("content-type")
            .is_some_and(|c| c.contains("javascript")),
        "{:?}",
        plain.header("content-type")
    );
    assert_eq!(
        plain.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(plain.header("vary"), Some("accept-encoding"));
    assert_eq!(plain.header("content-security-policy"), Some(CSP));
    assert!(plain.header("content-encoding").is_none());
    let plain_etag = plain.header("etag").expect("etag").to_owned();
    assert!(plain_etag.starts_with('"') && plain_etag.len() == 66);

    // The entry chunk is far above the 1 KiB sidecar threshold, so .br and .gz exist.
    let br = get_with(&app, &script, &[("accept-encoding", "gzip, deflate, br")]).await;
    assert_eq!(br.status, StatusCode::OK);
    assert_eq!(br.header("content-encoding"), Some("br"));
    assert_eq!(br.header("vary"), Some("accept-encoding"));
    assert!(
        br.header("content-type")
            .is_some_and(|c| c.contains("javascript"))
    );
    assert!(br.body.len() < plain.body.len());
    let br_etag = br.header("etag").expect("etag").to_owned();
    assert_ne!(br_etag, plain_etag, "each encoding has its own validator");

    let gz = get_with(&app, &script, &[("accept-encoding", "br;q=0, gzip")]).await;
    assert_eq!(gz.header("content-encoding"), Some("gzip"));
    assert_eq!(&gz.body[..2], &[0x1f, 0x8b], "gzip magic");

    let identity = get_with(&app, &script, &[("accept-encoding", "identity")]).await;
    assert!(identity.header("content-encoding").is_none());
    assert_eq!(identity.body, plain.body);

    let not_modified = get_with(
        &app,
        &script,
        &[("accept-encoding", "br"), ("if-none-match", &br_etag)],
    )
    .await;
    assert_eq!(not_modified.status, StatusCode::NOT_MODIFIED);
    assert!(not_modified.body.is_empty());
    assert_eq!(not_modified.header("etag"), Some(br_etag.as_str()));

    // A validator of a different encoding does not match.
    let changed = get_with(
        &app,
        &script,
        &[("accept-encoding", "br"), ("if-none-match", &plain_etag)],
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK);

    let index_etag = index.header("etag").expect("index etag").to_owned();
    let index_304 = get_with(&app, "/console/users/1", &[("if-none-match", &index_etag)]).await;
    assert_eq!(index_304.status, StatusCode::NOT_MODIFIED);
    assert_eq!(index_304.header("cache-control"), Some("no-cache"));

    // A chunk that does not exist fails loudly instead of receiving the HTML index.
    let missing = script.replace(".js", "-missing.js");
    let resp = app.get(&missing).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}
