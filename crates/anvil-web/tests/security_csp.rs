//! Every UI page carries the strict CSP, `frame-ancestors 'none'` and `Referrer-Policy:
//! no-referrer`, contains no inline script (only self-hosted script files such as the sign-in
//! page's webauthn.js, which the password form does not need) and references no external host
//! (SEC-04, UI-01).
//! Selected backend via `ANVILID_TEST_DB`.

mod support;
mod ui_helpers;

use support::TestResponse;
use ui_helpers::*;

const ORIGIN: &str = "https://op.test";

fn check(name: &str, resp: &TestResponse) {
    let csp = resp
        .header("content-security-policy")
        .unwrap_or_else(|| panic!("{name}: CSP header"));
    assert!(!csp.contains("unsafe-inline"), "{name}: {csp}");
    assert!(!csp.contains("unsafe-eval"), "{name}: {csp}");
    let script_src = csp
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("script-src"));
    assert!(
        script_src.is_none_or(|d| d == "script-src 'self'" || d == "script-src 'none'"),
        "{name}: {csp}"
    );
    assert!(csp.contains("default-src 'none'"), "{name}: {csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{name}: {csp}");
    // The self-hosted theme fonts may load, from our origin only; no external source at all.
    let font_src: Vec<&str> = csp
        .split(';')
        .map(str::trim)
        .filter(|d| d.starts_with("font-src"))
        .collect();
    assert_eq!(font_src, ["font-src 'self'"], "{name}: {csp}");
    assert!(
        !csp.contains("http:") && !csp.contains("https:") && !csp.contains('*'),
        "{name}: {csp}"
    );
    assert_eq!(
        resp.header("referrer-policy"),
        Some("no-referrer"),
        "{name}"
    );

    let html = resp.html();
    // Only `<script src="/…/assets/…" defer></script>`: a same-origin file, no inline code.
    let lower = html.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(i) = rest.find("<script") {
        let tag = &rest[i..];
        let end = tag
            .find("</script>")
            .map_or(tag.len(), |e| e + "</script>".len());
        let tag = &tag[..end];
        let src = tag
            .strip_prefix("<script src=\"")
            .and_then(|t| t.split_once('"'));
        assert!(
            src.is_some_and(|(src, after)| src.starts_with('/')
                && src.contains("/assets/")
                && after == " defer></script>"),
            "{name}: only self-hosted script files are allowed: {tag}"
        );
        rest = &rest[i + end..];
    }
    for scheme in ["http://", "https://"] {
        let mut rest = html.as_str();
        while let Some(i) = rest.find(scheme) {
            let url = &rest[i..];
            assert!(
                url.starts_with(&format!("{ORIGIN}/")) || url.starts_with(&format!("{ORIGIN}\"")),
                "{name}: external URL {}",
                &url[..url.len().min(60)]
            );
            rest = &rest[i + scheme.len()..];
        }
    }
}

#[tokio::test]
async fn every_ui_page_has_the_strict_headers_and_no_external_references() {
    let app = OwnApp::installed().await;
    let mut pages = Vec::new();
    for path in [
        "/ui/login",
        "/ui/registration",
        "/ui/recovery",
        "/ui/recovery?token=sample",
        "/ui/verification?token=sample",
        "/t/system/ui/login",
    ] {
        let resp = Client::get(&app, path).await;
        // A token that was never issued shows the "link expired" page (400, 07.1-07): its headers
        // are checked like every other page.
        let expected = if path.contains("token=sample") { 400 } else { 200 };
        assert_eq!(resp.status, expected, "{path}");
        pages.push((path.to_owned(), resp));
    }
    let setup = format!("/setup?token={}", app.setup_token);
    let resp = Client::get(&app, &setup).await;
    assert_eq!(resp.status, 200);
    pages.push(("setup".to_owned(), resp));

    // Error pages.
    let resp = Client::get(&app, "/ui/nope").await;
    assert_eq!(resp.status, 404);
    pages.push(("error 404".to_owned(), resp));
    let resp = Client::get(&app, "/setup?token=bad").await;
    assert_eq!(resp.status, 403);
    pages.push(("error 403".to_owned(), resp));

    // A message page.
    let resp = submit_form(&app, "/ui/recovery", &[("email", "x@example.com")]).await;
    assert_eq!(resp.status, 200);
    pages.push(("message".to_owned(), resp));

    // The setup result page.
    let resp = submit_form(
        &app,
        &setup,
        &[
            ("email", "admin@example.com"),
            ("password", "a long admin passphrase"),
        ],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(resp.html().contains("mgmt-client-secret"));
    pages.push(("setup_done".to_owned(), resp));

    for (name, resp) in &pages {
        check(name, resp);
    }
}
