//! Smoke tests of the web shell on the selected backend (`ANVILID_TEST_DB`).

mod support;

use support::{TestApp, csrf_from};

const CSP: &str =
    "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'";

fn assert_security_headers(resp: &support::TestResponse, hsts: bool) {
    assert_eq!(resp.header("content-security-policy"), Some(CSP));
    assert_eq!(resp.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.header("strict-transport-security").is_some(), hsts);
    assert!(
        resp.header("x-request-id").is_some(),
        "request id propagated"
    );
}

#[tokio::test]
async fn harness_starts_and_health_live_answers() {
    let app = TestApp::uninstalled().await;
    let resp = app.get("/health/live").await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text(), "ok");
    assert_security_headers(&resp, true);
    assert_eq!(app.get("/healthz").await.status, 200);
}

#[tokio::test]
async fn malformed_tenant_path_is_a_themed_404_with_security_headers() {
    let app = TestApp::uninstalled().await;
    for path in ["/t/", "/t", "/t//token"] {
        let resp = app.get(path).await;
        assert_eq!(resp.status, 404, "{path}");
        assert!(resp.html().contains("Page not found."), "{path}");
        assert!(resp.html().contains("data-error-key=\"not_found\""));
        assert_security_headers(&resp, true);
    }
}

#[tokio::test]
async fn dev_mode_has_no_hsts() {
    let app = TestApp::uninstalled_dev().await;
    let resp = app.get("/t/").await;
    assert_eq!(resp.status, 404);
    assert_security_headers(&resp, false);
    assert!(resp.html().contains("id=\"dev-mode-banner\""));
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let app = TestApp::uninstalled().await;
    let big = "a".repeat(anvil_web::BODY_LIMIT + 1);
    let resp = app.post_form("/health/live", &[("x", &big)]).await;
    assert_eq!(resp.status, 413);
}

#[test]
fn csrf_helper_extracts_the_token() {
    let html = r#"<input type="hidden" name="csrf_token" value="abc-123">"#;
    assert_eq!(csrf_from(html), "abc-123");
}

#[tokio::test]
async fn health_ready_when_storage_answers() {
    let app = TestApp::new().await;
    assert_eq!(app.get("/health/ready").await.status, 200);
}

#[tokio::test]
async fn harness_installs_tenants_and_keys() {
    let app = TestApp::new().await;
    let system = app.system.as_ref().expect("system tenant");
    let default = app.default.as_ref().expect("default tenant");
    assert_eq!(system.tenant.slug, "system");
    assert_eq!(default.tenant.slug, "default");
    let now = anvil_core::ports::Clock::now(app.clock());
    let keys = app
        .storage()
        .keys()
        .published(default.tenant.id, now)
        .await
        .expect("published keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, default.kid);
    let opened = app
        .kek()
        .open(
            anvil_core::model::SIGNING_KEY_PURPOSE,
            &anvil_core::model::signing_key_aad(keys[0].id),
            &keys[0].private_key_enc,
        )
        .expect("the sealed key opens with the harness KEK");
    assert!(!opened.is_empty());
    assert_eq!(app.issuer(None), "https://op.test");
    assert_eq!(app.issuer(Some("system")), "https://op.test/t/system");
}

#[tokio::test]
async fn path_tenant_is_resolved_before_routing() {
    let app = TestApp::new().await;
    // No route yet, but the 404 page is rendered for the resolved tenant (name and asset base).
    let resp = app.get("/t/default/no-such-page").await;
    assert_eq!(resp.status, 404);
    let html = resp.html();
    assert!(
        html.contains("<p class=\"anvil-tenant\">Default</p>"),
        "{html}"
    );
    assert!(html.contains("/t/default/assets/anvil.css"));
    assert_security_headers(&resp, true);

    // Assets resolve through the tenant path rewrite.
    let css = app.get("/t/default/assets/anvil.css").await;
    assert_eq!(css.status, 200);
    assert_eq!(css.header("cache-control"), Some("public, max-age=3600"));
}

#[tokio::test]
async fn root_resolves_the_default_tenant() {
    let app = TestApp::new().await;
    let html = app.get("/no-such-page").await.html();
    assert!(
        html.contains("<p class=\"anvil-tenant\">Default</p>"),
        "{html}"
    );
    assert!(html.contains("href=\"/assets/anvil.css\""));
}

#[tokio::test]
async fn unknown_slug_is_a_404_without_tenant() {
    let app = TestApp::new().await;
    let resp = app.get("/t/nope/token").await;
    assert_eq!(resp.status, 404);
    let html = resp.html();
    assert!(html.contains("Page not found."));
    assert!(!html.contains("anvil-tenant"));
}

#[tokio::test]
async fn unregistered_host_falls_back_to_the_default_tenant() {
    let app = TestApp::new().await;
    let req = axum::http::Request::get("/x")
        .header("host", "unknown.example.test")
        .body(axum::body::Body::empty())
        .expect("request");
    let html = app.send(req).await.html();
    assert!(
        html.contains("<p class=\"anvil-tenant\">Default</p>"),
        "{html}"
    );
}

#[tokio::test]
async fn registered_host_resolves_its_tenant() {
    let app = TestApp::new().await;
    app.storage()
        .tenants()
        .create(&anvil_core::model::NewTenant {
            id: anvil_core::model::TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: Some("login.acme.test".into()),
            settings: anvil_core::model::TenantSettings::default(),
            created_at: support::start_time(),
        })
        .await
        .expect("create host tenant");
    let req = axum::http::Request::get("/no-such-page")
        .header("host", "login.acme.test")
        .body(axum::body::Body::empty())
        .expect("request");
    let html = app.send(req).await.html();
    assert!(
        html.contains("<p class=\"anvil-tenant\">Acme</p>"),
        "{html}"
    );
    assert!(html.contains("href=\"/assets/anvil.css\""));
}
