//! Theming security controls (UI-03): the custom CSS validator through the API, logo sniffing and
//! size limit, tenant isolation of stylesheets, logos and preview tokens, preview expiry, framing
//! allowed only on the preview page, and admin scope enforcement on every branding route.
//! Selected backend via `ANVILID_TEST_DB`.

mod admin_support;
mod support;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use anvil_core::model::{NewTenant, TenantId, TenantSettings};
use anvil_core::ports::Clock as _;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};

const T: &str = "/api/admin/v1/tenants/default/branding";

/// A 1x1 PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

async fn req(app: &TestApp, t: &str, m: Method, path: &str, body: Option<Value>) -> TestResponse {
    call(app, m, path, Some(t), body).await
}

async fn other_tenant(app: &TestApp) {
    app.storage()
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: "other".into(),
            display_name: "Other".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: app.clock().now(),
        })
        .await
        .expect("create tenant");
}

async fn preview(app: &TestApp, t: &str, body: Value) -> (String, String) {
    let resp = req(app, t, Method::POST, &format!("{T}/preview"), Some(body)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body_json(&resp);
    (
        v["token"].as_str().unwrap().to_owned(),
        v["preview_url"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn dangerous_custom_css_is_refused_by_the_api() {
    let app = app().await;
    let t = admin_token(&app, "admin:settings:write").await;
    for css in [
        "@import url(https://evil.example/x.css);",
        "@import 'x.css';",
        ".a { background: url(https://evil.example/t.gif) }",
        ".a { background: URL(x) }",
        ".a { content: \"\\61\" }",
        ".a { b\\ackground: red }",
        "</style><script>alert(1)</script>",
        ".a { behavior: url(x.htc) }",
        ".a { color: red",
    ] {
        for path in [T.to_owned(), format!("{T}/preview")] {
            let m = if path.ends_with("preview") {
                Method::POST
            } else {
                Method::PUT
            };
            let resp = req(&app, &t, m, &path, Some(json!({"custom_css": css}))).await;
            assert_field_error(&resp, "custom_css");
        }
    }
    // Nothing was stored.
    assert_eq!(
        app.get("/theme/theme.css").await.text(),
        ".anvil-logo{display:none}\n"
    );
}

#[tokio::test]
async fn logos_are_sniffed_and_size_limited() {
    let app = app().await;
    let t = admin_token(&app, "admin:settings:write").await;
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
    let gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;";
    let mut oversize = PNG[..8].to_vec();
    oversize.resize(256 * 1024 + 1, 0);
    // A PNG body that claims to be something else still has to be a PNG by its bytes.
    let html = b"<html><script>alert(1)</script></html>";
    for bytes in [&svg[..], &gif[..], &oversize[..], &html[..], &[][..]] {
        let resp = req(
            &app,
            &t,
            Method::PUT,
            &format!("{T}/logo"),
            Some(json!({"data": anvil_jose::encoding::b64std(bytes)})),
        )
        .await;
        assert_field_error(&resp, "logo");
    }
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{T}/logo"),
        Some(json!({"data": "not base64!"})),
    )
    .await;
    assert_field_error(&resp, "data");
}

#[tokio::test]
async fn tenants_cannot_read_each_others_theme_logo_or_preview() {
    let app = app().await;
    let t = admin_token(&app, "admin:settings:write").await;
    other_tenant(&app).await;
    let resp = req(
        &app,
        &t,
        Method::PUT,
        T,
        Some(json!({"tokens": {"colors": {"primary": "#123456"}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{T}/logo"),
        Some(json!({"data": anvil_jose::encoding::b64std(PNG)})),
    )
    .await;
    let logo_url = body_json(&resp)["logo_url"].as_str().unwrap().to_owned();
    let sha = logo_url.rsplit('/').next().unwrap().to_owned();

    // The default tenant's logo exists; under the other tenant it does not.
    assert_eq!(app.get(&format!("/theme/logo/{sha}")).await.status, 200);
    assert_eq!(
        app.get(&format!("/t/other/theme/logo/{sha}")).await.status,
        404
    );
    // The other tenant's stylesheet has neither the colours nor the logo.
    let css = app.get("/t/other/theme/theme.css").await.text();
    assert_eq!(css, ".anvil-logo{display:none}\n");

    let (token, url) = preview(
        &app,
        &t,
        json!({"tokens": {"colors": {"primary": "#0a0b0c"}}}),
    )
    .await;
    assert_eq!(app.get(&url).await.status, 200);
    assert_eq!(
        app.get(&format!("/t/other/ui/preview?token={token}"))
            .await
            .status,
        404
    );
    assert_eq!(
        app.get(&format!("/t/other/theme/theme.css?preview={token}"))
            .await
            .status,
        404
    );
}

#[tokio::test]
async fn expired_or_unknown_preview_tokens_are_not_found() {
    let app = app().await;
    let t = admin_token(&app, "admin:settings:write").await;
    let (token, url) = preview(&app, &t, json!({})).await;
    assert_eq!(app.get(&url).await.status, 200);
    app.clock()
        .advance(std::time::Duration::from_secs(15 * 60 + 1));
    // The admin token expired with the clock as well.
    let t = admin_token(&app, "admin:settings:write").await;
    let resp = app.get(&url).await;
    assert_eq!(resp.status, 404);
    assert!(
        resp.header("content-security-policy")
            .unwrap()
            .contains("frame-ancestors 'none'"),
        "the 404 page is not framable"
    );
    assert_eq!(
        app.get(&format!("/theme/theme.css?preview={token}"))
            .await
            .status,
        404
    );
    // An expired token cannot be published either.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{T}/publish"),
        Some(json!({"token": token})),
    )
    .await;
    assert_problem(&resp, 404);
    for bad in ["", "short", "x".repeat(43).as_str(), "../../etc"] {
        assert_eq!(
            app.get(&format!("/t/default/ui/preview?token={bad}"))
                .await
                .status,
            404,
            "{bad}"
        );
    }
}

#[tokio::test]
async fn only_the_preview_page_may_be_framed_by_self() {
    let app = app().await;
    let t = admin_token(&app, "admin:settings:write").await;
    let (_, url) = preview(&app, &t, json!({})).await;
    let resp = app.get(&url).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.header("content-security-policy"),
        Some(
            "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'self'; base-uri 'none'"
        )
    );
    assert_eq!(resp.header("x-frame-options"), Some("SAMEORIGIN"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert!(!resp.html().contains("<script"), "no script on the preview");

    for page in ["/ui/login", "/t/default/ui/login", "/theme/theme.css"] {
        let resp = app.get(page).await;
        let csp = resp.header("content-security-policy").unwrap_or_default();
        assert!(csp.contains("frame-ancestors 'none'"), "{page}: {csp}");
        assert_eq!(resp.header("x-frame-options"), Some("DENY"), "{page}");
    }
}

#[tokio::test]
async fn every_branding_route_enforces_the_admin_scope() {
    let app = app().await;
    let full = admin_token(&app, "admin:read admin:write").await;
    let client = {
        let resp = req(
            &app,
            &full,
            Method::POST,
            "/api/admin/v1/tenants/default/clients",
            Some(json!({"name": "RP", "client_type": "confidential", "redirect_uris": ["https://rp.example/cb"]})),
        )
        .await;
        assert_eq!(resp.status, 201, "{}", resp.text());
        body_json(&resp)["client_id"].as_str().unwrap().to_owned()
    };
    let unrelated = admin_token(&app, "admin:users:write").await;
    let read_only = admin_token(&app, "admin:settings:read").await;
    let settings_write = admin_token(&app, "admin:settings:write").await;

    let c = format!("/api/admin/v1/tenants/default/clients/{client}/branding");
    let mut routes: Vec<(Method, String, bool)> = Vec::new();
    for base in [T.to_owned(), c] {
        routes.push((Method::GET, base.clone(), false));
        routes.push((Method::PUT, base.clone(), true));
        routes.push((Method::DELETE, base.clone(), true));
        routes.push((Method::PUT, format!("{base}/logo"), true));
        routes.push((Method::DELETE, format!("{base}/logo"), true));
        routes.push((Method::POST, format!("{base}/preview"), true));
        routes.push((Method::POST, format!("{base}/publish"), true));
    }
    for (m, path, write) in &routes {
        // Bodies that deserialize, so the scope check is what answers.
        let body = Some(if path.ends_with("/logo") {
            json!({"data": "AA=="})
        } else if path.ends_with("/publish") {
            json!({"token": "x"})
        } else {
            json!({})
        });
        let resp = call(&app, m.clone(), path, None, body.clone()).await;
        assert_problem(&resp, 401);
        let resp = req(&app, &unrelated, m.clone(), path, body.clone()).await;
        assert_problem(&resp, 403);
        if *write {
            let resp = req(&app, &read_only, m.clone(), path, body.clone()).await;
            assert_problem(&resp, 403);
        }
    }
    // The system tenant's branding (the console sign-in pages) needs admin:write.
    let resp = req(
        &app,
        &settings_write,
        Method::PUT,
        "/api/admin/v1/tenants/system/branding",
        Some(json!({})),
    )
    .await;
    assert_problem(&resp, 403);
    let resp = req(
        &app,
        &full,
        Method::PUT,
        "/api/admin/v1/tenants/system/branding",
        Some(json!({})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    // Not reachable through a tenant path.
    let resp = req(
        &app,
        &full,
        Method::GET,
        "/t/default/api/admin/v1/tenants/default/branding",
        None,
    )
    .await;
    assert_eq!(resp.status, 404);
}
