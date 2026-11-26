//! Upstream sign-in buttons on the gated sign-in pages (AUTH-07, AUTH-08, OIDC-16) on the
//! selected backend (`ANVILID_TEST_DB`): a locked (429) password sign-in, before and after the
//! flow runs, the CAPTCHA-required and CAPTCHA-failed pages, a failed passkey assertion and a
//! passkey lockout all list the tenant's enabled connections, so a gated user still sees the
//! other ways to sign in. Disabled connections are never listed, and a tenant without
//! connections renders no button group.

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    CAPTCHA_SECRET_PURPOSE, CaptchaProvider, CaptchaSettings, ConnectionConfig, ConnectionUpdate,
    OidcConfig, TenantSettings,
};
use anvil_core::ports::Clock as _;
use anvil_web::AppConfig;
use anvil_web::adapters::captcha::CaptchaEndpoints;
use anvil_web::adapters::outbound::OutboundPolicy;
use axum::body::Body;
use axum::http::{Method, Request, header};
use support::{TestApp, TestResponse, csrf_from};
use ui_helpers::{default_tenant, login, open_form, register, set_settings, to_path};
use upstream_flow::add_connection;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const WRONG: &str = "wrong password 123";
/// The enabled connection every gated page must list.
const ON: &str = "acme-id";
/// A disabled connection no page may list.
const OFF: &str = "retired-id";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// The route-class limit for auth POSTs is raised so it does not mask the brute-force limits
/// (as in `security_bruteforce.rs`).
fn base_config(c: &mut AppConfig) {
    c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
}

fn oidc(issuer: &str) -> ConnectionConfig {
    ConnectionConfig::Oidc(OidcConfig {
        issuer: issuer.into(),
        client_id: "anvil-test".into(),
        scopes: vec![],
        use_pkce: true,
        fetch_userinfo: false,
    })
}

/// One enabled and one disabled connection on the default tenant. Rendering the buttons needs
/// no provider round trip, so the issuers are never contacted.
async fn add_connections(app: &TestApp) {
    add_connection(app, ON, "Acme ID", oidc("https://idp.example.test"), false).await;
    let off = add_connection(
        app,
        OFF,
        "Retired ID",
        oidc("https://old-idp.example.test"),
        false,
    )
    .await;
    app.storage()
        .connections()
        .update(
            default_tenant(app).id,
            off.id,
            &ConnectionUpdate {
                enabled: Some(false),
                ..ConnectionUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("disable connection")
        .expect("connection exists");
}

/// An app with a registered user and, when `connections`, the two connections.
async fn app_with(connections: bool, f: impl FnOnce(&mut AppConfig)) -> TestApp {
    let app = TestApp::with(|c| {
        base_config(c);
        f(c);
    })
    .await;
    register(&app, "", EMAIL, PASSWORD).await;
    if connections {
        add_connections(&app).await;
    }
    app
}

/// Asserts the page lists the enabled connection's button form and never the disabled one.
fn assert_buttons(resp: &TestResponse) {
    let html = resp.html();
    assert!(
        html.contains(&format!("id=\"upstream-{ON}-form\"")),
        "the enabled connection is listed: {html}"
    );
    assert!(html.contains(&format!("id=\"upstream-{ON}\"")), "{html}");
    assert!(
        !html.contains(&format!("upstream-{OFF}")),
        "the disabled connection is never listed: {html}"
    );
}

fn assert_no_button_group(resp: &TestResponse) {
    let html = resp.html();
    assert!(!html.contains("anvil-upstream"), "{html}");
    assert!(!html.contains("id=\"upstream-"), "{html}");
}

fn peer(n: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, n)), 40000)
}

/// A same-origin form POST from `peer`.
async fn post_from(
    app: &TestApp,
    peer: SocketAddr,
    path: &str,
    pairs: &[(&str, &str)],
) -> TestResponse {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    app.send_from(
        peer,
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(body))
            .expect("request"),
    )
    .await
}

/// Opens the sign-in page and submits it from `peer` with `extra` fields.
async fn login_from(
    app: &TestApp,
    peer: SocketAddr,
    password: &str,
    extra: &[(&str, &str)],
) -> TestResponse {
    let (action, csrf) = open_form(app, "/ui/login").await;
    let mut pairs = vec![
        ("csrf_token", csrf.as_str()),
        ("identifier", EMAIL),
        ("password", password),
    ];
    pairs.extend_from_slice(extra);
    post_from(app, peer, &action, &pairs).await
}

/// Five wrong passwords (400), then the sixth locks: returns (lock after the failed attempt, lock
/// before the flow runs).
async fn password_locks(app: &TestApp) -> (TestResponse, TestResponse) {
    for i in 0..5 {
        let resp = login(app, "", EMAIL, WRONG).await;
        assert_eq!(resp.status, 400, "attempt {i}: {}", resp.text());
    }
    let after = login(app, "", EMAIL, WRONG).await;
    assert_eq!(after.status, 429, "{}", after.text());
    let before = login(app, "", EMAIL, PASSWORD).await;
    assert_eq!(before.status, 429, "{}", before.text());
    (after, before)
}

/// Turnstile settings with `secret` sealed for the default tenant.
fn captcha_settings(app: &TestApp, secret: &str) -> CaptchaSettings {
    let tenant = default_tenant(app);
    let sealed = app
        .kek()
        .seal(
            CAPTCHA_SECRET_PURPOSE,
            tenant.id.0.as_bytes(),
            secret.as_bytes(),
        )
        .expect("seal");
    CaptchaSettings {
        provider: CaptchaProvider::Turnstile,
        site_key: "site-key-123".into(),
        secret_sealed: anvil_jose::encoding::b64url(&sealed),
    }
}

/// An attribute of the passkey form (`action`, `data-options-url`) as a path.
fn passkey_attr(app: &TestApp, html: &str, attr: &str) -> String {
    let form = &html[html.find("id=\"login-passkey\"").expect("passkey form")..];
    let marker = format!("{attr}=\"");
    let start = form.find(&marker).expect("attribute") + marker.len();
    let end = form[start..].find('"').expect("quoted") + start;
    to_path(app, &form[start..end].replace("&amp;", "&"))
}

/// Six malformed passkey assertions, each after asking for a challenge like webauthn.js: the
/// first fails (400), the sixth locks (429) and a seventh is refused before the flow (429).
/// Returns (first failure, lock after the failure, lock before the flow).
async fn passkey_failures(app: &TestApp) -> (TestResponse, TestResponse, TestResponse) {
    let page = app.get("/ui/login").await;
    let html = page.html();
    let csrf = csrf_from(&html);
    let options = passkey_attr(app, &html, "data-options-url");
    let action = passkey_attr(app, &html, "action");
    let attempt = async || {
        let resp = app.post_form(&options, &[("csrf_token", &csrf)]).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        app.post_form(&action, &[("csrf_token", &csrf), ("response", "garbage")])
            .await
    };
    let first = attempt().await;
    assert_eq!(first.status, 400, "{}", first.text());
    for i in 1..5 {
        assert_eq!(attempt().await.status, 400, "attempt {i}");
    }
    let locked = attempt().await;
    assert_eq!(locked.status, 429, "{}", locked.text());
    let before = app
        .post_form(&action, &[("csrf_token", &csrf), ("response", "garbage")])
        .await;
    assert_eq!(before.status, 429, "{}", before.text());
    (first, locked, before)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_sign_in_page_lists_only_enabled_connections() {
    let app = app_with(true, |_| {}).await;
    assert_buttons(&app.get("/ui/login").await);
}

#[tokio::test]
async fn password_lockout_pages_list_the_upstream_buttons() {
    let app = app_with(true, |_| {}).await;
    let (after, before) = password_locks(&app).await;
    assert!(after.html().contains("Try again in"), "{}", after.html());
    assert_buttons(&after);
    assert_buttons(&before);
}

#[tokio::test]
async fn without_connections_the_lockout_page_has_no_button_group() {
    let app = app_with(false, |_| {}).await;
    let (after, before) = password_locks(&app).await;
    assert_no_button_group(&after);
    assert_no_button_group(&before);
}

#[tokio::test]
async fn captcha_required_and_failed_pages_list_the_upstream_buttons() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string_contains("response=bad-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"success":false,"error-codes":["invalid-input-response"]}"#),
        )
        .mount(&server)
        .await;
    let uri = server.uri();
    let app = app_with(true, |c| {
        c.rate_limits.loose_threshold_per_hour = 5;
        // The mock listens on loopback: allow it (production policy blocks it).
        c.outbound = OutboundPolicy::loopback_dev();
        c.captcha_endpoints = CaptchaEndpoints {
            turnstile: format!("{uri}/siteverify"),
            hcaptcha: format!("{uri}/siteverify"),
        };
    })
    .await;
    let settings = captcha_settings(&app, "provider-secret");
    set_settings(
        &app,
        default_tenant(&app).id,
        TenantSettings {
            captcha: Some(settings),
            ..TenantSettings::default()
        },
    )
    .await;
    // Failures from five IPs reach the identifier tier's threshold: a CAPTCHA is required.
    for n in 1..=5 {
        let resp = login_from(&app, peer(n), WRONG, &[]).await;
        assert_eq!(resp.status, 400, "ip {n}: {}", resp.text());
    }

    // No CAPTCHA response: refused with the widget, and the buttons.
    let required = login_from(&app, peer(6), WRONG, &[]).await;
    assert_eq!(required.status, 400, "{}", required.text());
    assert!(
        required
            .html()
            .contains("data-message-key=\"login.captcha_required\""),
        "{}",
        required.html()
    );
    assert!(required.html().contains("id=\"captcha-widget\""));
    assert_buttons(&required);

    // A response the provider rejects: the same page with the failure message.
    let failed = login_from(
        &app,
        peer(6),
        WRONG,
        &[("cf-turnstile-response", "bad-token")],
    )
    .await;
    assert_eq!(failed.status, 400, "{}", failed.text());
    assert!(
        failed
            .html()
            .contains("data-message-key=\"login.captcha_failed\""),
        "{}",
        failed.html()
    );
    assert!(failed.html().contains("id=\"captcha-widget\""));
    assert_buttons(&failed);
}

#[tokio::test]
async fn passkey_failure_and_lockout_pages_list_the_upstream_buttons() {
    let app = app_with(true, |_| {}).await;
    let (failed, locked, before) = passkey_failures(&app).await;
    assert!(
        failed.html().contains("name=\"password\""),
        "the sign-in form is shown again"
    );
    assert_buttons(&failed);
    assert_buttons(&locked);
    assert_buttons(&before);
}

#[tokio::test]
async fn without_connections_the_passkey_pages_have_no_button_group() {
    let app = app_with(false, |_| {}).await;
    let (failed, locked, before) = passkey_failures(&app).await;
    assert_no_button_group(&failed);
    assert_no_button_group(&locked);
    assert_no_button_group(&before);
}
