//! Security controls of the headless flow API in browser mode (UI-05, decision Q5), on the
//! selected backend (`ANVILID_TEST_DB`). Every control has a test that proves it rejects bad
//! input: the exact-origin allow-list, the CSRF header, JSON-only bodies, credentialed CORS
//! without wildcards, preflights for listed origins only, the UI Fetch-Metadata layer left
//! unchanged, brute-force throttling and CAPTCHA shared with the built-in pages (one
//! `flow_driver`), and the DTO never exposing internal members.

mod headless_support;
mod support;
mod ui_helpers;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anvil_core::model::{CAPTCHA_SECRET_PURPOSE, CaptchaProvider, CaptchaSettings, TenantSettings};
use anvil_web::adapters::captcha::CaptchaEndpoints;
use anvil_web::adapters::outbound::OutboundPolicy;
use headless_support::*;
use serde_json::{Value, json};
use support::TestApp;
use ui_helpers::{default_tenant, flow_cookie, login, register, session_cookie};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const WRONG: &str = "wrong password 123";

async fn app_with_user() -> TestApp {
    let app = app().await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
}

fn assert_problem(resp: &support::TestResponse, status: u16, code: &str) {
    assert_eq!(resp.status, status, "{}", resp.text());
    assert_eq!(
        resp.header("content-type"),
        Some("application/problem+json"),
        "{}",
        resp.text()
    );
    assert_eq!(body(resp)["code"], code, "{}", resp.text());
}

#[tokio::test]
async fn headless_foreign_origin_refused() {
    let app = app_with_user().await;
    // Start, read and submit from an unlisted origin: 403 before any flow work.
    for origin in [
        EVIL,
        "null",
        "https://app.op.test:8443",
        "http://app.op.test",
    ] {
        let resp = Call::post(&format!("{API}/login"), &json!({}))
            .origin(Some(origin))
            .send(&app)
            .await;
        assert_problem(&resp, 403, "forbidden_origin");
        assert!(flow_cookie(&app).is_none(), "no flow started for {origin}");
    }
    let (flow, _) = start(&app, "login", &json!({})).await;
    let resp = Call::post(&flow.path(), &password(EMAIL, PASSWORD))
        .csrf(&flow.csrf)
        .origin(Some(EVIL))
        .site(Some("cross-site"))
        .send(&app)
        .await;
    assert_problem(&resp, 403, "forbidden_origin");
    assert!(session_cookie(&app).is_none());
    let resp = Call::get(&flow.path())
        .csrf(&flow.csrf)
        .origin(Some(EVIL))
        .send(&app)
        .await;
    assert_problem(&resp, 403, "forbidden_origin");
    // A browser request without Origin that is not same-origin is refused too.
    let resp = Call::post(&format!("{API}/login"), &json!({}))
        .origin(None)
        .site(Some("cross-site"))
        .send(&app)
        .await;
    assert_problem(&resp, 403, "forbidden_origin");
    // An empty allow-list admits only the tenant's own origin.
    allow_origins(&app, &[], TenantSettings::default()).await;
    let resp = Call::post(&format!("{API}/login"), &json!({}))
        .send(&app)
        .await;
    assert_problem(&resp, 403, "forbidden_origin");
    let resp = Call::post(&format!("{API}/login"), &json!({}))
        .origin(Some("https://op.test"))
        .site(Some("same-origin"))
        .send(&app)
        .await;
    assert_eq!(resp.status, 200, "own origin: {}", resp.text());
}

#[tokio::test]
async fn headless_missing_csrf_header_refused() {
    let app = app_with_user().await;
    let (flow, _) = start(&app, "login", &json!({})).await;
    let resp = Call::post(&flow.path(), &password(EMAIL, PASSWORD))
        .send(&app)
        .await;
    assert_problem(&resp, 403, "csrf");
    assert!(session_cookie(&app).is_none());
    let resp = Call::get(&flow.path()).send(&app).await;
    assert_problem(&resp, 403, "csrf");
    let resp = Call::post(&format!("{}/passkey/options", flow.path()), &json!({}))
        .send(&app)
        .await;
    assert_problem(&resp, 403, "csrf");
}

#[tokio::test]
async fn headless_wrong_csrf_header_refused() {
    let app = app_with_user().await;
    let (flow, _) = start(&app, "login", &json!({})).await;
    let wrong = format!("{}x", flow.csrf);
    let resp = Call::post(&flow.path(), &password(EMAIL, PASSWORD))
        .csrf(&wrong)
        .send(&app)
        .await;
    assert_problem(&resp, 403, "csrf");
    assert!(session_cookie(&app).is_none());
    let resp = Call::get(&flow.path()).csrf(&wrong).send(&app).await;
    assert_problem(&resp, 403, "csrf");
    // The right token without the flow cookie (another browser) is refused as well.
    app.clear_cookies();
    let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
    assert_problem(&resp, 403, "csrf");
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn headless_form_encoded_body_refused_415() {
    let app = app_with_user().await;
    let form = "identifier=alice%40example.com&password=x";
    for ct in [
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=x"),
        Some("text/plain"),
        None,
    ] {
        let resp = Call::post(&format!("{API}/login"), &json!({}))
            .content_type(ct, form)
            .send(&app)
            .await;
        assert_problem(&resp, 415, "unsupported_media_type");
    }
    let (flow, _) = start(&app, "login", &json!({})).await;
    let resp = Call::post(&flow.path(), &json!({}))
        .csrf(&flow.csrf)
        .content_type(Some("application/x-www-form-urlencoded"), form)
        .send(&app)
        .await;
    assert_problem(&resp, 415, "unsupported_media_type");
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn headless_no_wildcard_cors_with_credentials() {
    let app = app_with_user().await;
    let resp = Call::post(&format!("{API}/login"), &json!({}))
        .send(&app)
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("access-control-allow-origin"), Some(SPA));
    assert_eq!(
        resp.header("access-control-allow-credentials"),
        Some("true")
    );
    let vary = resp
        .headers
        .get_all("vary")
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(",");
    assert!(vary.contains("origin"), "{vary}");
    // Refused and unlisted requests never get an allow-origin header, and nothing is ever `*`.
    for origin in [EVIL, "null"] {
        let resp = Call::post(&format!("{API}/login"), &json!({}))
            .origin(Some(origin))
            .send(&app)
            .await;
        assert!(
            resp.header("access-control-allow-origin").is_none(),
            "{origin}"
        );
    }
    let resp = Call::post(&format!("{API}/login"), &json!({}))
        .origin(Some("https://op.test"))
        .site(Some("same-origin"))
        .send(&app)
        .await;
    assert_ne!(resp.header("access-control-allow-origin"), Some("*"));
    // The protocol endpoints keep their uncredentialed `*` (public_cors unchanged).
    let resp = app.get("/.well-known/openid-configuration").await;
    assert!(
        resp.header("access-control-allow-credentials").is_none(),
        "public CORS stays without credentials"
    );
}

#[tokio::test]
async fn headless_preflight_only_for_allowed_origin() {
    let app = app().await;
    let resp = Call::preflight(&format!("{API}/login"), SPA)
        .send(&app)
        .await;
    assert_eq!(resp.header("access-control-allow-origin"), Some(SPA));
    assert_eq!(
        resp.header("access-control-allow-credentials"),
        Some("true")
    );
    let allowed = resp
        .header("access-control-allow-headers")
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(allowed.contains("x-csrf-token"), "{allowed}");
    let methods = resp
        .header("access-control-allow-methods")
        .unwrap_or_default()
        .to_ascii_uppercase();
    assert!(methods.contains("POST"), "{methods}");

    let resp = Call::preflight(&format!("{API}/login"), EVIL)
        .send(&app)
        .await;
    assert!(resp.header("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn headless_ui_router_still_refuses_cross_site() {
    let app = app_with_user().await;
    // The SPA's origin is allow-listed for the API, never for the pages.
    let (action, csrf) = ui_helpers::open_form(&app, "/ui/login").await;
    for (origin, site) in [(SPA, "same-site"), (SPA, "cross-site")] {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("csrf_token", csrf.as_str()),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ])
            .finish();
        let resp = Call::post(&action, &Value::Null)
            .origin(Some(origin))
            .site(Some(site))
            .content_type(Some("application/x-www-form-urlencoded"), &body)
            .send(&app)
            .await;
        assert_eq!(resp.status, 403, "{site}: {}", resp.text());
        assert!(session_cookie(&app).is_none());
        assert!(resp.header("access-control-allow-origin").is_none());
    }
}

#[tokio::test]
async fn headless_api_not_behind_ui_fetch_metadata() {
    // An allow-listed cross-site caller reaches the API (the UI layer would answer 403).
    let app = app_with_user().await;
    let resp = Call::post(&format!("{API}/login"), &json!({}))
        .site(Some("cross-site"))
        .send(&app)
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

fn peer(n: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, n)), 40000)
}

#[tokio::test]
async fn headless_throttling_shared_with_ui() {
    // API failures lock the page for the same identifier (and client IP).
    let app = app_with_user().await;
    for _ in 0..5 {
        let (flow, _) = start(&app, "login", &json!({})).await;
        let resp = flow.submit(&app, &password(EMAIL, WRONG)).await;
        assert_eq!(resp.status, 400, "{}", resp.text());
    }
    let (flow, _) = start(&app, "login", &json!({})).await;
    let resp = flow.submit(&app, &password(EMAIL, WRONG)).await;
    assert_eq!(resp.status, 429, "{}", resp.text());
    assert_eq!(resp.header("retry-after"), Some("1"));
    let v = body(&resp);
    assert_eq!(v["retry_after"], 1);
    assert_eq!(message_keys(&v), vec!["login.too_many_attempts"]);
    let resp = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(resp.status, 429, "the page is locked too: {}", resp.text());
    assert!(session_cookie(&app).is_none());

    // And page failures lock the API.
    let app = app_with_user().await;
    for _ in 0..5 {
        let resp = login(&app, "", EMAIL, WRONG).await;
        assert_eq!(resp.status, 400, "{}", resp.text());
    }
    let resp = login(&app, "", EMAIL, WRONG).await;
    assert_eq!(resp.status, 429);
    let (flow, _) = start(&app, "login", &json!({})).await;
    let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
    assert_eq!(resp.status, 429, "the API is locked too: {}", resp.text());
    assert!(session_cookie(&app).is_none());
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

#[tokio::test]
async fn headless_captcha_required_in_browser_mode() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string_contains("response=good-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"success":true}"#))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string_contains("response=bad-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"success":false,"error-codes":["invalid-input-response"]}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    let uri = server.uri();
    let app = app_with(|c| {
        c.rate_limits.loose_threshold_per_hour = 5;
        c.outbound = OutboundPolicy::loopback_dev();
        c.captcha_endpoints = CaptchaEndpoints {
            turnstile: format!("{uri}/siteverify"),
            hcaptcha: format!("{uri}/siteverify"),
        };
    })
    .await;
    register(&app, "", EMAIL, PASSWORD).await;
    let settings = captcha_settings(&app, "provider-secret");
    allow_origins(
        &app,
        &[SPA],
        TenantSettings {
            captcha: Some(settings),
            ..TenantSettings::default()
        },
    )
    .await;

    let submit_from = |n: u8, body: Value| {
        let app = &app;
        async move {
            let (flow, _) = start(app, "login", &json!({})).await;
            Call::post(&flow.path(), &body)
                .csrf(&flow.csrf)
                .peer(peer(n))
                .send(app)
                .await
        }
    };
    for n in 1..=4 {
        let resp = submit_from(n, password(EMAIL, WRONG)).await;
        assert_eq!(resp.status, 400, "ip {n}: {}", resp.text());
        assert!(body(&resp)["form"].get("captcha").is_none());
    }
    // The failure that reaches the threshold asks for a CAPTCHA on the next submission.
    let resp = submit_from(5, password(EMAIL, WRONG)).await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        body(&resp)["form"]["captcha"],
        json!({"provider": "turnstile", "site_key": "site-key-123"})
    );
    // No CAPTCHA: refused before the password is checked, with the site key.
    let resp = submit_from(6, password(EMAIL, PASSWORD)).await;
    assert_problem(&resp, 403, "captcha_required");
    assert_eq!(body(&resp)["captcha"]["site_key"], "site-key-123");
    assert!(session_cookie(&app).is_none());
    // A response the provider rejects.
    let mut bad = password(EMAIL, PASSWORD);
    bad["captcha"] = json!({"turnstile": "bad-token"});
    let resp = submit_from(6, bad).await;
    assert_problem(&resp, 403, "captcha_failed");
    assert!(session_cookie(&app).is_none());
    // A verified CAPTCHA lets the attempt through to the password check.
    let mut good = password(EMAIL, PASSWORD);
    good["captcha"] = json!({"turnstile": "good-token"});
    let resp = submit_from(6, good).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body(&resp)["step"], "completed");
    assert!(session_cookie(&app).is_some());
}

/// Every key anywhere in `v` (objects nested in arrays included).
fn keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                out.push(k.clone());
                keys(v, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
        _ => {}
    }
}

#[tokio::test]
async fn headless_dto_never_contains_internal_fields() {
    let app = app_with_user().await;
    let (flow, started) = start(&app, "login", &json!({})).await;
    let cookie = flow_cookie(&app).expect("flow cookie").1;
    let failed = body(
        &flow
            .submit(&app, &password(EMAIL, PASSWORD.replace('c', "k").as_str()))
            .await,
    );
    let got = body(&flow.get(&app).await);
    let done = body(&flow.submit(&app, &password(EMAIL, PASSWORD)).await);
    assert_eq!(done["step"], "completed");
    for v in [&started, &failed, &got, &done] {
        let text = v.to_string();
        for secret in [cookie.as_str(), PASSWORD, "korrekt"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        for internal in [
            "/ui/login?flow=",
            "\"post\"",
            "cookie_hash",
            "csrf_hash",
            "\"state\"",
        ] {
            assert!(!text.contains(internal), "{internal} in {text}");
        }
        let mut all = Vec::new();
        keys(v, &mut all);
        for k in [
            "action",
            "method",
            "cookie_token",
            "factor_user",
            "auth_request_id",
        ] {
            assert!(!all.iter().any(|x| x == k), "{k} in {text}");
        }
        if let Some(form) = v.get("form") {
            assert!(form.get("csrf_token").is_none(), "{text}");
        }
    }
}
