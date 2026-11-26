//! Security controls of the headless flow API in browser mode (UI-05, decision Q5), on the
//! selected backend (`ANVILID_TEST_DB`). Every control has a test that proves it rejects bad
//! input: the exact-origin allow-list, the CSRF header, JSON-only bodies, credentialed CORS
//! without wildcards, preflights for listed origins only, the UI Fetch-Metadata layer left
//! unchanged, brute-force throttling and CAPTCHA shared with the built-in pages (one
//! `flow_driver`), and the DTO never exposing internal members.
//!
//! Native-app mode (07-18, `native_*`): the PAR-bound start for `headless_native` first-party
//! clients only (DCR and CIMD clients refused), the flow token (required, exact, never usable
//! on a cookie-bound flow and never replaced by the cookie binding), no browser signals, PKCE at
//! the token endpoint, the single-use `request_uri`, CAPTCHA falling back to the browser, no
//! session cookie, and throttling shared with the built-in pages.

mod authz;
mod headless_support;
mod native_support;
mod par_support;
mod support;
mod token_support;
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

// ---------------------------------------------------------------------------------------------
// Native-app mode (07-18)
// ---------------------------------------------------------------------------------------------

mod native {
    use anvil_core::model::{ClientAuthMethod, ClientSource, TenantSettings};
    use axum::http::Method;
    use serde_json::json;

    use super::{EMAIL, PASSWORD, WRONG, assert_problem, captcha_settings, peer};
    use crate::headless_support::{Call, SPA, allow_origins, app, app_with, body, password, start};
    use crate::native_support::*;
    use crate::par_support::{PREFIX, authorize, exchange, par_client, push_default};
    use crate::support::TestApp;
    use crate::token_support::{REDIRECT, VERIFIER, token_at};
    use crate::ui_helpers::{flow_cookie, login, register, session_cookie};

    async fn app_with_user() -> TestApp {
        let app = app().await;
        register(&app, "", EMAIL, PASSWORD).await;
        app.clear_cookies();
        app
    }

    #[tokio::test]
    async fn native_requires_par_request_uri() {
        let app = app_with_user().await;
        let client = native_client(&app).await;
        // No request_uri, or no client_id.
        for body in [
            json!({"client_id": client.id()}),
            json!({"request_uri": format!("{PREFIX}abc")}),
            json!({"client_id": client.id(), "request_uri": ""}),
        ] {
            let resp = native_call(&app, Method::POST, START, None, Some(&body), &[]).await;
            assert_problem(&resp, 400, "invalid_request");
        }
        // A request_uri that was never pushed, or not a PAR URN.
        for uri in [
            format!("{PREFIX}{}", "A".repeat(43)),
            "https://rp.example/req".into(),
        ] {
            let resp = native_start(&app, client.id(), &uri).await;
            assert_problem(&resp, 400, "invalid_request_uri");
        }
        // The flow token header without a native start body is not a native start.
        let resp = native_call(&app, Method::POST, START, Some("x"), Some(&json!({})), &[]).await;
        assert_problem(&resp, 400, "invalid_request");
        // Only the login kind starts natively.
        let request_uri = push_default(&app, &client).await;
        let body = json!({"client_id": client.id(), "request_uri": request_uri});
        let resp = native_call(
            &app,
            Method::POST,
            "/api/flows/v1/registration",
            None,
            Some(&body),
            &[],
        )
        .await;
        assert_problem(&resp, 400, "invalid_request");
    }

    #[tokio::test]
    async fn native_requires_headless_native_client() {
        let app = app_with_user().await;
        let iss = app.issuer(None);
        // A normal first-party public PKCE client: its pushed request is refused for native start.
        let normal = par_client(&app, ClientAuthMethod::None).await;
        let request_uri = push_default(&app, &normal).await;
        let resp = native_start(&app, normal.id(), &request_uri).await;
        assert_problem(&resp, 403, "client_not_eligible");
        assert!(!sets_cookie(&resp));
        // Refused before the resume: the request_uri still works at /authorize.
        let cookie = crate::par_support::signed_in(&app, "bob@example.com").await;
        let resp = authorize(&app, normal.id(), &request_uri, &[], Some(&cookie)).await;
        crate::par_support::code_of(&resp, &iss);
        // An unknown client and another client's request_uri.
        let native = native_client(&app).await;
        let request_uri = push_default(&app, &normal).await;
        let resp = native_start(&app, "no-such-client", &request_uri).await;
        assert_problem(&resp, 403, "client_not_eligible");
        let resp = native_start(&app, native.id(), &request_uri).await;
        assert_problem(&resp, 400, "invalid_request_uri");
        // A headless_native client that is not first-party (stored bypassing validation).
        let third = native_client_with(&app, |c| {
            c.consent_mode = anvil_core::model::ConsentMode::Required;
        })
        .await;
        let request_uri = push_default(&app, &third).await;
        let resp = native_start(&app, third.id(), &request_uri).await;
        assert_problem(&resp, 403, "client_not_eligible");
    }

    #[tokio::test]
    async fn native_dcr_client_refused() {
        let app = app_with_user().await;
        let client =
            native_client_with(&app, |c| c.registration_source = ClientSource::Dynamic).await;
        let request_uri = push_default(&app, &client).await;
        let resp = native_start(&app, client.id(), &request_uri).await;
        assert_problem(&resp, 403, "client_not_eligible");
    }

    #[tokio::test]
    async fn native_cimd_client_refused() {
        let app = app_with_user().await;
        let client = native_client_with(&app, |c| c.registration_source = ClientSource::Cimd).await;
        let request_uri = push_default(&app, &client).await;
        let resp = native_start(&app, client.id(), &request_uri).await;
        assert_problem(&resp, 403, "client_not_eligible");
    }

    #[tokio::test]
    async fn native_flow_token_required() {
        let app = app_with_user().await;
        let client = native_client(&app).await;
        let (flow, _) = started(&app, &client).await;
        // Without any binding the request is browser mode and has no CSRF header.
        let resp = flow
            .submit_with(&app, None, &password(EMAIL, PASSWORD))
            .await;
        assert_problem(&resp, 403, "csrf");
        let resp = native_call(&app, Method::GET, &flow.path(), None, None, &[]).await;
        assert_problem(&resp, 403, "csrf");
        // The AnvilFlow scheme without a usable token.
        for bad in ["", "a b", "x=y"] {
            let resp = flow
                .submit_with(&app, Some(bad), &password(EMAIL, PASSWORD))
                .await;
            assert_problem(&resp, 401, "flow_token");
            assert_eq!(resp.header("www-authenticate"), Some("AnvilFlow"));
        }
        // Nothing was signed in; the right token still works.
        let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        code_of(&resp, &app.issuer(None));
    }

    #[tokio::test]
    async fn native_wrong_flow_token_refused() {
        let app = app_with_user().await;
        let client = native_client(&app).await;
        let (flow, _) = started(&app, &client).await;
        let (other, _) = started(&app, &client).await;
        let random = anvil_jose::encoding::random_token();
        for token in [random.as_str(), other.token.as_str(), &flow.token[..42]] {
            let resp = flow
                .submit_with(&app, Some(token), &password(EMAIL, PASSWORD))
                .await;
            assert_problem(&resp, 403, "flow_token");
            let resp = native_call(&app, Method::GET, &flow.path(), Some(token), None, &[]).await;
            assert_problem(&resp, 403, "flow_token");
        }
        let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        code_of(&resp, &app.issuer(None));
    }

    #[tokio::test]
    async fn native_cookie_bound_flow_refused_with_token() {
        let app = app_with_user().await;
        let (browser, _) = start(&app, "login", &json!({})).await;
        let (_, cookie) = flow_cookie(&app).expect("flow cookie");
        app.clear_cookies();
        let native = NativeFlow {
            id: browser.id.clone(),
            token: cookie.clone(),
        };
        // The flow cookie or the CSRF token presented as a flow token.
        for token in [cookie.as_str(), browser.csrf.as_str()] {
            let resp = native
                .submit_with(&app, Some(token), &password(EMAIL, PASSWORD))
                .await;
            assert_problem(&resp, 403, "flow_token");
            let resp = native_call(&app, Method::GET, &native.path(), Some(token), None, &[]).await;
            assert_problem(&resp, 403, "flow_token");
        }
        assert!(session_cookie(&app).is_none());
    }

    #[tokio::test]
    async fn native_token_flow_refused_with_cookie() {
        let app = app_with_user().await;
        // The flow cookie's name comes from a browser start.
        start(&app, "login", &json!({})).await;
        let (name, _) = flow_cookie(&app).expect("flow cookie");
        app.clear_cookies();
        let client = native_client(&app).await;
        let (flow, _) = started(&app, &client).await;
        let cookie = format!("{name}={}", flow.token);
        // Browser mode with the flow token as the flow cookie and any CSRF value.
        for csrf in [flow.token.as_str(), "anything"] {
            let resp = Call::post(&flow.path(), &password(EMAIL, PASSWORD))
                .csrf(csrf)
                .header("cookie", &cookie)
                .send(&app)
                .await;
            assert_problem(&resp, 403, "csrf");
            let resp = Call::get(&flow.path())
                .csrf(csrf)
                .header("cookie", &cookie)
                .send(&app)
                .await;
            assert_problem(&resp, 403, "csrf");
        }
        assert!(session_cookie(&app).is_none());
        // The flow is untouched and still completes with its token.
        let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        code_of(&resp, &app.issuer(None));
    }

    #[tokio::test]
    async fn native_browser_signals_refused() {
        let app = app_with_user().await;
        let client = native_client(&app).await;
        let request_uri = push_default(&app, &client).await;
        for signal in [
            ("origin", SPA),
            ("origin", "https://evil.test"),
            ("sec-fetch-site", "none"),
            ("sec-fetch-site", "same-origin"),
        ] {
            let resp = native_start_with(&app, client.id(), &request_uri, &[signal]).await;
            assert_eq!(resp.status, 403, "{signal:?}: {}", resp.text());
            assert!(!sets_cookie(&resp));
        }
        // Refused before the resume: the same request_uri starts without browser headers.
        let resp = native_start(&app, client.id(), &request_uri).await;
        let (flow, _) = NativeFlow::of(&resp);
        for signal in [("origin", SPA), ("sec-fetch-site", "none")] {
            let resp = native_call(
                &app,
                Method::POST,
                &flow.path(),
                Some(&flow.token),
                Some(&password(EMAIL, PASSWORD)),
                &[signal],
            )
            .await;
            assert_problem(&resp, 403, "browser_signals");
            let resp = native_call(
                &app,
                Method::GET,
                &flow.path(),
                Some(&flow.token),
                None,
                &[signal],
            )
            .await;
            assert_problem(&resp, 403, "browser_signals");
        }
        let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        code_of(&resp, &app.issuer(None));
    }

    #[tokio::test]
    async fn native_code_requires_code_verifier() {
        let app = app_with_user().await;
        let iss = app.issuer(None);
        let client = native_client(&app).await;
        let redeem = |code: String, verifier: Option<&'static str>| {
            let (app, auth) = (&app, client.auth(&iss));
            async move {
                let mut pairs = vec![
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("redirect_uri", REDIRECT),
                ];
                if let Some(v) = verifier {
                    pairs.push(("code_verifier", v));
                }
                token_at(app, "/token", &auth, &pairs).await
            }
        };
        for verifier in [None, Some("wrong-verifier-wrong-verifier-wrong-verifier-0")] {
            let (flow, _) = started(&app, &client).await;
            let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
            let code = code_of(&resp, &iss);
            let resp = redeem(code, verifier).await;
            assert_eq!(resp.status, 400, "{verifier:?}: {}", resp.text());
            assert_eq!(body(&resp)["error"], "invalid_grant", "{verifier:?}");
        }
        let (flow, _) = started(&app, &client).await;
        let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        let resp = redeem(code_of(&resp, &iss), Some(VERIFIER)).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
    }

    #[tokio::test]
    async fn native_request_uri_single_use() {
        let app = app_with_user().await;
        let client = native_client(&app).await;
        let request_uri = push_default(&app, &client).await;
        let resp = native_start(&app, client.id(), &request_uri).await;
        NativeFlow::of(&resp);
        let resp = native_start(&app, client.id(), &request_uri).await;
        assert_problem(&resp, 400, "invalid_request_uri");
        // Used up for /authorize too.
        let resp = authorize(&app, client.id(), &request_uri, &[], None).await;
        assert_eq!(resp.status, 400, "{}", resp.text());
        assert!(resp.header("location").is_none());
    }

    #[tokio::test]
    async fn native_captcha_returns_browser_required() {
        let app = app_with(|c| c.rate_limits.loose_threshold_per_hour = 5).await;
        register(&app, "", EMAIL, PASSWORD).await;
        app.clear_cookies();
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
        let client = native_client(&app).await;
        // Four failures from other addresses (browser mode), the fifth natively: the gate now
        // asks for a CAPTCHA, which a native app cannot show.
        for n in 1..=4 {
            let (flow, _) = start(&app, "login", &json!({})).await;
            let resp = Call::post(&flow.path(), &password(EMAIL, WRONG))
                .csrf(&flow.csrf)
                .peer(peer(n))
                .send(&app)
                .await;
            assert_eq!(resp.status, 400, "{}", resp.text());
        }
        app.clear_cookies();
        let (flow, _) = started(&app, &client).await;
        let resp = flow.submit(&app, &password(EMAIL, WRONG)).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        let v = body(&resp);
        assert_eq!(v["step"], "browser_required", "{v}");
        let url = v["url"].as_str().expect("url");
        assert!(
            url.starts_with(&format!("{}/authorize/continue?request=", app.issuer(None))),
            "{url}"
        );
        // The right password without a CAPTCHA is refused before it is checked.
        let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        let v = body(&resp);
        assert_eq!(v["step"], "browser_required", "{v}");
        assert!(v.get("result").is_none(), "{v}");
        assert!(!sets_cookie(&resp));
    }

    #[tokio::test]
    async fn native_no_sso_session_created() {
        let app = app_with_user().await;
        let iss = app.issuer(None);
        let client = native_client(&app).await;
        let request_uri = push_default(&app, &client).await;
        let start_resp = native_start(&app, client.id(), &request_uri).await;
        assert!(!sets_cookie(&start_resp));
        let (flow, _) = NativeFlow::of(&start_resp);
        let get = flow.get(&app).await;
        assert!(!sets_cookie(&get));
        let done = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        assert!(!sets_cookie(&done), "{:?}", done.headers);
        let code = code_of(&done, &iss);
        assert!(session_cookie(&app).is_none());
        assert!(flow_cookie(&app).is_none());
        // Nothing in any answer can be presented as a session: a browser request afterwards
        // (harness jar) is not signed in.
        let other = par_client(&app, ClientAuthMethod::None).await;
        let path = crate::authz::authorize_path(
            "",
            &[
                ("client_id", other.id()),
                ("response_type", "code"),
                ("scope", "openid"),
                ("redirect_uri", REDIRECT),
                ("prompt", "none"),
                ("code_challenge", crate::token_support::CHALLENGE),
                ("code_challenge_method", "S256"),
            ],
        );
        let resp = crate::authz::get(&app, &path, None).await;
        crate::authz::assert_error_redirect(&resp, REDIRECT, "login_required", &iss);
        // The code redeems normally.
        let resp = exchange(&app, &client, &code).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        assert!(!sets_cookie(&resp));
    }

    #[tokio::test]
    async fn native_throttling_shared_with_ui() {
        // Native failures lock the page for the same identifier and client IP.
        let app = app_with_user().await;
        let client = native_client(&app).await;
        for _ in 0..5 {
            let (flow, _) = started(&app, &client).await;
            let resp = flow.submit(&app, &password(EMAIL, WRONG)).await;
            assert_eq!(resp.status, 400, "{}", resp.text());
        }
        // The sixth failure locks (as in browser mode); then even the right password is refused.
        let (flow, _) = started(&app, &client).await;
        let resp = flow.submit(&app, &password(EMAIL, WRONG)).await;
        assert_eq!(resp.status, 429, "{}", resp.text());
        assert_eq!(resp.header("retry-after"), Some("1"));
        let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        assert_eq!(resp.status, 429, "{}", resp.text());
        assert!(body(&resp).get("result").is_none());
        let resp = login(&app, "", EMAIL, PASSWORD).await;
        assert_eq!(resp.status, 429, "the page is locked too: {}", resp.text());
        assert!(session_cookie(&app).is_none());

        // And page failures lock the native mode.
        let app = app_with_user().await;
        let client = native_client(&app).await;
        for _ in 0..5 {
            let resp = login(&app, "", EMAIL, WRONG).await;
            assert_eq!(resp.status, 400, "{}", resp.text());
        }
        let resp = login(&app, "", EMAIL, WRONG).await;
        assert_eq!(resp.status, 429);
        app.clear_cookies();
        let (flow, _) = started(&app, &client).await;
        let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
        assert_eq!(
            resp.status,
            429,
            "the native mode is locked too: {}",
            resp.text()
        );
        assert!(body(&resp).get("result").is_none());
    }
}
