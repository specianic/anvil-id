//! Brute-force protection of the sign-in pages (AUTH-09) on the selected backend
//! (`ANVILID_TEST_DB`): progressive locks per (identifier, IP) with 429 / `Retry-After` and an
//! in-page "try again in N seconds", enumeration-safe responses for unknown identifiers, reset on
//! success, the loose identifier tier (delay, or a CAPTCHA verified before the password when the
//! tenant has one), per-user second-factor throttling, per-IP passkey throttling and the
//! `rate_limit_lockout` audit event.
//!
//! The route-class limit for auth POSTs (per IP, tested in `security_ratelimit.rs`) is raised
//! here so it does not mask the brute-force limits under test. The brute-force limits keep their
//! defaults (5 free failures, then 1 s doubling) except where a test lowers the hourly
//! identifier threshold to keep the sequence short. Time moves only through the test clock.

mod support;
mod ui_helpers;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AuditAction, AuditQuery, CAPTCHA_SECRET_PURPOSE, CaptchaProvider, CaptchaSettings,
    CredentialId, NewTotp, TOTP_SEED_PURPOSE, TenantSettings, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_jose::otp::TotpSecret;
use anvil_web::AppConfig;
use anvil_web::adapters::captcha::CaptchaEndpoints;
use anvil_web::adapters::outbound::OutboundPolicy;
use aws_lc_rs::hmac;
use axum::body::Body;
use axum::http::{Method, Request, header};
use support::{TestApp, TestResponse, csrf_from};
use ui_helpers::*;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const WRONG: &str = "wrong password 123";

fn base_config(c: &mut AppConfig) {
    c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
}

async fn app() -> TestApp {
    let app = TestApp::with(base_config).await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
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
    identifier: &str,
    password: &str,
    extra: &[(&str, &str)],
) -> TestResponse {
    let (action, csrf) = open_form(app, "/ui/login").await;
    let mut pairs = vec![
        ("csrf_token", csrf.as_str()),
        ("identifier", identifier),
        ("password", password),
    ];
    pairs.extend_from_slice(extra);
    post_from(app, peer, &action, &pairs).await
}

async fn audit_count(app: &TestApp, action: AuditAction) -> usize {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                limit: 500,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit")
        .items
        .iter()
        .filter(|e| e.action == action)
        .count()
}

/// (status, Retry-After, page with per-flow values and the identifier normalised).
type Observed = (u16, Option<String>, String);

fn observe(resp: &TestResponse, identifier: &str) -> Observed {
    (
        resp.status.as_u16(),
        resp.header("retry-after").map(str::to_owned),
        normalize(&resp.html()).replace(identifier, "IDENT"),
    )
}

/// 5 wrong passwords, the 6th (locks 1 s), an immediate retry with the right password (still
/// locked), +1 s, a 7th wrong password (locks 2 s). Returns what each step answered.
async fn lock_sequence(app: &TestApp, identifier: &str) -> Vec<Observed> {
    let mut seen = Vec::new();
    for _ in 0..5 {
        let resp = login(app, "", identifier, WRONG).await;
        assert_eq!(resp.status, 400, "{}", resp.text());
        assert_eq!(
            message_keys(&resp.html()),
            vec!["login.invalid_credentials".to_owned()]
        );
        seen.push(observe(&resp, identifier));
    }
    let resp = login(app, "", identifier, WRONG).await;
    assert_eq!(resp.status, 429, "{}", resp.text());
    assert_eq!(resp.header("retry-after"), Some("1"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let html = resp.html();
    assert_eq!(
        message_keys(&html),
        vec!["login.too_many_attempts".to_owned()]
    );
    assert!(html.contains("Try again in 1 second."), "{html}");
    assert!(html.contains("id=\"login\""), "the form stays on the page");
    seen.push(observe(&resp, identifier));

    // Locked: even the right password is not looked at.
    let resp = login(app, "", identifier, PASSWORD).await;
    assert_eq!(resp.status, 429);
    assert!(session_cookie(app).is_none());
    seen.push(observe(&resp, identifier));

    app.clock().advance(Duration::from_secs(1));
    let resp = login(app, "", identifier, WRONG).await;
    assert_eq!(resp.status, 429);
    assert_eq!(resp.header("retry-after"), Some("2"));
    assert!(resp.html().contains("Try again in 2 seconds."));
    seen.push(observe(&resp, identifier));
    seen
}

#[tokio::test]
async fn failed_passwords_lock_progressively_and_success_resets() {
    let app = app().await;
    lock_sequence(&app, EMAIL).await;
    assert_eq!(
        audit_count(&app, AuditAction::RateLimitLockout).await,
        2,
        "one lockout event per transition to locked"
    );

    app.clock().advance(Duration::from_secs(2));
    let resp = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        session_cookie(&app).is_some(),
        "signed in after the lock window"
    );

    // The success reset the backoff: the next failure is an ordinary 400 again.
    app.clear_cookies();
    let resp = login(&app, "", EMAIL, WRONG).await;
    assert_eq!(resp.status, 400);
    assert!(resp.header("retry-after").is_none());
}

#[tokio::test]
async fn the_lock_is_per_identifier_and_ip() {
    let app = app().await;
    for _ in 0..6 {
        login(&app, "", EMAIL, WRONG).await;
    }
    assert_eq!(login(&app, "", EMAIL, PASSWORD).await.status, 429);
    // Another IP is not locked out by the first one's failures.
    let resp = login_from(&app, peer(7), EMAIL, PASSWORD, &[]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
}

#[tokio::test]
async fn unknown_identifiers_get_byte_identical_answers() {
    let known = app().await;
    let unknown = app().await;
    let a = lock_sequence(&known, EMAIL).await;
    let b = lock_sequence(&unknown, "nobody@example.com").await;
    assert_eq!(a.len(), b.len());
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(
            x, y,
            "step {i} differs between a known and an unknown identifier"
        );
    }
}

#[tokio::test]
async fn the_identifier_tier_delays_attempts_from_many_ips_without_captcha() {
    let app = TestApp::with(|c| {
        base_config(c);
        c.rate_limits.loose_threshold_per_hour = 5;
    })
    .await;
    register(&app, "", EMAIL, PASSWORD).await;
    for n in 1..=4 {
        let resp = login_from(&app, peer(n), EMAIL, WRONG, &[]).await;
        assert_eq!(resp.status, 400, "ip {n}");
    }
    // The failure that reaches the hourly threshold already answers with the delay.
    let resp = login_from(&app, peer(5), EMAIL, WRONG, &[]).await;
    assert_eq!(resp.status, 429, "{}", resp.text());
    assert_eq!(resp.header("retry-after"), Some("2"));
    // A sixth IP, right password: the short delay, password not checked.
    let resp = login_from(&app, peer(6), EMAIL, PASSWORD, &[]).await;
    assert_eq!(resp.status, 429, "{}", resp.text());
    assert_eq!(resp.header("retry-after"), Some("2"));
    assert!(resp.html().contains("Try again in 2 seconds."));
    assert!(session_cookie(&app).is_none());
    assert!(!resp.html().contains("captcha-widget"));
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
async fn with_captcha_the_identifier_tier_requires_a_verified_captcha_before_the_password() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string_contains("secret=provider-secret"))
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
    let app = TestApp::with(|c| {
        base_config(c);
        c.rate_limits.loose_threshold_per_hour = 5;
        // The mock listens on loopback: allow it (production policy blocks it).
        c.outbound = OutboundPolicy::loopback_dev();
        c.captcha_endpoints = CaptchaEndpoints {
            turnstile: format!("{uri}/siteverify"),
            hcaptcha: format!("{uri}/siteverify"),
        };
    })
    .await;
    register(&app, "", EMAIL, PASSWORD).await;
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

    // Below the threshold the page has no widget and the strict login CSP.
    let page = app.get("/ui/login").await;
    assert!(!page.html().contains("captcha-widget"));
    let csp = page.header("content-security-policy").expect("csp");
    assert!(!csp.contains("cloudflare"), "{csp}");

    for n in 1..=4 {
        let resp = login_from(&app, peer(n), EMAIL, WRONG, &[]).await;
        assert_eq!(resp.status, 400, "ip {n}");
    }
    // The failure that reaches the threshold already shows the widget for the next attempt.
    let resp = login_from(&app, peer(5), EMAIL, WRONG, &[]).await;
    assert_eq!(resp.status, 400);
    assert!(
        resp.html().contains("id=\"captcha-widget\""),
        "{}",
        resp.html()
    );

    let failed_before = audit_count(&app, AuditAction::LoginFailed).await;

    // No CAPTCHA response: refused before the password is checked (a wrong password would have
    // recorded login_failed), the widget is shown with the provider CSP on this page only.
    let resp = login_from(&app, peer(6), EMAIL, WRONG, &[]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let html = resp.html();
    assert_eq!(
        message_keys(&html),
        vec!["login.captcha_required".to_owned()]
    );
    assert!(
        html.contains("class=\"anvil-captcha cf-turnstile\""),
        "{html}"
    );
    assert!(html.contains("data-sitekey=\"site-key-123\""));
    assert!(
        html.contains(&format!("value=\"{EMAIL}\"")),
        "identifier echoed"
    );
    let csp = resp.header("content-security-policy").expect("csp");
    assert!(csp.contains("https://challenges.cloudflare.com"), "{csp}");
    assert!(!csp.contains("unsafe"), "{csp}");
    // The right password without a CAPTCHA does not sign in either.
    let resp = login_from(&app, peer(6), EMAIL, PASSWORD, &[]).await;
    assert_eq!(resp.status, 400);
    assert!(session_cookie(&app).is_none());

    // A response the provider rejects: refused, audited, password not checked.
    let resp = login_from(
        &app,
        peer(6),
        EMAIL,
        WRONG,
        &[("cf-turnstile-response", "bad-token")],
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.captcha_failed".to_owned()]
    );
    assert_eq!(audit_count(&app, AuditAction::CaptchaFailed).await, 1);
    assert_eq!(
        audit_count(&app, AuditAction::LoginFailed).await,
        failed_before,
        "the password was never verified while the CAPTCHA was missing or invalid"
    );

    // A verified CAPTCHA lets the attempt through to the password check.
    let resp = login_from(
        &app,
        peer(6),
        EMAIL,
        PASSWORD,
        &[("cf-turnstile-response", "good-token")],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
}

#[tokio::test]
async fn an_unreachable_captcha_provider_fails_closed() {
    let app = TestApp::with(|c| {
        base_config(c);
        c.rate_limits.loose_threshold_per_hour = 1;
        // Nothing listens here: verification is unavailable.
        // The mock listens on loopback: allow it (production policy blocks it).
        c.outbound = OutboundPolicy::loopback_dev();
        c.captcha_endpoints = CaptchaEndpoints {
            turnstile: "http://127.0.0.1:9/siteverify".into(),
            hcaptcha: "http://127.0.0.1:9/siteverify".into(),
        };
    })
    .await;
    register(&app, "", EMAIL, PASSWORD).await;
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
    login_from(&app, peer(1), EMAIL, WRONG, &[]).await;
    let resp = login_from(
        &app,
        peer(2),
        EMAIL,
        PASSWORD,
        &[("cf-turnstile-response", "any-token")],
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.captcha_failed".to_owned()]
    );
    assert!(session_cookie(&app).is_none());
}

// ---------------------------------------------------------------------------------------------
// Second factor and passkey
// ---------------------------------------------------------------------------------------------

fn totp_code(seed: &[u8], unix: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let counter = u64::try_from(unix / 30).expect("positive time");
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[off]) & 0x7f) << 24
        | u32::from(h[off + 1]) << 16
        | u32::from(h[off + 2]) << 8
        | u32::from(h[off + 3]);
    format!("{:06}", bin % 1_000_000)
}

/// Enrols TOTP for alice; returns the seed.
async fn enrol_totp(app: &TestApp) -> Vec<u8> {
    let tenant = default_tenant(app).id;
    let user = app
        .storage()
        .users()
        .get_by_email(tenant, EMAIL)
        .await
        .expect("lookup")
        .expect("user")
        .id;
    let id = CredentialId::new_v7();
    let seed = TotpSecret::generate();
    let secret_enc = app
        .kek()
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), seed.as_bytes())
        .expect("seal");
    let now = app.clock().now();
    app.storage()
        .users()
        .create_totp(
            tenant,
            user,
            &NewTotp {
                id,
                secret_enc,
                created_at: now,
            },
            &[],
            now,
        )
        .await
        .expect("totp");
    seed.as_bytes().to_vec()
}

async fn second_factor(app: &TestApp, page: &TestResponse, code: &str) -> TestResponse {
    let html = page.html();
    let token = hidden_inputs(&html)
        .into_iter()
        .find(|(n, _)| n == "factor_token")
        .map(|(_, v)| v)
        .expect("factor token");
    app.post_form(
        &form_action(app, &html),
        &[
            ("csrf_token", csrf_from(&html).as_str()),
            ("factor_token", token.as_str()),
            ("code", code),
        ],
    )
    .await
}

#[tokio::test]
async fn second_factor_attempts_are_throttled_per_user_and_reset_on_success() {
    let app = app().await;
    let seed = enrol_totp(&app).await;
    let page = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(page.status, 200);
    let good = totp_code(&seed, app.clock().now().unix_timestamp());
    let wrong = if good == "000000" { "111111" } else { "000000" };

    let mut last = page;
    for i in 0..5 {
        let resp = second_factor(&app, &last, wrong).await;
        assert_eq!(resp.status, 400, "attempt {i}: {}", resp.text());
        last = resp;
    }
    let resp = second_factor(&app, &last, wrong).await;
    assert_eq!(resp.status, 429, "{}", resp.text());
    assert_eq!(resp.header("retry-after"), Some("1"));
    assert!(resp.html().contains("Try again in 1 second."));
    assert!(resp.html().contains("id=\"second-factor\""), "form kept");
    assert_eq!(audit_count(&app, AuditAction::RateLimitLockout).await, 1);

    // Locked: the right code is not checked.
    let locked = second_factor(&app, &resp, &good).await;
    assert_eq!(locked.status, 429);
    assert!(locked.header("retry-after").is_some());
    assert!(session_cookie(&app).is_none());

    // A new password step does not reset the user's second-factor lock.
    app.clear_cookies();
    let page = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(second_factor(&app, &page, &good).await.status, 429);

    app.clock().advance(Duration::from_secs(1));
    let good = totp_code(&seed, app.clock().now().unix_timestamp());
    let resp = second_factor(&app, &page, &good).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());

    // Reset: a later wrong code is an ordinary 400.
    app.clear_cookies();
    let page = login(&app, "", EMAIL, PASSWORD).await;
    let resp = second_factor(&app, &page, wrong).await;
    assert_eq!(resp.status, 400);
}

#[tokio::test]
async fn passkey_failures_are_throttled_per_ip() {
    let app = app().await;
    let page = app.get("/ui/login").await;
    let html = page.html();
    let csrf = csrf_from(&html);
    let options = action_path(&app, &html, "data-options-url");
    let action = action_path(&app, &html, "action");
    // An assertion is verified (and counted) only against a challenge, so each attempt asks
    // for options first, like webauthn.js.
    let challenge = |peer: SocketAddr| {
        let (app, options, csrf) = (&app, &options, &csrf);
        async move {
            let resp = post_from(app, peer, options, &[("csrf_token", csrf)]).await;
            assert_eq!(resp.status, 200, "{}", resp.text());
        }
    };
    for i in 0..5 {
        challenge(support::DEFAULT_PEER).await;
        let resp = app
            .post_form(&action, &[("csrf_token", &csrf), ("response", "garbage")])
            .await;
        assert_eq!(resp.status, 400, "attempt {i}");
    }
    challenge(support::DEFAULT_PEER).await;
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("response", "garbage")])
        .await;
    assert_eq!(resp.status, 429, "{}", resp.text());
    assert_eq!(resp.header("retry-after"), Some("1"));
    // Another IP is unaffected.
    challenge(peer(9)).await;
    let resp = post_from(
        &app,
        peer(9),
        &action,
        &[("csrf_token", &csrf), ("response", "garbage")],
    )
    .await;
    assert_eq!(resp.status, 400);
}

/// An attribute of the passkey form (`action`, `data-options-url`) as a path.
fn action_path(app: &TestApp, html: &str, attr: &str) -> String {
    let form = &html[html.find("id=\"login-passkey\"").expect("passkey form")..];
    let marker = format!("{attr}=\"");
    let start = form.find(&marker).expect("attribute") + marker.len();
    let end = form[start..].find('"').expect("quoted") + start;
    to_path(app, &form[start..end].replace("&amp;", "&"))
}
