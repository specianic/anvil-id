//! CAPTCHA verification (AUTH-09): server-side siteverify per provider, fail closed on every
//! error, no network call for an empty token, and the widget partial. The provider is a wiremock
//! server (test code only); production code takes the siteverify URL as a constructor argument.

use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::{CaptchaProvider, CaptchaSettings};
use anvil_web::adapters::captcha::{
    CaptchaEndpoints, CaptchaError, CaptchaVerifier, DEFAULT_TIMEOUT, HCAPTCHA_SITEVERIFY,
    TURNSTILE_SITEVERIFY,
};
use anvil_web::adapters::outbound::{OutboundClient, OutboundPolicy};
use anvil_web::render::Renderer;
use minijinja::context;
use secrecy::SecretString;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET: &str = "provider-secret";
const TOKEN: &str = "widget-token";

fn settings(provider: CaptchaProvider) -> CaptchaSettings {
    CaptchaSettings {
        provider,
        site_key: "site-key".into(),
        secret_sealed: String::new(),
    }
}

fn secret() -> SecretString {
    SecretString::from(SECRET.to_owned())
}

/// The development-mode outbound policy reaches the loopback mock.
fn outbound() -> Arc<OutboundClient> {
    Arc::new(OutboundClient::new(&OutboundPolicy::loopback_dev()).expect("outbound"))
}

async fn verifier(server: &MockServer, timeout: Duration) -> CaptchaVerifier {
    CaptchaVerifier::new(
        outbound(),
        CaptchaEndpoints {
            turnstile: format!("{}/turnstile/v0/siteverify", server.uri()),
            hcaptcha: format!("{}/hcaptcha/siteverify", server.uri()),
        },
        timeout,
    )
    .expect("verifier")
}

#[test]
fn defaults_are_the_provider_endpoints_and_five_seconds() {
    assert_eq!(
        TURNSTILE_SITEVERIFY,
        "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    );
    assert_eq!(HCAPTCHA_SITEVERIFY, "https://api.hcaptcha.com/siteverify");
    assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(5));
    let d = CaptchaEndpoints::default();
    assert_eq!(d.turnstile, TURNSTILE_SITEVERIFY);
    assert_eq!(d.hcaptcha, HCAPTCHA_SITEVERIFY);
}

#[tokio::test]
async fn turnstile_success_posts_secret_response_and_remoteip() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/turnstile/v0/siteverify"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("secret=provider-secret"))
        .and(body_string_contains("response=widget-token"))
        .and(body_string_contains("remoteip=198.51.100.7"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"success":true}"#))
        .expect(1)
        .mount(&server)
        .await;
    let v = verifier(&server, DEFAULT_TIMEOUT).await;
    v.verify(
        &settings(CaptchaProvider::Turnstile),
        &secret(),
        TOKEN,
        Some("198.51.100.7".parse().expect("ip")),
    )
    .await
    .expect("verified");
}

#[tokio::test]
async fn hcaptcha_uses_its_own_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hcaptcha/siteverify"))
        .and(body_string_contains("response=widget-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"success":true}"#))
        .expect(1)
        .mount(&server)
        .await;
    let v = verifier(&server, DEFAULT_TIMEOUT).await;
    v.verify(&settings(CaptchaProvider::Hcaptcha), &secret(), TOKEN, None)
        .await
        .expect("verified");
}

#[tokio::test]
async fn success_false_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"success":false,"error-codes":["invalid-input-response"]}"#),
        )
        .mount(&server)
        .await;
    let v = verifier(&server, DEFAULT_TIMEOUT).await;
    let err = v
        .verify(
            &settings(CaptchaProvider::Turnstile),
            &secret(),
            TOKEN,
            None,
        )
        .await
        .expect_err("rejected");
    assert!(matches!(err, CaptchaError::Rejected), "{err:?}");
}

#[tokio::test]
async fn http_error_fails_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string(r#"{"success":true}"#))
        .mount(&server)
        .await;
    let v = verifier(&server, DEFAULT_TIMEOUT).await;
    let err = v
        .verify(
            &settings(CaptchaProvider::Turnstile),
            &secret(),
            TOKEN,
            None,
        )
        .await
        .expect_err("fails closed");
    assert!(matches!(err, CaptchaError::Unavailable(_)), "{err:?}");
}

#[tokio::test]
async fn timeout_fails_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"success":true}"#)
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    let v = verifier(&server, Duration::from_millis(200)).await;
    let err = v
        .verify(&settings(CaptchaProvider::Hcaptcha), &secret(), TOKEN, None)
        .await
        .expect_err("timeout");
    assert!(matches!(err, CaptchaError::Unavailable(_)), "{err:?}");
}

#[tokio::test]
async fn malformed_json_fails_closed() {
    let server = MockServer::start().await;
    for body in ["not json", r#"{"ok":true}"#, r#"{"success":"true"}"#, ""] {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let v = verifier(&server, DEFAULT_TIMEOUT).await;
        let err = v
            .verify(
                &settings(CaptchaProvider::Turnstile),
                &secret(),
                TOKEN,
                None,
            )
            .await
            .expect_err(body);
        assert!(
            matches!(err, CaptchaError::Unavailable(_)),
            "{body}: {err:?}"
        );
    }
}

#[tokio::test]
async fn oversized_body_fails_closed() {
    let server = MockServer::start().await;
    let big = format!(r#"{{"success":true,"pad":"{}"}}"#, "x".repeat(64 * 1024));
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(big))
        .mount(&server)
        .await;
    let v = verifier(&server, DEFAULT_TIMEOUT).await;
    assert!(
        v.verify(
            &settings(CaptchaProvider::Turnstile),
            &secret(),
            TOKEN,
            None
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/turnstile/v0/siteverify"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/elsewhere", server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"success":true}"#))
        .expect(0)
        .mount(&server)
        .await;
    let v = verifier(&server, DEFAULT_TIMEOUT).await;
    assert!(
        v.verify(
            &settings(CaptchaProvider::Turnstile),
            &secret(),
            TOKEN,
            None
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn empty_token_is_rejected_without_a_network_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"success":true}"#))
        .expect(0)
        .mount(&server)
        .await;
    let v = verifier(&server, DEFAULT_TIMEOUT).await;
    for token in ["", "   "] {
        let err = v
            .verify(
                &settings(CaptchaProvider::Turnstile),
                &secret(),
                token,
                None,
            )
            .await
            .expect_err("empty");
        assert!(matches!(err, CaptchaError::MissingToken), "{err:?}");
    }
}

#[tokio::test]
async fn non_https_endpoints_are_refused() {
    let err = CaptchaVerifier::new(
        outbound(),
        CaptchaEndpoints {
            turnstile: "http://siteverify.example.test/x".into(),
            hcaptcha: HCAPTCHA_SITEVERIFY.into(),
        },
        DEFAULT_TIMEOUT,
    )
    .expect_err("plain http to a non-loopback host");
    assert!(matches!(err, CaptchaError::Config(_)));
}

#[tokio::test]
async fn production_outbound_policy_does_not_reach_a_loopback_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"success":true}"#))
        .expect(0)
        .mount(&server)
        .await;
    let prod = Arc::new(OutboundClient::new(&OutboundPolicy::default()).expect("outbound"));
    let v = CaptchaVerifier::new(
        prod,
        CaptchaEndpoints {
            turnstile: format!("{}/turnstile/v0/siteverify", server.uri()),
            hcaptcha: format!("{}/hcaptcha/siteverify", server.uri()),
        },
        DEFAULT_TIMEOUT,
    )
    .expect("loopback http passes the endpoint rule");
    let err = v
        .verify(
            &settings(CaptchaProvider::Turnstile),
            &secret(),
            TOKEN,
            None,
        )
        .await
        .expect_err("guard refuses plain http in production");
    assert!(matches!(err, CaptchaError::Unavailable(_)), "{err:?}");
}

fn render_partial(ctx: minijinja::Value) -> String {
    Renderer::new(None)
        .expect("theme")
        .page("captcha.html", ctx)
        .expect("partial renders")
        .0
}

#[test]
fn widget_partial_per_provider() {
    let t = render_partial(context! {
        captcha => context! { provider => "turnstile", site_key => "0x4AAA\"<x>" },
    });
    assert!(t.contains("class=\"anvil-captcha cf-turnstile\""), "{t}");
    assert!(t.contains("id=\"captcha-widget\""));
    assert!(
        t.contains("data-sitekey=\"0x4AAA&quot;&lt;x&gt;\""),
        "site key is escaped: {t}"
    );
    assert!(t.contains("src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\""));
    assert!(t.contains("<noscript>"));
    assert!(!t.contains("hcaptcha"));

    let h = render_partial(context! {
        captcha => context! { provider => "hcaptcha", site_key => "10000000-ffff" },
    });
    assert!(h.contains("class=\"anvil-captcha h-captcha\""), "{h}");
    assert!(h.contains("data-sitekey=\"10000000-ffff\""));
    assert!(h.contains("src=\"https://js.hcaptcha.com/1/api.js\""));
    assert!(!h.contains("cloudflare"));

    // Without CAPTCHA settings the partial renders nothing external.
    let none = render_partial(context! {});
    assert!(!none.contains("<script"), "{none}");
    assert!(!none.contains("https://"));
}
