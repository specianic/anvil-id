//! PKCE, nonce, response type and request-object controls at the authorization endpoint
//! (SEC-01, OIDC-02). Once the client and redirect URI are trusted, every failure is a `303`
//! error redirect carrying `iss`.

mod authz;
mod support;

use authz::*;
use support::TestApp;

async fn send(app: &TestApp, pairs: &[(&str, &str)]) -> support::TestResponse {
    get(app, &authorize_path("", pairs), None).await
}

fn without<'a>(mut p: Vec<(&'a str, &'a str)>, keys: &[&str]) -> Vec<(&'a str, &'a str)> {
    p.retain(|(k, _)| !keys.contains(k));
    p
}

#[tokio::test]
async fn pkce_violations_are_invalid_request() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let base = pkce_params(&c.client_id);

    let missing = without(base.clone(), &["code_challenge", "code_challenge_method"]);
    let mut plain = without(base.clone(), &["code_challenge_method"]);
    plain.push(("code_challenge_method", "plain"));
    let no_method = without(base.clone(), &["code_challenge_method"]);
    let mut malformed = without(base.clone(), &["code_challenge"]);
    malformed.push(("code_challenge", "too-short"));
    let mut bad_chars = without(base.clone(), &["code_challenge"]);
    bad_chars.push((
        "code_challenge",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM",
    ));
    let method_only = without(base.clone(), &["code_challenge"]);

    for (case, p) in [
        ("missing challenge", missing),
        ("plain", plain),
        ("challenge without method", no_method),
        ("malformed challenge", malformed),
        ("non-base64url challenge", bad_chars),
        ("method without challenge", method_only),
    ] {
        let resp = send(&app, &p).await;
        assert_error_redirect(&resp, RP, "invalid_request", &iss);
        assert_eq!(param(&resp, "state").as_deref(), Some("st-1"), "{case}");
    }
}

#[tokio::test]
async fn public_native_client_always_needs_pkce() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = native_client(&app, &t, &["http://127.0.0.1:1234/cb"]).await;
    let resp = send(
        &app,
        &[
            ("response_type", "code"),
            ("client_id", &c.client_id),
            ("redirect_uri", "http://127.0.0.1:1234/cb"),
            ("scope", "openid"),
            ("nonce", "n-1"),
        ],
    )
    .await;
    assert_error_redirect(&resp, "http://127.0.0.1:1234/cb", "invalid_request", &iss);
}

#[tokio::test]
async fn opted_out_confidential_client_may_omit_pkce_and_nonce() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = no_pkce_client(&app, &t).await;
    let p = without(
        pkce_params(&c.client_id),
        &["code_challenge", "code_challenge_method"],
    );
    assert_login_redirect(&send(&app, &p).await, &iss);

    let mut with_nonce = p.clone();
    with_nonce.push(("nonce", "n-1"));
    assert_login_redirect(&send(&app, &with_nonce).await, &iss);

    // Opting out never relaxes S256-only.
    let mut plain = p.clone();
    plain.push((
        "code_challenge",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    ));
    plain.push(("code_challenge_method", "plain"));
    assert_error_redirect(&send(&app, &plain).await, RP, "invalid_request", &iss);
}

#[tokio::test]
async fn pkce_required_client_without_pkce_is_rejected_even_with_nonce() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let mut p = without(
        pkce_params(&c.client_id),
        &["code_challenge", "code_challenge_method"],
    );
    p.push(("nonce", "n-1"));
    assert_error_redirect(&send(&app, &p).await, RP, "invalid_request", &iss);
}

#[tokio::test]
async fn implicit_and_hybrid_response_types_are_unsupported() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    for rt in [
        "token",
        "id_token",
        "code id_token",
        "code token",
        "id_token token",
    ] {
        let mut p = without(pkce_params(&c.client_id), &["response_type"]);
        p.push(("response_type", rt));
        p.push(("nonce", "n-1"));
        let resp = send(&app, &p).await;
        assert_error_redirect(&resp, RP, "unsupported_response_type", &iss);
    }
    let p = without(pkce_params(&c.client_id), &["response_type"]);
    assert_error_redirect(&send(&app, &p).await, RP, "invalid_request", &iss);
}

#[tokio::test]
async fn request_objects_are_not_supported() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let mut p = pkce_params(&c.client_id);
    p.push(("request", "x"));
    assert_error_redirect(&send(&app, &p).await, RP, "request_not_supported", &iss);
    let mut p = pkce_params(&c.client_id);
    p.push(("request_uri", "x"));
    assert_error_redirect(&send(&app, &p).await, RP, "request_uri_not_supported", &iss);
}

#[tokio::test]
async fn duplicate_parameters_are_invalid_request() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let mut p = pkce_params(&c.client_id);
    p.push(("state", "st-2"));
    assert_error_redirect(&send(&app, &p).await, RP, "invalid_request", &iss);
    let mut p = pkce_params(&c.client_id);
    p.push(("code_challenge", CHALLENGE));
    assert_error_redirect(&send(&app, &p).await, RP, "invalid_request", &iss);
}

#[tokio::test]
async fn missing_openid_scope_is_invalid_scope() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let mut p = without(pkce_params(&c.client_id), &["scope"]);
    p.push(("scope", "profile"));
    assert_error_redirect(&send(&app, &p).await, RP, "invalid_scope", &iss);
}
