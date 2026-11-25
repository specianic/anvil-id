//! RFC 9207: every authorization response (success and error) carries exactly one `iss` equal to
//! the tenant's issuer.

mod authz;
mod support;

use authz::*;
use support::TestApp;

#[tokio::test]
async fn success_redirect_has_iss() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let cookie = session(&app, &t, u).await;
    let mut p = pkce_params(&c.client_id);
    p.push(("prompt", "none"));
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(param(&resp, "code").is_some());
    assert_eq!(param(&resp, "iss").as_deref(), Some(iss.as_str()));
}

#[tokio::test]
async fn login_required_redirect_has_iss() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let mut p = pkce_params(&c.client_id);
    p.push(("prompt", "none"));
    let resp = get(&app, &authorize_path("", &p), None).await;
    assert_error_redirect(&resp, RP, "login_required", &iss);
}

#[tokio::test]
async fn invalid_request_redirect_has_iss() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let mut p = pkce_params(&c.client_id);
    p.retain(|(k, _)| *k != "code_challenge_method");
    p.push(("code_challenge_method", "plain"));
    let resp = get(&app, &authorize_path("", &p), None).await;
    assert_error_redirect(&resp, RP, "invalid_request", &iss);
}

#[tokio::test]
async fn path_tenant_iss() {
    let app = TestApp::new().await;
    let t = path_tenant(&app, "acme").await;
    let c = web_client(&app, &t).await;
    let mut p = pkce_params(&c.client_id);
    p.push(("prompt", "none"));
    let resp = get(&app, &authorize_path("/t/acme", &p), None).await;
    assert_error_redirect(&resp, RP, "login_required", "https://op.test/t/acme");
    assert_eq!(app.issuer(Some("acme")), "https://op.test/t/acme");

    // Login redirects stay inside the tenant.
    p.retain(|(k, _)| *k != "prompt");
    let resp = get(&app, &authorize_path("/t/acme", &p), None).await;
    assert_login_redirect(&resp, "https://op.test/t/acme");
}

#[tokio::test]
async fn iss_is_added_even_if_the_client_sends_one() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let mut p = pkce_params(&c.client_id);
    p.push(("prompt", "none"));
    p.push(("iss", "https://evil.example"));
    let resp = get(&app, &authorize_path("", &p), None).await;
    // `param` asserts there is exactly one iss.
    assert_eq!(param(&resp, "iss").as_deref(), Some(iss.as_str()));
}
