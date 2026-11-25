//! The authorization endpoint over HTTP: login redirects, session reuse, prompt, max_age,
//! id_token_hint, POST parity and `/authorize/continue`.

mod authz;
mod support;

use std::time::Duration;

use anvil_core::ports::Clock;
use authz::*;
use support::{TestApp, location};

fn with<'a>(
    mut p: Vec<(&'a str, &'a str)>,
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    p.extend_from_slice(extra);
    p
}

fn assert_code_redirect(resp: &support::TestResponse, iss: &str, state: &str) -> String {
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(resp).starts_with(&format!("{RP}?")),
        "{}",
        location(resp)
    );
    assert_eq!(param(resp, "state").as_deref(), Some(state));
    assert_eq!(param(resp, "iss").as_deref(), Some(iss));
    assert!(param(resp, "error").is_none());
    let code = param(resp, "code").expect("code");
    assert_eq!(code.len(), 43);
    code
}

#[tokio::test]
async fn no_session_redirects_to_login() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let resp = get(&app, &authorize_path("", &pkce_params(&c.client_id)), None).await;
    let id = assert_login_redirect(&resp, &iss);
    assert!(uuid::Uuid::parse_str(&id).is_ok(), "{id}");
    assert!(
        resp.header("access-control-allow-origin").is_none(),
        "no CORS on /authorize"
    );
}

#[tokio::test]
async fn session_with_prompt_none_issues_a_code() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let cookie = session(&app, &t, u).await;
    let p = with(pkce_params(&c.client_id), &[("prompt", "none")]);
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    assert_code_redirect(&resp, &iss, "st-1");

    // Without prompt the existing session is reused too.
    let resp = get(
        &app,
        &authorize_path("", &pkce_params(&c.client_id)),
        Some(&cookie),
    )
    .await;
    assert_code_redirect(&resp, &iss, "st-1");
}

#[tokio::test]
async fn prompt_none_without_session_is_login_required_and_keeps_a_long_state() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let state = "s".repeat(2048);
    let mut p = pkce_params(&c.client_id);
    p.retain(|(k, _)| *k != "state");
    p.push(("state", &state));
    p.push(("prompt", "none"));
    let resp = get(&app, &authorize_path("", &p), None).await;
    assert_error_redirect(&resp, RP, "login_required", &iss);
    assert_eq!(param(&resp, "state").as_deref(), Some(state.as_str()));
}

#[tokio::test]
async fn prompt_login_then_continue_issues_a_code() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let old = session(&app, &t, u).await;
    // The old sign-in happened before this authorization request.
    app.clock().advance(Duration::from_secs(60));
    let p = with(pkce_params(&c.client_id), &[("prompt", "login")]);
    let resp = get(&app, &authorize_path("", &p), Some(&old)).await;
    let id = assert_login_redirect(&resp, &iss);

    // The old session does not satisfy prompt=login on continue either.
    let path = format!("/authorize/continue?request={id}");
    let resp = get(&app, &path, Some(&old)).await;
    assert_login_redirect(&resp, &iss);

    // Simulate the login flow: a newer session.
    app.clock().advance(Duration::from_secs(1));
    let fresh = session(&app, &t, u).await;
    let resp = get(&app, &path, Some(&fresh)).await;
    assert_code_redirect(&resp, &iss, "st-1");

    // The request is single-use.
    let resp = get(&app, &path, Some(&fresh)).await;
    assert_error_page(&resp, "flow_expired");
}

#[tokio::test]
async fn continue_after_login_from_no_session() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let resp = get(&app, &authorize_path("", &pkce_params(&c.client_id)), None).await;
    let id = assert_login_redirect(&resp, &iss);
    let cookie = session(&app, &t, u).await;
    let resp = get(
        &app,
        &format!("/authorize/continue?request={id}"),
        Some(&cookie),
    )
    .await;
    assert_code_redirect(&resp, &iss, "st-1");
}

#[tokio::test]
async fn continue_with_unknown_or_malformed_request_is_flow_expired() {
    let app = TestApp::new().await;
    for path in [
        "/authorize/continue",
        "/authorize/continue?request=not-a-uuid",
        "/authorize/continue?request=0192f0c4-7a1b-7c3d-8e9f-0123456789ab",
    ] {
        assert_error_page(&get(&app, path, None).await, "flow_expired");
    }
}

#[tokio::test]
async fn continue_expires_with_the_request() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let resp = get(&app, &authorize_path("", &pkce_params(&c.client_id)), None).await;
    let id = assert_login_redirect(&resp, &iss);
    app.clock().advance(Duration::from_secs(16 * 60));
    let cookie = session(&app, &t, u).await;
    let resp = get(
        &app,
        &format!("/authorize/continue?request={id}"),
        Some(&cookie),
    )
    .await;
    assert_error_page(&resp, "flow_expired");
}

#[tokio::test]
async fn max_age_exceeded_requires_login() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let cookie = session(&app, &t, u).await;
    app.clock().advance(Duration::from_secs(2));
    let p = with(pkce_params(&c.client_id), &[("max_age", "1")]);
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    assert_login_redirect(&resp, &iss);

    // A generous max_age reuses the session.
    let p = with(pkce_params(&c.client_id), &[("max_age", "3600")]);
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    assert_code_redirect(&resp, &iss, "st-1");
}

#[tokio::test]
async fn post_behaves_like_get() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let resp = post(&app, "/authorize", &pkce_params(&c.client_id), None).await;
    assert_login_redirect(&resp, &iss);

    let u = user(&app, &t, "alice@example.com").await;
    let cookie = session(&app, &t, u).await;
    let p = with(pkce_params(&c.client_id), &[("prompt", "none")]);
    let resp = post(&app, "/authorize", &p, Some(&cookie)).await;
    assert_code_redirect(&resp, &iss, "st-1");

    let mut bad = pkce_params(&c.client_id);
    bad.retain(|(k, _)| *k != "code_challenge_method");
    bad.push(("code_challenge_method", "plain"));
    let resp = post(&app, "/authorize", &bad, None).await;
    assert_error_redirect(&resp, RP, "invalid_request", &iss);
}

#[tokio::test]
async fn post_requires_a_form_body() {
    let app = TestApp::new().await;
    let req = axum::http::Request::post("/authorize")
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{}"))
        .expect("request");
    assert_error_page(&app.send(req).await, "invalid_request");
}

#[tokio::test]
async fn display_ui_locales_and_unknown_params_are_accepted() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let p = with(
        pkce_params(&c.client_id),
        &[
            ("display", "popup"),
            ("ui_locales", "de-CH en"),
            ("x_unknown", "1"),
            ("claims_locales", "en"),
        ],
    );
    assert_login_redirect(&get(&app, &authorize_path("", &p), None).await, &iss);
}

#[tokio::test]
async fn id_token_hint_for_another_user_with_prompt_none_is_login_required() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let alice = user(&app, &t, "alice@example.com").await;
    let bob = user(&app, &t, "bob@example.com").await;
    let cookie = session(&app, &t, alice).await;

    let row = app
        .storage()
        .keys()
        .active(t.id, "RS256")
        .await
        .expect("key lookup")
        .expect("active key");
    let signer = anvil_core::service::key::open_key(app.kek(), &row).expect("open key");
    let now = app.clock().now().unix_timestamp();
    let hint_for = |sub: String| {
        signer
            .sign_jwt(
                Some("JWT"),
                &serde_json::json!({
                    "iss": iss,
                    "sub": sub,
                    "aud": c.client_id,
                    "iat": now,
                    "exp": now + 300,
                }),
            )
            .expect("sign hint")
    };

    let bob_hint = hint_for(bob.to_string());
    let p = with(
        pkce_params(&c.client_id),
        &[("prompt", "none"), ("id_token_hint", &bob_hint)],
    );
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    assert_error_redirect(&resp, RP, "login_required", &iss);

    // The matching hint issues a code.
    let alice_hint = hint_for(alice.to_string());
    let p = with(
        pkce_params(&c.client_id),
        &[("prompt", "none"), ("id_token_hint", &alice_hint)],
    );
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    assert_code_redirect(&resp, &iss, "st-1");

    // A hint that does not verify is invalid_request with prompt=none.
    let p = with(
        pkce_params(&c.client_id),
        &[("prompt", "none"), ("id_token_hint", "not.a.jwt")],
    );
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    assert_error_redirect(&resp, RP, "invalid_request", &iss);
}

#[tokio::test]
async fn path_tenant_session_is_scoped_to_the_tenant() {
    let app = TestApp::new().await;
    let acme = path_tenant(&app, "acme").await;
    let iss = app.issuer(Some("acme"));
    let c = web_client(&app, &acme).await;
    let u = user(&app, &acme, "alice@example.com").await;
    let cookie = session(&app, &acme, u).await;
    let p = with(pkce_params(&c.client_id), &[("prompt", "none")]);
    let resp = get(&app, &authorize_path("/t/acme", &p), Some(&cookie)).await;
    assert_code_redirect(&resp, &iss, "st-1");
}
