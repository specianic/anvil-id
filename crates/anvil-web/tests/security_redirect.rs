//! Redirect URI controls at the authorization endpoint (SEC-01, RFC 9700 §4.1): anything other
//! than an exactly registered URI renders the error page and never sends a `Location` header.

mod authz;
mod support;

use authz::*;
use axum::http::header::LOCATION;
use support::{TestApp, location};

/// Requests `client_id` with `redirect_uri`, otherwise valid.
async fn request(app: &TestApp, client_id: &str, redirect_uri: &str) -> support::TestResponse {
    let mut p = pkce_params(client_id);
    p.retain(|(k, _)| *k != "redirect_uri");
    p.push(("redirect_uri", redirect_uri));
    get(app, &authorize_path("", &p), None).await
}

fn assert_mismatch(resp: &support::TestResponse, case: &str) {
    assert_eq!(resp.status, 400, "{case}: {}", resp.text());
    assert!(resp.headers.get(LOCATION).is_none(), "{case}: no Location");
    let html = resp.html();
    assert!(
        html.contains("data-error-key=\"redirect_uri_mismatch\""),
        "{case}"
    );
    assert!(
        html.contains("The redirect URI in this request is not registered for this client."),
        "{case}: marker text"
    );
}

#[tokio::test]
async fn modified_redirect_uris_render_the_error_page() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    for (case, uri) in [
        ("unregistered", "https://evil.example/cb"),
        ("appended path", "https://rp.example/cb/extra"),
        ("added query", "https://rp.example/cb?x=1"),
        ("case-changed host", "https://RP.example/cb"),
        ("fragment", "https://rp.example/cb#frag"),
        ("trailing slash", "https://rp.example/cb/"),
        ("scheme downgrade", "http://rp.example/cb"),
    ] {
        assert_mismatch(&request(&app, &c.client_id, uri).await, case);
    }
}

#[tokio::test]
async fn web_client_port_change_is_rejected() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = web_client_with(&app, &t, &["https://rp.example:8443/cb"]).await;
    assert_mismatch(
        &request(&app, &c.client_id, "https://rp.example:9443/cb").await,
        "port",
    );
    // Even loopback gets no port flexibility for web clients.
    let c = web_client_with(&app, &t, &["http://127.0.0.1:8000/cb"]).await;
    assert_mismatch(
        &request(&app, &c.client_id, "http://127.0.0.1:9000/cb").await,
        "web loopback port",
    );
}

#[tokio::test]
async fn unknown_client_renders_the_error_page() {
    let app = TestApp::new().await;
    for client_id in ["no-such-client", ""] {
        let resp = request(&app, client_id, RP).await;
        assert_eq!(resp.status, 400, "{client_id:?}");
        assert!(resp.headers.get(LOCATION).is_none());
        let key = if client_id.is_empty() {
            "invalid_request"
        } else {
            "unknown_client"
        };
        assert!(
            resp.html().contains(&format!("data-error-key=\"{key}\"")),
            "{client_id:?}: {}",
            resp.html()
        );
    }
    let resp = request(&app, "no-such-client", RP).await;
    assert!(resp.html().contains("This application is not registered."));
}

#[tokio::test]
async fn native_loopback_ip_port_change_is_allowed() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = native_client(&app, &t, &["http://127.0.0.1:1234/cb"]).await;
    let mut p = pkce_params(&c.client_id);
    p.retain(|(k, _)| *k != "redirect_uri");
    p.push(("redirect_uri", "http://127.0.0.1:5555/cb"));
    p.push(("prompt", "none"));
    let resp = get(&app, &authorize_path("", &p), None).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with("http://127.0.0.1:5555/cb?"));
    assert_eq!(param(&resp, "error").as_deref(), Some("login_required"));
}

#[tokio::test]
async fn native_localhost_port_change_is_rejected() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = native_client(&app, &t, &["http://localhost:1234/cb"]).await;
    assert_mismatch(
        &request(&app, &c.client_id, "http://localhost:5555/cb").await,
        "localhost port",
    );
    // A different path on a loopback IP is still a mismatch.
    let c = native_client(&app, &t, &["http://127.0.0.1:1234/cb"]).await;
    assert_mismatch(
        &request(&app, &c.client_id, "http://127.0.0.1:5555/other").await,
        "loopback path",
    );
}

#[tokio::test]
async fn post_with_bad_redirect_uri_renders_the_error_page() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let mut p = pkce_params(&c.client_id);
    p.retain(|(k, _)| *k != "redirect_uri");
    p.push(("redirect_uri", "https://evil.example/cb"));
    assert_mismatch(&post(&app, "/authorize", &p, None).await, "POST");
}

#[tokio::test]
async fn bad_redirect_uri_wins_over_a_bad_response_type() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let path = authorize_path(
        "",
        &[
            ("response_type", "token"),
            ("client_id", &c.client_id),
            ("redirect_uri", "https://evil.example/cb"),
            ("scope", "openid"),
        ],
    );
    assert_mismatch(&get(&app, &path, None).await, "bad response_type");
}
