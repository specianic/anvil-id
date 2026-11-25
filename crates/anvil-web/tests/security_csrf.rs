//! CSRF defences of the self-service forms (SEC-04): the per-flow synchronizer token, the flow
//! cookie binding and the Fetch-Metadata layer. Selected backend via `ANVILID_TEST_DB`.

mod support;
mod ui_helpers;

use axum::body::Body;
use axum::http::{Method, Request, header};
use support::{TestApp, TestResponse};
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

/// A login form POST with explicit headers (no `Sec-Fetch-Site` unless given).
async fn raw_post(
    app: &TestApp,
    action: &str,
    pairs: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> TestResponse {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(action)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    app.send(b.body(Body::from(body)).expect("request")).await
}

fn assert_csrf_rejected(resp: &TestResponse, what: &str) {
    assert_eq!(resp.status, 403, "{what}: {}", resp.text());
    assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"), "{what}");
    assert!(
        session_cookie_header(resp).is_none(),
        "{what}: no session cookie"
    );
}

fn session_cookie_header(resp: &TestResponse) -> Option<String> {
    resp.headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.contains("anvil_session_"))
        .map(str::to_owned)
}

async fn app() -> TestApp {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
}

#[tokio::test]
async fn missing_csrf_token_is_403() {
    let app = app().await;
    let (action, _) = open_form(&app, "/ui/login").await;
    let resp = app
        .post_form(&action, &[("identifier", EMAIL), ("password", PASSWORD)])
        .await;
    assert_csrf_rejected(&resp, "missing csrf_token");
}

#[tokio::test]
async fn wrong_csrf_token_is_403() {
    let app = app().await;
    let (action, csrf) = open_form(&app, "/ui/login").await;
    let wrong = format!("{}x", &csrf[..csrf.len() - 1]);
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &wrong),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_csrf_rejected(&resp, "wrong csrf_token");
}

#[tokio::test]
async fn csrf_token_of_another_flow_is_403() {
    let app = app().await;
    let (action, _) = open_form(&app, "/ui/login").await;
    let (_, other_csrf) = open_form(&app, "/ui/login").await;
    // The second GET replaced the flow cookie; neither token pair matches the first flow.
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &other_csrf),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_csrf_rejected(&resp, "foreign flow");
}

#[tokio::test]
async fn missing_flow_cookie_is_403() {
    let app = app().await;
    let (action, csrf) = open_form(&app, "/ui/login").await;
    app.clear_cookies();
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_csrf_rejected(&resp, "missing flow cookie");
}

#[tokio::test]
async fn missing_flow_id_is_403() {
    let app = app().await;
    let (_, csrf) = open_form(&app, "/ui/login").await;
    let resp = app
        .post_form(
            "/ui/login",
            &[
                ("csrf_token", &csrf),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_csrf_rejected(&resp, "missing flow id");
}

#[tokio::test]
async fn cross_site_fetch_metadata_is_403() {
    let app = app().await;
    let (action, csrf) = open_form(&app, "/ui/login").await;
    let pairs = [
        ("csrf_token", csrf.as_str()),
        ("identifier", EMAIL),
        ("password", PASSWORD),
    ];
    let resp = raw_post(&app, &action, &pairs, &[("sec-fetch-site", "cross-site")]).await;
    assert_csrf_rejected(&resp, "Sec-Fetch-Site: cross-site");
    let resp = raw_post(&app, &action, &pairs, &[("origin", "https://evil.test")]).await;
    assert_csrf_rejected(&resp, "foreign Origin");
}

#[tokio::test]
async fn valid_token_without_fetch_headers_is_accepted() {
    let app = app().await;
    let (action, csrf) = open_form(&app, "/ui/login").await;
    let resp = raw_post(
        &app,
        &action,
        &[
            ("csrf_token", &csrf),
            ("identifier", EMAIL),
            ("password", PASSWORD),
        ],
        &[],
    )
    .await;
    assert_ne!(resp.status, 403, "{}", resp.text());
    assert_eq!(resp.status, 200);
    assert!(session_cookie_header(&resp).is_some(), "signed in");
}

#[tokio::test]
async fn same_origin_header_is_accepted() {
    let app = app().await;
    let (action, csrf) = open_form(&app, "/ui/login").await;
    let resp = raw_post(
        &app,
        &action,
        &[
            ("csrf_token", &csrf),
            ("identifier", EMAIL),
            ("password", PASSWORD),
        ],
        &[("origin", "https://op.test")],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn every_form_page_rejects_a_missing_token() {
    let app = app().await;
    for page in [
        "/ui/registration",
        "/ui/recovery",
        "/ui/verification?token=t",
    ] {
        let (action, _) = open_form(&app, page).await;
        let resp = app.post_form(&action, &[("email", EMAIL)]).await;
        assert_eq!(resp.status, 403, "{page}");
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"), "{page}");
    }
}
