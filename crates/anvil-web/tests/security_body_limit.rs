//! Request body limit (UI-03 review of 04-18's per-request middleware) on the selected backend
//! (`ANVILID_TEST_DB`): every route family answers 413 for a body one byte above
//! [`anvil_web::BODY_LIMIT`] (64 KiB), whether it is announced in `Content-Length` or streamed
//! without it (refused while it is read). Form pages, the admin JSON API, `/token` and `/logout`
//! all answer exactly 413 in both cases: the form and admin JSON extractor rejections go through
//! one shared check (`ui::login::rejection_is_too_large`). Only the two branding logo
//! upload routes (tenant and client) accept more, up to [`LOGO_BODY_LIMIT`] (400 KiB): one byte
//! above it is 413 there too, and a 100 KiB logo goes through.
//!
//! The route match itself (`admin::branding::is_logo_upload`) is crate-private; this test pins
//! its effect from outside.

mod admin_support;
mod support;
mod ui_helpers;

use admin_support::{API, admin_token, call};
use anvil_cache::limiter::RateQuota;
use anvil_web::BODY_LIMIT;
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::json;
use support::{TestApp, TestResponse, json as body_json};
use ui_helpers::open_form;

/// The logo upload limit (`admin::branding::LOGO_BODY_LIMIT`, crate-private).
const LOGO_BODY_LIMIT: usize = 400 * 1024;

/// The 8-byte PNG signature (the logo check sniffs it).
const PNG_SIGNATURE: &[u8] = &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

/// A request with `body` of `content_type`, an optional bearer token and, when `announce`, a
/// `Content-Length` header (without it the limit applies while the body is read).
async fn send(
    app: &TestApp,
    method: Method,
    path: &str,
    token: Option<&str>,
    content_type: &str,
    body: String,
    announce: bool,
) -> TestResponse {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, content_type)
        .header("sec-fetch-site", "same-origin");
    if announce {
        req = req.header(header::CONTENT_LENGTH, body.len());
    }
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    app.send(req.body(Body::from(body)).expect("request")).await
}

/// A form body of exactly `len` bytes.
fn form_of_len(len: usize) -> String {
    let body = format!("x={}", "a".repeat(len - 2));
    assert_eq!(body.len(), len);
    body
}

/// A JSON object body `{"key":"aaa…"}` of exactly `len` bytes.
fn json_of_len(key: &str, len: usize) -> String {
    let overhead = format!(r#"{{"{key}":""}}"#).len();
    let body = format!(r#"{{"{key}":"{}"}}"#, "a".repeat(len - overhead));
    assert_eq!(body.len(), len);
    body
}

/// Asserts exactly 413 for an oversized body announced in `Content-Length`, and exactly 413 for
/// the same body streamed without it (refused while it is read; the handler never runs).
async fn assert_413(
    app: &TestApp,
    method: Method,
    path: &str,
    token: Option<&str>,
    content_type: &str,
    body: &str,
) {
    let resp = send(
        app,
        method.clone(),
        path,
        token,
        content_type,
        body.to_owned(),
        true,
    )
    .await;
    assert_eq!(resp.status, 413, "{method} {path}: {}", resp.text());
    let resp = send(
        app,
        method.clone(),
        path,
        token,
        content_type,
        body.to_owned(),
        false,
    )
    .await;
    assert_eq!(
        resp.status,
        413,
        "{method} {path} (streamed): {}",
        resp.text()
    );
    if path.contains("/api/admin/") {
        // Admin API failures stay problem documents.
        let problem = body_json(&resp);
        assert_eq!(problem["status"], 413, "{problem}");
    }
}

const FORM: &str = "application/x-www-form-urlencoded";
const JSON: &str = "application/json";

#[tokio::test]
async fn protocol_and_page_routes_answer_413_above_64_kib() {
    let app = app().await;
    let big = form_of_len(BODY_LIMIT + 1);
    assert_413(&app, Method::POST, "/token", None, FORM, &big).await;
    assert_413(&app, Method::POST, "/logout", None, FORM, &big).await;
    let (action, _) = open_form(&app, "/ui/login").await;
    assert!(action.starts_with("/ui/login?flow="), "{action}");
    assert_413(&app, Method::POST, &action, None, FORM, &big).await;
}

#[tokio::test]
async fn admin_json_routes_answer_413_above_64_kib() {
    let app = app().await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let big = json_of_len("slug", BODY_LIMIT + 1);
    assert_413(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&t),
        JSON,
        &big,
    )
    .await;
    let big = json_of_len("display_name", BODY_LIMIT + 1);
    assert_413(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default"),
        Some(&t),
        JSON,
        &big,
    )
    .await;
    // Branding settings are not the logo route: they keep the 64 KiB limit.
    let big = json_of_len("custom_css", BODY_LIMIT + 1);
    assert_413(
        &app,
        Method::PUT,
        &format!("{API}/tenants/default/branding"),
        Some(&t),
        JSON,
        &big,
    )
    .await;
}

/// The 413 mapping only fires for the size limit: other extractor rejections keep their 400.
#[tokio::test]
async fn other_body_rejections_stay_400() {
    let app = app().await;
    let (action, _) = open_form(&app, "/ui/login").await;
    // A form page posted with a non-form content type.
    let resp = send(
        &app,
        Method::POST,
        &action,
        None,
        JSON,
        "{}".to_owned(),
        false,
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    // Malformed JSON on the admin API.
    let t = admin_token(&app, "admin:read admin:write").await;
    let resp = send(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&t),
        JSON,
        "{".to_owned(),
        false,
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(body_json(&resp)["status"], 400);
}

#[tokio::test]
async fn logo_uploads_accept_up_to_400_kib_and_no_more() {
    let app = app().await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/clients"),
        Some(&t),
        Some(json!({
            "name": "Branded app",
            "client_type": "confidential",
            "redirect_uris": ["https://rp.example/cb"],
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let client_id = body_json(&resp)["client_id"]
        .as_str()
        .expect("client_id")
        .to_owned();
    let routes = [
        format!("{API}/tenants/default/branding/logo"),
        format!("{API}/tenants/default/clients/{client_id}/branding/logo"),
    ];

    let too_big = json_of_len("data", LOGO_BODY_LIMIT + 1);
    // A 100 KiB PNG (signature plus padding), base64 in the JSON upload body.
    let mut png = PNG_SIGNATURE.to_vec();
    png.resize(100 * 1024, 0);
    let logo = json!({ "data": anvil_jose::encoding::b64std(&png) }).to_string();
    assert!(
        logo.len() > BODY_LIMIT,
        "the logo is above the general limit"
    );

    for route in &routes {
        assert_413(&app, Method::PUT, route, Some(&t), JSON, &too_big).await;
        let resp = send(&app, Method::PUT, route, Some(&t), JSON, logo.clone(), true).await;
        assert_ne!(resp.status, 413, "{route}");
        assert_eq!(resp.status, 200, "{route}: {}", resp.text());
    }
}
