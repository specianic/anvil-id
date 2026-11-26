//! Phase 7 route skeletons (plan 07-04): the pre-declared routes of later plans answer 404 until
//! the owning plan implements them, never a fake success. Each owning plan deletes its case here
//! when it ships the route: 07-13 (`/par`), 07-10 (`/api/flows/v1`), 07-17 (admin user export).
//!
//! `api_flows_not_behind_ui_fetch_metadata` pins where the headless API is merged: outside the
//! UI Fetch-Metadata layer, which would answer a cross-site `POST` with 403.

mod admin_support;
mod support;

use admin_support::{API, admin_token, call};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use support::{TestApp, TestResponse};

async fn post_json(app: &TestApp, path: &str, sec_fetch_site: Option<&str>) -> TestResponse {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(site) = sec_fetch_site {
        req = req.header("sec-fetch-site", site);
    }
    app.send(req.body(Body::from("{}")).expect("request")).await
}

fn assert_not_found(resp: &TestResponse, what: &str) {
    assert_eq!(
        resp.status,
        StatusCode::NOT_FOUND,
        "{what}: {}",
        resp.text()
    );
}

#[tokio::test]
async fn par_is_not_served_yet() {
    let app = TestApp::new().await;
    let resp = app
        .post_form(
            "/t/default/par",
            &[("client_id", "app"), ("response_type", "code")],
        )
        .await;
    assert_not_found(&resp, "POST /t/default/par");
}

#[tokio::test]
async fn flows_api_is_not_served_yet() {
    let app = TestApp::new().await;
    let resp = post_json(&app, "/t/default/api/flows/v1/login", Some("same-origin")).await;
    assert_not_found(&resp, "POST /t/default/api/flows/v1/login");
    // A JSON surface, not the HTML 404 page.
    assert_eq!(
        resp.header("content-type"),
        Some("application/problem+json")
    );
    let resp = app.get("/t/default/api/flows/v1/login/x").await;
    assert_not_found(&resp, "GET /t/default/api/flows/v1/login/x");
}

#[tokio::test]
async fn admin_user_export_is_not_served_yet() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:read").await;
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/export"),
        Some(&token),
        None,
    )
    .await;
    assert_not_found(&resp, "GET users/export");
}

#[tokio::test]
async fn api_flows_not_behind_ui_fetch_metadata() {
    let app = TestApp::new().await;
    let resp = post_json(&app, "/t/default/api/flows/v1/login", Some("cross-site")).await;
    assert_ne!(
        resp.status,
        StatusCode::FORBIDDEN,
        "the UI Fetch-Metadata layer must not cover /api/flows"
    );
    assert_not_found(&resp, "cross-site POST /t/default/api/flows/v1/login");
}
