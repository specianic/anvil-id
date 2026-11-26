//! Phase 7 route skeletons (plan 07-04): the pre-declared routes of later plans answer 404 until
//! the owning plan implements them, never a fake success. Each owning plan deletes its case here
//! when it ships the route: 07-17 (admin user export). 07-13 shipped `/par` (tests in `par.rs`,
//! `security_par.rs`); 07-10 shipped
//! `/api/flows/v1`; its placement outside the UI Fetch-Metadata layer is pinned in
//! `security_headless.rs` (`headless_api_not_behind_ui_fetch_metadata`).

mod admin_support;
mod support;

use admin_support::{API, admin_token, call};
use axum::http::{Method, StatusCode};
use support::{TestApp, TestResponse};

fn assert_not_found(resp: &TestResponse, what: &str) {
    assert_eq!(
        resp.status,
        StatusCode::NOT_FOUND,
        "{what}: {}",
        resp.text()
    );
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
