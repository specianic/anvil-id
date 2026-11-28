//! `GET /api/admin/v1/system/info`: the running version is disclosed to console administrators
//! only (a system-tenant token with at least one admin scope). Missing tokens, tokens of an
//! application tenant and org-admin tokens are 401; a system-tenant token without any admin
//! scope is 403. No public endpoint, header or error body carries the version.

mod admin_support;
mod support;
mod token_support;

use admin_support::{
    API, add_member, admin_token, assert_problem, call, create_org, create_role, mint_access_token,
    org_admin_token, system_client, system_issuer,
};
use anvil_core::service::admin_scope::ALL_ADMIN_SCOPES;
use axum::body::Body;
use axum::http::{Method, Request};
use support::{TestApp, TestResponse, json};
use token_support::seed_user;

/// A version string no other part of the server could produce by accident.
const VERSION: &str = "9.87.6-sysinfo-sentinel";

fn info() -> String {
    format!("{API}/system/info")
}

async fn app() -> TestApp {
    TestApp::with(|c| {
        c.rate_limits.enabled = false;
        c.server_version = Some(VERSION.to_owned());
    })
    .await
}

fn assert_no_version(what: &str, resp: &TestResponse) {
    assert!(
        !resp.text().contains(VERSION),
        "{what} discloses the version in its body"
    );
    for (name, value) in &resp.headers {
        assert!(
            !value.to_str().unwrap_or_default().contains(VERSION),
            "{what} discloses the version in header {name}"
        );
    }
}

#[tokio::test]
async fn system_info_without_a_token_is_401() {
    let app = app().await;
    let resp = call(&app, Method::GET, &info(), None, None).await;
    let body = assert_problem(&resp, 401);
    assert_eq!(body["type"], "urn:anvilid:problem:invalid_token");
    assert!(resp.header("www-authenticate").is_some());
    assert_no_version("401", &resp);

    let resp = call(&app, Method::GET, &info(), Some("not.a.jwt"), None).await;
    assert_problem(&resp, 401);
    assert_no_version("401 (malformed token)", &resp);
}

#[tokio::test]
async fn system_info_refuses_application_tenant_and_org_admin_tokens() {
    let app = app().await;
    let default = app.default.as_ref().expect("installed");

    // An application client of the default tenant (its key, its issuer), even claiming admin
    // scopes.
    let client_id = system_client(&app, &["admin:read"]).await;
    let token = mint_access_token(&app, default, &app.issuer(None), &client_id, "admin:read").await;
    let resp = call(&app, Method::GET, &info(), Some(&token), None).await;
    assert_problem(&resp, 401);
    assert_no_version("application tenant token", &resp);

    // An org admin of the default tenant.
    let tenant = default.tenant.clone();
    let org = create_org(&app, tenant.id, "acme").await;
    let role = create_role(&app, tenant.id, Some(org.id), "org-admins", &["org:admin"]).await;
    let user = seed_user(&app, tenant.id, "ada@example.test").await;
    add_member(&app, tenant.id, org.id, user.id, &[role.id]).await;
    let token = org_admin_token(&app, &tenant, org.id, user.id).await.token;
    let resp = call(&app, Method::GET, &info(), Some(&token), None).await;
    assert_problem(&resp, 401);
    assert_no_version("org admin token", &resp);
}

#[tokio::test]
async fn system_info_without_an_admin_scope_is_403() {
    let app = app().await;
    let system = app.system.as_ref().expect("installed");
    // A system-tenant token that carries no admin scope (e.g. a console sign-in of a user
    // without an administrator role).
    let client_id = system_client(&app, &["openid", "profile"]).await;
    let token = mint_access_token(
        &app,
        system,
        &system_issuer(&app),
        &client_id,
        "openid profile",
    )
    .await;
    let resp = call(&app, Method::GET, &info(), Some(&token), None).await;
    let body = assert_problem(&resp, 403);
    assert_eq!(body["type"], "urn:anvilid:problem:insufficient_scope");
    assert_no_version("403", &resp);
}

#[tokio::test]
async fn system_info_answers_any_admin_scope_with_the_configured_version() {
    let app = app().await;
    for scope in ALL_ADMIN_SCOPES {
        let token = admin_token(&app, scope).await;
        let resp = call(&app, Method::GET, &info(), Some(&token), None).await;
        assert_eq!(resp.status, 200, "{scope}: {}", resp.text());
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        assert_eq!(
            json(&resp),
            serde_json::json!({ "version": VERSION, "smtp_configured": false }),
            "{scope}"
        );
    }
}

/// rc.4: `smtp_configured` reflects the installation SMTP transport (`smtp_url`), for admins
/// only (the 401/403 tests above cover the same endpoint).
#[tokio::test]
async fn system_info_reports_whether_installation_smtp_is_configured() {
    for configured in [false, true] {
        let app = TestApp::with(|c| {
            c.rate_limits.enabled = false;
            c.server_version = Some(VERSION.to_owned());
            c.installation_smtp = configured;
        })
        .await;
        let token = admin_token(&app, "admin:read").await;
        let resp = call(&app, Method::GET, &info(), Some(&token), None).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        assert_eq!(json(&resp)["smtp_configured"], configured);
        // Never anything about the transport itself.
        assert!(!resp.text().contains("smtp://"), "{}", resp.text());

        // Still admin-only.
        let resp = call(&app, Method::GET, &info(), None, None).await;
        assert_problem(&resp, 401);
    }
}

#[tokio::test]
async fn system_info_without_a_configured_version_is_an_error_not_a_guess() {
    let app = TestApp::with(|c| c.rate_limits.enabled = false).await;
    let token = admin_token(&app, "admin:read").await;
    let resp = call(&app, Method::GET, &info(), Some(&token), None).await;
    assert_problem(&resp, 500);
}

#[tokio::test]
async fn public_endpoints_never_disclose_the_version() {
    let app = app().await;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/t/system/.well-known/openid-configuration",
        "/jwks",
        "/t/system/jwks",
        "/health/live",
        "/health/ready",
        "/healthz",
        "/readyz",
        "/ui/login",
        "/ui/registration",
        "/ui/recovery",
        "/console/",
        "/api/admin/v1/openapi.json",
        "/does-not-exist",
        "/api/admin/v1/does-not-exist",
        "/api/flows/v1/does-not-exist",
    ] {
        let resp = app.get(path).await;
        assert_no_version(path, &resp);
    }
    // An error body of the token endpoint.
    let req = Request::post("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("grant_type=nonsense"))
        .expect("request");
    let resp = app.send(req).await;
    assert_no_version("/token error", &resp);
}
