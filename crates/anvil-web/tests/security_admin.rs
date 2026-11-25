//! Negative tests for management API authentication and authorisation (QUAL-01): every way a
//! request can lack the right credentials is rejected.

mod admin_support;
mod support;

use std::time::Duration;

use admin_support::*;
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::json;
use support::TestApp;

fn tenants() -> String {
    format!("{API}/tenants")
}

fn assert_unauthorized(resp: &support::TestResponse) {
    let body = assert_problem(resp, 401);
    assert_eq!(body["type"], "urn:anvilid:problem:invalid_token");
    let challenge = resp.header("www-authenticate").expect("WWW-Authenticate");
    assert!(challenge.starts_with("Bearer"), "{challenge}");
}

fn assert_insufficient_scope(resp: &support::TestResponse) {
    let body = assert_problem(resp, 403);
    assert_eq!(body["type"], "urn:anvilid:problem:insufficient_scope");
    let challenge = resp.header("www-authenticate").expect("WWW-Authenticate");
    assert!(
        challenge.starts_with("Bearer") && challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
}

#[tokio::test]
async fn missing_or_malformed_authorization_is_401() {
    let app = TestApp::new().await;
    let resp = call(&app, Method::GET, &tenants(), None, None).await;
    assert_unauthorized(&resp);
    // No credentials at all: a challenge without an error code (RFC 6750 §3.1).
    assert!(!resp.header("www-authenticate").unwrap().contains("error="));

    let token = admin_token(&app, "admin:read").await;
    for value in [
        format!("Basic {token}"),
        "Bearer".to_owned(),
        "Bearer ".to_owned(),
        format!("Bearer {token} extra"),
        "Bearer not.a.jwt".to_owned(),
    ] {
        let req = Request::get(tenants())
            .header(header::AUTHORIZATION, value.clone())
            .body(Body::empty())
            .unwrap();
        let resp = app.send(req).await;
        assert_unauthorized(&resp);
        assert!(
            resp.header("www-authenticate")
                .unwrap()
                .contains("error=\"invalid_token\""),
            "{value}"
        );
    }

    // Tokens in the query string are not accepted.
    let resp = call(
        &app,
        Method::GET,
        &format!("{}?access_token={token}", tenants()),
        None,
        None,
    )
    .await;
    assert_ne!(resp.status, 200);

    // The same token in the header works (positive control).
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn tampered_token_is_401() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let sig = parts[2].clone();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    parts[2] = format!("{flipped}{}", &sig[1..]);
    let resp = call(&app, Method::GET, &tenants(), Some(&parts.join(".")), None).await;
    assert_unauthorized(&resp);
}

#[tokio::test]
async fn id_token_as_bearer_is_401() {
    let app = TestApp::new().await;
    let client_id = system_client(&app, &["admin:write"]).await;
    let id_token = mint_system_id_token(&app, &client_id).await;
    let resp = call(&app, Method::GET, &tenants(), Some(&id_token), None).await;
    assert_unauthorized(&resp);
}

#[tokio::test]
async fn access_token_of_another_tenant_is_401() {
    let app = TestApp::new().await;
    let default = app.default.as_ref().unwrap();
    let client_id = system_client(&app, &["admin:write"]).await;

    // A genuine default-tenant token (default key, default issuer).
    let token = mint_access_token(
        &app,
        default,
        &app.issuer(None),
        &client_id,
        "admin:read admin:write",
    )
    .await;
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_unauthorized(&resp);

    // The default tenant's key claiming the system issuer.
    let token = mint_access_token(
        &app,
        default,
        &system_issuer(&app),
        &client_id,
        "admin:read admin:write",
    )
    .await;
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_unauthorized(&resp);

    // The system key with another issuer.
    let system = app.system.as_ref().unwrap();
    let token = mint_access_token(
        &app,
        system,
        &app.issuer(Some("default")),
        &client_id,
        "admin:write",
    )
    .await;
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_unauthorized(&resp);
}

#[tokio::test]
async fn expired_token_is_401() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:read").await;
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_eq!(resp.status, 200);
    app.clock().advance(Duration::from_secs(11 * 60));
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_unauthorized(&resp);
}

#[tokio::test]
async fn token_of_a_deleted_client_is_401() {
    let app = TestApp::new().await;
    let admin = admin_token(&app, "admin:write").await;
    let client_id = system_client(&app, &["admin:read"]).await;
    let system = app.system.as_ref().unwrap();
    let token =
        mint_access_token(&app, system, &system_issuer(&app), &client_id, "admin:read").await;
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_eq!(resp.status, 200);

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/system/clients/{client_id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_unauthorized(&resp);
}

#[tokio::test]
async fn read_scope_cannot_write() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:read").await;
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_eq!(resp.status, 200);
    let resp = call(
        &app,
        Method::POST,
        &tenants(),
        Some(&token),
        Some(json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    assert_insufficient_scope(&resp);
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(&token),
        Some(json!({"email": "x@example.com", "invite": true})),
    )
    .await;
    assert_insufficient_scope(&resp);
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default"),
        Some(&token),
        None,
    )
    .await;
    assert_insufficient_scope(&resp);
}

#[tokio::test]
async fn resource_scopes_are_confined_to_their_resource() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:users:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(&token),
        Some(json!({"email": "erin@example.com", "invite": true})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);

    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/clients"),
        Some(&token),
        Some(json!({"name": "x", "client_type": "public", "redirect_uris": ["https://a.example/cb"]})),
    )
    .await;
    assert_insufficient_scope(&resp);
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/clients"),
        Some(&token),
        None,
    )
    .await;
    assert_insufficient_scope(&resp);
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_insufficient_scope(&resp);

    // admin:clients:read reads clients only.
    let token = admin_token(&app, "admin:clients:read").await;
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/clients"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/clients"),
        Some(&token),
        Some(json!({"name": "x", "client_type": "public", "redirect_uris": ["https://a.example/cb"]})),
    )
    .await;
    assert_insufficient_scope(&resp);
}

#[tokio::test]
async fn system_clients_need_full_admin() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:clients:write").await;
    let cc = json!({
        "name": "escalation",
        "client_type": "confidential",
        "grant_types": ["client_credentials"],
        "scopes": ["admin:write"],
    });

    // Allowed in an application tenant.
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/clients"),
        Some(&token),
        Some(cc.clone()),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());

    // In the system tenant a client can carry admin scopes: admin:clients:write must not mint
    // or take over one.
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/system/clients"),
        Some(&token),
        Some(cc.clone()),
    )
    .await;
    assert_insufficient_scope(&resp);
    let existing = system_client(&app, &["admin:write"]).await;
    for (method, path, body) in [
        (
            Method::POST,
            format!("{API}/tenants/system/clients/{existing}/secret"),
            None,
        ),
        (
            Method::PATCH,
            format!("{API}/tenants/system/clients/{existing}"),
            Some(json!({"name": "mine"})),
        ),
        (
            Method::DELETE,
            format!("{API}/tenants/system/clients/{existing}"),
            None,
        ),
    ] {
        let resp = call(&app, method, &path, Some(&token), body).await;
        assert_insufficient_scope(&resp);
    }
    // Reading system clients is fine (no secrets are returned).
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/system/clients/{existing}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);

    // admin:write may.
    let admin = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/system/clients"),
        Some(&admin),
        Some(cc),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
}

#[tokio::test]
async fn admin_api_is_installation_level_only() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:read admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &tenants(),
        Some(&token),
        Some(json!({"slug": "acme", "display_name": "Acme", "host": "login.acme.test"})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());

    for path in [
        "/t/acme/api/admin/v1/tenants",
        "/t/default/api/admin/v1/tenants",
        "/t/system/api/admin/v1/tenants",
        "/t/acme/api/admin/v1/openapi.json",
    ] {
        let resp = call(&app, Method::GET, path, Some(&token), None).await;
        assert_eq!(resp.status, 404, "{path}: {}", resp.text());
    }

    // Host-based tenant.
    let req = Request::get(tenants())
        .header(header::HOST, "login.acme.test")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.send(req).await;
    assert_eq!(resp.status, 404, "{}", resp.text());

    // Positive control at the root.
    let resp = call(&app, Method::GET, &tenants(), Some(&token), None).await;
    assert_eq!(resp.status, 200);
}
