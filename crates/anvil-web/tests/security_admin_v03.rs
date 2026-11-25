//! Negative tests for the 0.3 connection routes (SEC-03): every operation rejects a missing
//! token (401) and a token without the settings scope (403), read scopes never write, another
//! tenant's connection is 404 through every route, the system tenant's connections need
//! `admin:write`, and the connection secret is never returned, not even in validation errors.

mod admin_support;
mod support;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};

const SECRET: &str = "connection-secret-never-disclosed-5c1e";

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

struct Route {
    method: Method,
    path: String,
    body: Option<Value>,
    write: bool,
}

fn google(slug: &str) -> Value {
    json!({"slug": slug, "display_name": "Google",
           "config": {"type": "social", "provider": "google", "client_id": "c"},
           "secret": SECRET})
}

fn routes() -> Vec<Route> {
    let base = format!("{API}/tenants/default/connections");
    let id = uuid::Uuid::now_v7();
    let r = |method, path: String, body, write| Route {
        method,
        path,
        body,
        write,
    };
    vec![
        r(Method::GET, base.clone(), None, false),
        r(Method::POST, base.clone(), Some(google("scoped")), true),
        r(Method::GET, format!("{base}/{id}"), None, false),
        r(
            Method::PATCH,
            format!("{base}/{id}"),
            Some(json!({"enabled": false})),
            true,
        ),
        r(Method::DELETE, format!("{base}/{id}"), None, true),
        r(
            Method::PUT,
            format!("{base}/{id}/secret"),
            Some(json!({"secret": SECRET})),
            true,
        ),
    ]
}

async fn send(app: &TestApp, route: &Route, token: Option<&str>) -> TestResponse {
    call(
        app,
        route.method.clone(),
        &route.path,
        token,
        route.body.clone(),
    )
    .await
}

fn what(route: &Route) -> String {
    format!("{} {}", route.method, route.path)
}

fn assert_forbidden(resp: &TestResponse, what: &str) {
    let body = assert_problem(resp, 403);
    assert_eq!(
        body["type"], "urn:anvilid:problem:insufficient_scope",
        "{what}"
    );
}

fn assert_allowed(resp: &TestResponse, what: &str) {
    let s = resp.status.as_u16();
    assert!(
        s != 401 && s != 403 && s < 500,
        "{what}: {s} {}",
        resp.text()
    );
    if s != 204 {
        assert_eq!(resp.header("cache-control"), Some("no-store"), "{what}");
    }
    assert!(!resp.text().contains(SECRET), "{what}: {}", resp.text());
}

#[tokio::test]
async fn every_connection_route_rejects_a_missing_token() {
    let app = app().await;
    for route in routes() {
        let resp = send(&app, &route, None).await;
        assert_problem(&resp, 401);
        assert!(
            resp.header("www-authenticate")
                .is_some_and(|c| c.starts_with("Bearer")),
            "{}",
            what(&route)
        );
    }
}

#[tokio::test]
async fn every_connection_route_requires_the_settings_scope() {
    let app = app().await;
    let unrelated = admin_token(
        &app,
        "admin:tenants:write admin:clients:write admin:users:write",
    )
    .await;
    let settings_read = admin_token(&app, "admin:settings:read").await;
    let broad_read = admin_token(&app, "admin:read").await;
    let settings_write = admin_token(&app, "admin:settings:write").await;
    let full = admin_token(&app, "admin:write").await;
    for route in routes() {
        let w = what(&route);
        assert_forbidden(&send(&app, &route, Some(&unrelated)).await, &w);
        for token in [&settings_read, &broad_read] {
            let resp = send(&app, &route, Some(token)).await;
            if route.write {
                assert_forbidden(&resp, &w);
            } else {
                assert_allowed(&resp, &w);
            }
        }
        assert_allowed(&send(&app, &route, Some(&settings_write)).await, &w);
        assert_allowed(&send(&app, &route, Some(&full)).await, &w);
    }
}

#[tokio::test]
async fn another_tenants_connection_is_not_found() {
    let app = app().await;
    let full = admin_token(&app, "admin:read admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&full),
        Some(json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/acme/connections"),
        Some(&full),
        Some(google("google")),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let id = body_json(&resp)["id"].as_str().unwrap().to_owned();

    let wrong = format!("{API}/tenants/default/connections/{id}");
    for (method, path, body) in [
        (Method::GET, wrong.clone(), None),
        (
            Method::PATCH,
            wrong.clone(),
            Some(json!({"enabled": false})),
        ),
        (
            Method::PUT,
            format!("{wrong}/secret"),
            Some(json!({"secret": null})),
        ),
        (Method::DELETE, wrong.clone(), None),
    ] {
        let resp = call(&app, method.clone(), &path, Some(&full), body).await;
        assert_problem(&resp, 404);
    }
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/connections"),
        Some(&full),
        None,
    )
    .await;
    assert_eq!(body_json(&resp)["items"], json!([]));

    // The connection is unchanged in its own tenant.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/acme/connections/{id}"),
        Some(&full),
        None,
    )
    .await;
    let c = body_json(&resp);
    assert_eq!(c["enabled"], true);
    assert_eq!(c["secret_configured"], true);
    // Malformed ids are unknown connections too.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/acme/connections/not-a-uuid"),
        Some(&full),
        None,
    )
    .await;
    assert_problem(&resp, 404);
}

#[tokio::test]
async fn system_tenant_connections_need_admin_write() {
    let app = app().await;
    let settings = admin_token(&app, "admin:settings:write").await;
    let path = format!("{API}/tenants/system/connections");
    let resp = call(
        &app,
        Method::POST,
        &path,
        Some(&settings),
        Some(google("g")),
    )
    .await;
    assert_forbidden(&resp, "POST system connections");
    // Reads are not affected.
    let resp = call(&app, Method::GET, &path, Some(&settings), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let full = admin_token(&app, "admin:write").await;
    let resp = call(&app, Method::POST, &path, Some(&full), Some(google("g"))).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert!(!resp.text().contains(SECRET));
}

#[tokio::test]
async fn the_secret_is_never_echoed_in_validation_errors() {
    let app = app().await;
    let full = admin_token(&app, "admin:read admin:write").await;
    let base = format!("{API}/tenants/default/connections");
    let bodies = [
        // Invalid slug, oversized/controlled secret, Apple without a valid key, schema error.
        json!({"slug": "BAD", "display_name": "x",
               "config": {"type": "social", "provider": "google", "client_id": "c"},
               "secret": SECRET}),
        json!({"slug": "g", "display_name": "x",
               "config": {"type": "social", "provider": "google", "client_id": "c"},
               "secret": format!("{SECRET}\n")}),
        json!({"slug": "a", "display_name": "x",
               "config": {"type": "social", "provider": "apple", "client_id": "c",
                          "apple": {"team_id": "T1", "key_id": "K1"}},
               "secret": SECRET}),
        json!({"slug": "g", "display_name": "x", "config": {"type": "nope"}, "secret": SECRET}),
        json!({"slug": "g", "display_name": "x", "unknown": 1, "secret": SECRET,
               "config": {"type": "social", "provider": "google", "client_id": "c"}}),
    ];
    for body in bodies {
        let resp = call(&app, Method::POST, &base, Some(&full), Some(body)).await;
        assert!(resp.status.as_u16() == 422, "{}", resp.text());
        assert!(!resp.text().contains(SECRET), "{}", resp.text());
    }
    // Nothing was stored.
    let resp = call(&app, Method::GET, &base, Some(&full), None).await;
    assert_eq!(body_json(&resp)["items"], json!([]));
}
