//! Negative tests for the 0.2 management API routes (QUAL-01): every new operation rejects a
//! missing token (401), a token of another tenant (401) and a token without the matching scope
//! (403), accepts its resource scope and the broad scopes, answers `Cache-Control: no-store`, and
//! never discloses the CAPTCHA secret or the SMTP password.

mod admin_support;
mod support;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use anvil_core::model::UserId;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, TestResponse};

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

/// One new operation: method, path, body, the resource scope and whether it writes.
struct Route {
    method: Method,
    path: String,
    body: Option<Value>,
    resource: &'static str,
    write: bool,
}

fn routes() -> Vec<Route> {
    let user = UserId::new_v7();
    let other = UserId::new_v7();
    let base = format!("{API}/tenants/default");
    let r = |method: Method, path: String, body: Option<Value>, resource, write| Route {
        method,
        path,
        body,
        resource,
        write,
    };
    let template = json!({"subject": "Hi {{ tenant_name }}", "body_html": "<p>{{ link }}</p>", "body_text": "{{ link }}"});
    let smtp =
        json!({"host": "127.0.0.1", "port": 2525, "from": "noreply@example.com", "tls": "none"});
    vec![
        r(
            Method::GET,
            format!("{base}/sessions"),
            None,
            "sessions",
            false,
        ),
        r(
            Method::DELETE,
            format!("{base}/sessions/{other}"),
            None,
            "sessions",
            true,
        ),
        r(
            Method::GET,
            format!("{base}/users/{user}/sessions"),
            None,
            "sessions",
            false,
        ),
        r(
            Method::DELETE,
            format!("{base}/users/{user}/sessions"),
            None,
            "sessions",
            true,
        ),
        r(
            Method::GET,
            format!("{base}/users/{user}/credentials"),
            None,
            "users",
            false,
        ),
        r(
            Method::DELETE,
            format!("{base}/users/{user}/credentials/{other}"),
            None,
            "users",
            true,
        ),
        r(
            Method::GET,
            format!("{base}/audit-events"),
            None,
            "audit",
            false,
        ),
        r(
            Method::GET,
            format!("{base}/email-templates"),
            None,
            "settings",
            false,
        ),
        r(
            Method::GET,
            format!("{base}/email-templates/verification"),
            None,
            "settings",
            false,
        ),
        r(
            Method::PUT,
            format!("{base}/email-templates/verification"),
            Some(template),
            "settings",
            true,
        ),
        r(
            Method::DELETE,
            format!("{base}/email-templates/verification"),
            None,
            "settings",
            true,
        ),
        r(Method::GET, format!("{base}/smtp"), None, "settings", false),
        r(
            Method::PUT,
            format!("{base}/smtp"),
            Some(smtp),
            "settings",
            true,
        ),
        r(
            Method::DELETE,
            format!("{base}/smtp"),
            None,
            "settings",
            true,
        ),
        r(
            Method::POST,
            format!("{base}/smtp/test"),
            Some(json!({"to": "ops@example.com"})),
            "settings",
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

fn describe(route: &Route) -> String {
    format!("{} {}", route.method, route.path)
}

fn assert_no_store(resp: &TestResponse, what: &str) {
    if resp.status.as_u16() != 204 {
        assert_eq!(resp.header("cache-control"), Some("no-store"), "{what}");
    }
}

fn assert_unauthorized(resp: &TestResponse, what: &str) {
    assert_eq!(resp.status.as_u16(), 401, "{what}: {}", resp.text());
    let body = assert_problem(resp, 401);
    assert_eq!(body["type"], "urn:anvilid:problem:invalid_token", "{what}");
    assert!(
        resp.header("www-authenticate")
            .is_some_and(|c| c.starts_with("Bearer")),
        "{what}"
    );
    assert_no_store(resp, what);
}

fn assert_forbidden(resp: &TestResponse, what: &str) {
    assert_eq!(resp.status.as_u16(), 403, "{what}: {}", resp.text());
    let body = assert_problem(resp, 403);
    assert_eq!(
        body["type"], "urn:anvilid:problem:insufficient_scope",
        "{what}"
    );
    assert_no_store(resp, what);
}

fn assert_allowed(resp: &TestResponse, what: &str) {
    let s = resp.status.as_u16();
    assert!(s != 401 && s != 403, "{what}: {s} {}", resp.text());
    assert!(s < 500, "{what}: {s} {}", resp.text());
    assert_no_store(resp, what);
}

#[tokio::test]
async fn every_new_route_rejects_a_missing_token() {
    let app = app().await;
    for route in routes() {
        let resp = send(&app, &route, None).await;
        assert_unauthorized(&resp, &describe(&route));
    }
}

#[tokio::test]
async fn every_new_route_rejects_tokens_of_another_tenant() {
    let app = app().await;
    let default = app.default.as_ref().unwrap();
    let client_id = system_client(&app, &["admin:write"]).await;
    // A genuine default-tenant token, and the default key claiming the system issuer.
    let tokens = [
        mint_access_token(
            &app,
            default,
            &app.issuer(None),
            &client_id,
            "admin:read admin:write",
        )
        .await,
        mint_access_token(
            &app,
            default,
            &system_issuer(&app),
            &client_id,
            "admin:read admin:write",
        )
        .await,
    ];
    for token in &tokens {
        for route in routes() {
            let resp = send(&app, &route, Some(token)).await;
            assert_unauthorized(&resp, &describe(&route));
        }
    }
}

#[tokio::test]
async fn every_new_route_requires_its_scope() {
    let app = app().await;
    let unrelated = admin_token(
        &app,
        "admin:tenants:write admin:clients:write admin:users:read",
    )
    .await;
    let broad_read = admin_token(&app, "admin:read").await;
    for route in routes() {
        let what = describe(&route);
        // A token for other resources only (users:read does satisfy credential reads).
        let resp = send(&app, &route, Some(&unrelated)).await;
        if route.resource == "users" && !route.write {
            assert_allowed(&resp, &what);
        } else {
            assert_forbidden(&resp, &what);
        }
        // Read scopes never grant writes.
        let own_read = admin_token(&app, &format!("admin:{}:read", route.resource)).await;
        for token in [&own_read, &broad_read] {
            let resp = send(&app, &route, Some(token)).await;
            if route.write {
                assert_forbidden(&resp, &what);
            } else {
                assert_allowed(&resp, &what);
            }
        }
    }
}

#[tokio::test]
async fn every_new_route_accepts_its_resource_scope_and_admin_write() {
    let app = app().await;
    let full = admin_token(&app, "admin:write").await;
    for route in routes() {
        let what = describe(&route);
        let own_write = admin_token(&app, &format!("admin:{}:write", route.resource)).await;
        assert_allowed(&send(&app, &route, Some(&own_write)).await, &what);
        assert_allowed(&send(&app, &route, Some(&full)).await, &what);
    }
}

#[tokio::test]
async fn tenant_signing_and_captcha_settings_need_the_tenants_write_scope() {
    let app = app().await;
    let settings = admin_token(&app, "admin:settings:write admin:tenants:read").await;
    for body in [
        json!({"settings": {"signing_algs": ["ES256"]}}),
        json!({"settings": {"captcha": {"provider": "turnstile", "site_key": "k", "secret": "s"}}}),
    ] {
        let resp = call(
            &app,
            Method::PATCH,
            &format!("{API}/tenants/default"),
            Some(&settings),
            Some(body),
        )
        .await;
        assert_forbidden(&resp, "PATCH /tenants/default");
    }
    let stored = app
        .storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.settings.signing_algs, vec!["RS256"]);
    assert!(stored.settings.captcha.is_none());
}

#[tokio::test]
async fn captcha_secret_and_smtp_password_are_never_disclosed() {
    let app = app().await;
    let full = admin_token(&app, "admin:read admin:write").await;
    let captcha_secret = "captcha-secret-never-shown-42";
    let smtp_password = "smtp-password-never-shown-42";
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default"),
        Some(&full),
        Some(json!({"settings": {"captcha": {"provider": "turnstile", "site_key": "site", "secret": captcha_secret}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(
        &app,
        Method::PUT,
        &format!("{API}/tenants/default/smtp"),
        Some(&full),
        Some(json!({
            "host": "127.0.0.1", "port": 2525, "username": "mailer",
            "password": smtp_password, "from": "noreply@example.com", "tls": "none",
        })),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let sealed = app
        .storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap()
        .settings
        .captcha
        .unwrap()
        .secret_sealed;

    for path in [
        "/tenants",
        "/tenants/default",
        "/tenants/default/smtp",
        "/tenants/default/audit-events?limit=200",
        "/tenants/system/audit-events?limit=200",
        "/openapi.json",
    ] {
        let resp = call(
            &app,
            Method::GET,
            &format!("{API}{path}"),
            Some(&full),
            None,
        )
        .await;
        assert_eq!(resp.status, 200, "{path}: {}", resp.text());
        let text = resp.text();
        for needle in [captcha_secret, smtp_password, sealed.as_str()] {
            assert!(!text.contains(needle), "{path} discloses a secret");
        }
        assert!(!text.contains("secret_sealed") && !text.contains("password_enc"));
    }
}
