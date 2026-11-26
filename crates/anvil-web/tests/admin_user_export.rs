//! User export over the management API (ADM-09, plan 07-17) on the selected backend
//! (`ANVILID_TEST_DB`): the single user export, the GDPR data-subject bundle (every inventory
//! category present) and the streamed NDJSON bulk export over more than one page.

mod admin_support;
mod support;

use admin_support::{API, admin_token, call};
use anvil_cache::limiter::RateQuota;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use support::{TestApp, json as body_json};

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

/// Imports `n` users without passwords through the import route; returns their ids.
async fn import_users(app: &TestApp, n: usize) -> Vec<String> {
    let token = admin_token(app, "admin:users:write").await;
    let body: String = (0..n)
        .map(|i| {
            json!({"email": format!("user{i:03}@example.com"), "email_verified": true,
                   "claims": {"name": format!("User {i}")}})
            .to_string()
                + "\n"
        })
        .collect();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{API}/tenants/default/users/import"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from(body))
        .expect("request");
    let resp = app.send(req).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let report = body_json(&resp);
    assert_eq!(report["counts"]["created"], n as u64, "{report}");
    report["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["user_id"].as_str().unwrap().to_owned())
        .collect()
}

/// A user with a password, created through the admin API.
async fn create_user(app: &TestApp, email: &str) -> String {
    let token = admin_token(app, "admin:users:write").await;
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(&token),
        Some(
            json!({"email": email, "password": "a long enough password 1",
                    "email_verified": true, "claims": {"given_name": "Ada"}}),
        ),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    body_json(&resp)["id"].as_str().unwrap().to_owned()
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

#[tokio::test]
async fn single_user_export_has_the_documented_fields() {
    let app = app().await;
    let id = create_user(&app, "single@example.com").await;
    let token = admin_token(&app, "admin:users:export").await;
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/{id}/export"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let doc = body_json(&resp);
    assert_eq!(doc["id"], id.as_str());
    assert_eq!(doc["email"], "single@example.com");
    assert_eq!(doc["claims"]["given_name"], "Ada");
    assert_eq!(
        keys(&doc),
        [
            "attributes",
            "claims",
            "created_at",
            "credentials",
            "email",
            "email_verified",
            "id",
            "identity_links",
            "last_login_at",
            "organizations",
            "roles",
            "status",
            "updated_at",
            "username",
        ]
    );
    assert_eq!(doc["credentials"][0]["kind"], "password");
    assert!(doc.get("password_hash").is_none());

    // Unknown users (and non-UUID ids) are 404.
    for other in [uuid::Uuid::now_v7().to_string(), "nope".to_owned()] {
        let resp = call(
            &app,
            Method::GET,
            &format!("{API}/tenants/default/users/{other}/export"),
            Some(&token),
            None,
        )
        .await;
        admin_support::assert_problem(&resp, 404);
    }
}

#[tokio::test]
async fn gdpr_bundle_has_every_inventory_category() {
    let app = app().await;
    let id = create_user(&app, "subject@example.com").await;
    let token = admin_token(&app, "admin:users:export").await;
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/{id}/export?profile=gdpr"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let bundle = body_json(&resp);
    assert_eq!(
        keys(&bundle),
        [
            "attributes",
            "audit_events",
            "consents",
            "credentials",
            "export_format_version",
            "generated_at",
            "identity_links",
            "operator_statement",
            "organizations",
            "pending_self_service_tokens",
            "roles",
            "sessions",
            "subject",
            "token_families",
        ]
    );
    assert_eq!(bundle["export_format_version"], 1);
    assert_eq!(bundle["subject"]["id"], id.as_str());
    assert_eq!(bundle["credentials"]["password_set"], true);
    assert!(bundle["operator_statement"].is_null());
    // The creation by the administrator is in the audit section, by role only.
    assert!(
        bundle["audit_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["actor"] == "administrator"),
        "{bundle}"
    );

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/{id}/export?profile=other"),
        Some(&token),
        None,
    )
    .await;
    admin_support::assert_field_error(&resp, "profile");
}

#[tokio::test]
async fn bulk_export_streams_ndjson_over_several_pages() {
    let app = app().await;
    // 130 users: more than one page of 100.
    let mut ids = import_users(&app, 130).await;
    ids.sort();
    let token = admin_token(&app, "admin:users:export").await;
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/export"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    assert_eq!(resp.header("content-type"), Some("application/x-ndjson"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let text = resp.text();
    assert!(text.ends_with('\n'));
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is JSON"))
        .collect();
    assert_eq!(lines.len(), ids.len());
    // Every user exactly once, in id order; no error line.
    let got: Vec<String> = lines
        .iter()
        .map(|l| l["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(got, ids);
    assert!(lines.iter().all(|l| l.get("error").is_none()));
    assert!(lines.iter().all(|l| l.get("password_hash").is_none()));

    // An empty tenant exports an empty body.
    let tenant_token = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&tenant_token),
        Some(json!({"slug": "empty", "display_name": "Empty"})),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/empty/users/export"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.is_empty(), "{}", resp.text());
}
