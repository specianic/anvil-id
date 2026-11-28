//! Security tests for the rc.4 management API additions (plan 07.1-06): client home URL
//! validation refusals, the built-in console client deletion guard, and the admin-triggered
//! password reset (scope, tenant isolation, blocked users, no token in the response).

mod admin_support;
mod support;

use admin_support::{API, admin_token, assert_field_error, call};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.enabled = false).await
}

fn clients(tenant: &str) -> String {
    format!("{API}/tenants/{tenant}/clients")
}

fn client_body(extra: Value) -> Value {
    let mut base = json!({
        "name": "RP",
        "client_type": "public",
        "redirect_uris": ["https://rp.example/cb"],
    });
    for (k, v) in extra.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

// ---------------------------------------------------------------------------------------------
// Client home URLs
// ---------------------------------------------------------------------------------------------

/// Values the one home URL validation refuses on every path.
fn unsafe_home_uris() -> Vec<String> {
    vec![
        "javascript:alert(1)".to_owned(),
        "data:text/html,<script>alert(1)</script>".to_owned(),
        "http://evil.example/".to_owned(),
        "https://user:pw@app.example/".to_owned(),
        "https://user@app.example/".to_owned(),
        "https://app.example/#frag".to_owned(),
        "/home".to_owned(),
        "app.example/home".to_owned(),
        "not a url".to_owned(),
        String::new(),
        "https://app.example/ x".to_owned(),
        format!("https://app.example/{}", "a".repeat(2048)),
    ]
}

#[tokio::test]
async fn client_home_uris_refuse_unsafe_values() {
    let app = app().await;
    let token = admin_token(&app, "admin:clients:write").await;

    // A client to patch.
    let resp = call(
        &app,
        Method::POST,
        &clients("default"),
        Some(&token),
        Some(client_body(json!({}))),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let id = body_json(&resp)["client_id"].as_str().unwrap().to_owned();
    let path = format!("{}/{id}", clients("default"));

    for field in ["client_uri", "initiate_login_uri"] {
        for bad in unsafe_home_uris() {
            // Create: 422 naming the field, nothing stored.
            let resp = call(
                &app,
                Method::POST,
                &clients("default"),
                Some(&token),
                Some(client_body(json!({ field: bad }))),
            )
            .await;
            assert_field_error(&resp, field);
            // The refusal never echoes the value.
            if !bad.is_empty() {
                assert!(!resp.text().contains(&bad), "{field}={bad} echoed");
            }

            // Update: 422 naming the field, the stored value unchanged.
            let resp = call(
                &app,
                Method::PATCH,
                &path,
                Some(&token),
                Some(json!({ field: bad })),
            )
            .await;
            assert_field_error(&resp, field);
        }
    }
    let resp = call(&app, Method::GET, &path, Some(&token), None).await;
    let view = body_json(&resp);
    assert_eq!(view["client_uri"], Value::Null);
    assert_eq!(view["initiate_login_uri"], Value::Null);

    // Wrong JSON type: refused by the body parser.
    let resp = call(
        &app,
        Method::POST,
        &clients("default"),
        Some(&token),
        Some(client_body(json!({"client_uri": 5}))),
    )
    .await;
    assert_eq!(resp.status, 422, "{}", resp.text());
}
