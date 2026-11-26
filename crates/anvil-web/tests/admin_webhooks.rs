//! Webhook admin API (ADM-05): endpoint CRUD with the secret shown once, secret rotation, URL
//! refusal by the outbound policy at write time, test sends, the delivery log (status, attempts,
//! last HTTP status, error class, next attempt; no payload) with pagination, redelivery, audit
//! rows and tenant isolation.

mod admin_support;
mod support;
mod token_support;
mod webhook_support;

use admin_support::{API, admin_token, assert_field_error, assert_problem, call};
use anvil_core::model::AuditAction;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::acme;
use webhook_support::{audit, dev_app, dev_worker, hook_url, sink};

async fn create(app: &TestApp, token: &str, slug: &str, body: Value) -> Value {
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/{slug}/webhooks"),
        Some(token),
        Some(body),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    body_json(&resp)
}

fn hooks_body(name: &str) -> Value {
    json!({
        "name": name,
        "url": "https://hooks.example.com/anvil",
        "events": ["user.created", "session.created"]
    })
}

#[tokio::test]
async fn endpoint_crud_shows_the_secret_once_and_is_audited() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:settings:write").await;

    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/webhooks"),
        Some(&token),
        Some(hooks_body("crm")),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let created = body_json(&resp);
    let id = created["endpoint"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        resp.header("location"),
        Some(format!("/api/admin/v1/tenants/default/webhooks/{id}").as_str())
    );
    let secret = created["secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("whsec_"), "{secret}");
    let endpoint = &created["endpoint"];
    assert_eq!(endpoint["name"], "crm");
    assert_eq!(
        endpoint["events"],
        json!(["user.created", "session.created"])
    );
    assert_eq!(endpoint["enabled"], true);
    assert_eq!(endpoint["secret_configured"], true);
    assert_eq!(endpoint["previous_secret_expires_at"], Value::Null);

    // Reads never carry the secret.
    let path = format!("{API}/tenants/default/webhooks/{id}");
    let resp = call(&app, Method::GET, &path, Some(&token), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(!resp.text().contains(&secret));
    assert!(body_json(&resp).get("secret").is_none());
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/webhooks"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    assert!(!resp.text().contains(&secret));
    assert_eq!(body_json(&resp)["items"][0]["id"], id.as_str());

    // PATCH events and enabled.
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"events": ["user.deleted"], "enabled": false})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let patched = body_json(&resp);
    assert_eq!(patched["events"], json!(["user.deleted"]));
    assert_eq!(patched["enabled"], false);
    assert_eq!(patched["url"], "https://hooks.example.com/anvil");

    // Rotation returns a new secret once and opens the 24 h window.
    let resp = call(
        &app,
        Method::POST,
        &format!("{path}/secret"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let rotated = body_json(&resp);
    let new_secret = rotated["secret"].as_str().unwrap().to_owned();
    assert!(new_secret.starts_with("whsec_"));
    assert_ne!(new_secret, secret);
    assert!(rotated["endpoint"]["previous_secret_expires_at"].is_string());
    let resp = call(&app, Method::GET, &path, Some(&token), None).await;
    assert!(!resp.text().contains(&new_secret));
    assert!(!resp.text().contains(&secret));

    let resp = call(&app, Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = call(&app, Method::GET, &path, Some(&token), None).await;
    assert_problem(&resp, 404);
    let resp = call(&app, Method::DELETE, &path, Some(&token), None).await;
    assert_problem(&resp, 404);

    for action in [
        AuditAction::WebhookEndpointCreated,
        AuditAction::WebhookEndpointUpdated,
        AuditAction::WebhookSecretRotated,
        AuditAction::WebhookEndpointDeleted,
    ] {
        let rows = audit(&app, action).await;
        assert_eq!(rows.len(), 1, "{action:?}");
        let details = Value::Object(rows[0].details.as_map().clone()).to_string();
        assert!(!details.contains(&secret) && !details.contains(&new_secret));
    }
}

#[tokio::test]
async fn invalid_endpoints_are_refused_at_write_time() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:settings:write").await;
    let post = |body: Value| {
        let app = &app;
        let token = token.clone();
        async move {
            call(
                app,
                Method::POST,
                &format!("{API}/tenants/default/webhooks"),
                Some(&token),
                Some(body),
            )
            .await
        }
    };

    // The outbound policy at write time (production: https only, no private literals, no
    // credentials).
    for url in [
        "https://10.0.0.7/hook",
        "https://127.0.0.1/hook",
        "https://169.254.169.254/latest",
        "https://[::1]/hook",
        "http://hooks.example.com/hook",
        "https://user:pw@hooks.example.com/hook",
        "not a url",
    ] {
        let resp = post(json!({"name": "x", "url": url, "events": ["user.created"]})).await;
        assert_field_error(&resp, "url");
    }
    // Events: at least one, never `test`, only known types.
    let resp = post(json!({"name": "x", "url": "https://h.example/x", "events": []})).await;
    assert_field_error(&resp, "events");
    let resp = post(json!({"name": "x", "url": "https://h.example/x", "events": ["test"]})).await;
    assert_field_error(&resp, "events");
    let resp =
        post(json!({"name": "x", "url": "https://h.example/x", "events": ["user.nope"]})).await;
    assert_field_error(&resp, "body");
    // Name syntax.
    let resp =
        post(json!({"name": "Bad Name", "url": "https://h.example/x", "events": ["user.created"]}))
            .await;
    assert_field_error(&resp, "name");
    // A client cannot provide the secret through the API.
    let resp = post(json!({
        "name": "x", "url": "https://h.example/x", "events": ["user.created"],
        "secret": "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    }))
    .await;
    assert_field_error(&resp, "body");

    // Duplicate name.
    create(&app, &token, "default", hooks_body("crm")).await;
    let resp = post(hooks_body("crm")).await;
    assert_problem(&resp, 409);

    // PATCH goes through the same URL check.
    let id = body_json(
        &call(
            &app,
            Method::GET,
            &format!("{API}/tenants/default/webhooks"),
            Some(&token),
            None,
        )
        .await,
    )["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default/webhooks/{id}"),
        Some(&token),
        Some(json!({"url": "https://192.168.1.10/hook"})),
    )
    .await;
    assert_field_error(&resp, "url");
    assert_eq!(
        audit(&app, AuditAction::WebhookEndpointCreated).await.len(),
        1
    );
    assert!(
        audit(&app, AuditAction::WebhookEndpointUpdated)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn test_send_delivery_log_and_redelivery() {
    let app = dev_app().await;
    let token = admin_token(app, "admin:settings:write").await;
    let server = sink(503).await;
    let created = create(
        app,
        &token,
        "default",
        json!({"name": "crm", "url": hook_url(&server), "events": ["user.created"]}),
    )
    .await;
    let id = created["endpoint"]["id"].as_str().unwrap().to_owned();
    let base = format!("{API}/tenants/default/webhooks/{id}");

    let resp = call(
        app,
        Method::POST,
        &format!("{base}/test"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 202, "{}", resp.text());
    let queued = body_json(&resp);
    assert_eq!(queued["event_type"], "test");
    assert_eq!(queued["status"], "pending");
    assert_eq!(queued["attempts"], 0);
    assert_eq!(queued["endpoint_id"], id.as_str());
    assert!(queued["next_attempt_at"].is_string());
    assert!(queued.get("payload").is_none() && queued.get("payload_json").is_none());
    assert_eq!(audit(app, AuditAction::WebhookTestSent).await.len(), 1);

    // One attempt against the 503 sink.
    dev_worker(app).run_once().await.expect("worker run");
    let resp = call(
        app,
        Method::GET,
        &format!("{base}/deliveries"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let log = body_json(&resp);
    let first = &log["items"][0];
    assert_eq!(first["id"], queued["id"]);
    assert_eq!(first["status"], "pending");
    assert_eq!(first["attempts"], 1);
    assert_eq!(first["last_http_status"], 503);
    assert_eq!(first["error_class"], "status_5xx");
    assert!(first["next_attempt_at"].is_string());
    assert_eq!(first["completed_at"], Value::Null);
    assert!(!resp.text().contains("payload"), "{}", resp.text());
    assert!(!resp.text().contains(created["secret"].as_str().unwrap()));

    // Redelivery: a new delivery with fresh attempts; the original is unchanged.
    let delivery_id = first["id"].as_str().unwrap().to_owned();
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/default/webhooks/deliveries/{delivery_id}/redeliver"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 202, "{}", resp.text());
    let again = body_json(&resp);
    assert_ne!(again["id"], first["id"]);
    assert_eq!(again["attempts"], 0);
    assert_eq!(again["event_type"], "test");
    assert_eq!(audit(app, AuditAction::WebhookRedelivered).await.len(), 1);

    // Newest first, cursor pagination.
    let resp = call(
        app,
        Method::GET,
        &format!("{base}/deliveries?limit=1"),
        Some(&token),
        None,
    )
    .await;
    let page = body_json(&resp);
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["items"][0]["id"], again["id"]);
    let cursor = page["next_cursor"]
        .as_str()
        .expect("more follow")
        .to_owned();
    let resp = call(
        app,
        Method::GET,
        &format!("{base}/deliveries?limit=1&after={cursor}"),
        Some(&token),
        None,
    )
    .await;
    let page = body_json(&resp);
    assert_eq!(page["items"][0]["id"], first["id"]);
    assert_eq!(page["items"][0]["attempts"], 1, "original unchanged");
    assert_eq!(page["next_cursor"], Value::Null);
    let resp = call(
        app,
        Method::GET,
        &format!("{base}/deliveries?limit=0"),
        Some(&token),
        None,
    )
    .await;
    assert_field_error(&resp, "limit");

    // Unknown ids.
    let unknown = "0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a99";
    for (method, path) in [
        (
            Method::POST,
            format!("{API}/tenants/default/webhooks/deliveries/{unknown}/redeliver"),
        ),
        (
            Method::POST,
            format!("{API}/tenants/default/webhooks/{unknown}/test"),
        ),
        (
            Method::GET,
            format!("{API}/tenants/default/webhooks/{unknown}/deliveries"),
        ),
        (
            Method::GET,
            format!("{API}/tenants/default/webhooks/not-a-uuid"),
        ),
    ] {
        let resp = call(app, method, &path, Some(&token), None).await;
        assert_problem(&resp, 404);
    }
}

#[tokio::test]
async fn endpoints_and_deliveries_of_another_tenant_are_404() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:settings:write").await;
    acme(&app).await;
    let created = create(&app, &token, "acme", hooks_body("crm")).await;
    let id = created["endpoint"]["id"].as_str().unwrap().to_owned();
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/acme/webhooks/{id}/test"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 202, "{}", resp.text());
    let delivery = body_json(&resp)["id"].as_str().unwrap().to_owned();

    for (method, path, body) in [
        (
            Method::GET,
            format!("{API}/tenants/default/webhooks/{id}"),
            None,
        ),
        (
            Method::PATCH,
            format!("{API}/tenants/default/webhooks/{id}"),
            Some(json!({"enabled": false})),
        ),
        (
            Method::DELETE,
            format!("{API}/tenants/default/webhooks/{id}"),
            None,
        ),
        (
            Method::POST,
            format!("{API}/tenants/default/webhooks/{id}/secret"),
            None,
        ),
        (
            Method::POST,
            format!("{API}/tenants/default/webhooks/{id}/test"),
            None,
        ),
        (
            Method::GET,
            format!("{API}/tenants/default/webhooks/{id}/deliveries"),
            None,
        ),
        (
            Method::POST,
            format!("{API}/tenants/default/webhooks/deliveries/{delivery}/redeliver"),
            None,
        ),
    ] {
        let resp = call(&app, method.clone(), &path, Some(&token), body).await;
        assert_problem(&resp, 404);
    }
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/webhooks"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(body_json(&resp)["items"], json!([]));
    // Still intact in its own tenant.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/acme/webhooks/{id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["enabled"], true);
}
