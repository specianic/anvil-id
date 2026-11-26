//! Management API 1.0 client and tenant fields end to end: `require_pushed_authorization_requests`,
//! `client_kind` and `headless_native` on clients, `par` and `headless` in tenant settings. Each
//! field round-trips through create, patch and get; the field-combination rules of
//! `service::client::validate_client_policy` and the headless origin rules are refused with a
//! 422 problem naming the field.

mod admin_support;
mod support;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};

async fn app_with(dev_mode: bool) -> TestApp {
    TestApp::with(|c| {
        c.rate_limits.admin = RateQuota::per_second(100_000, 100_000);
        // `insecure_http` turns on development mode (localhost http headless origins).
        c.insecure_http = dev_mode;
    })
    .await
}

async fn req(app: &TestApp, t: &str, m: Method, path: &str, body: Option<Value>) -> TestResponse {
    call(app, m, path, Some(t), body).await
}

fn clients() -> String {
    format!("{API}/tenants/default/clients")
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

/// Creates a client with `extra`; returns its client_id.
async fn create(app: &TestApp, t: &str, extra: Value) -> String {
    let resp = req(app, t, Method::POST, &clients(), Some(client_body(extra))).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    body_json(&resp)["client_id"].as_str().unwrap().to_owned()
}

async fn get_client(app: &TestApp, t: &str, id: &str) -> Value {
    let resp = req(app, t, Method::GET, &format!("{}/{id}", clients()), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

async fn patch_client(app: &TestApp, t: &str, id: &str, body: Value) -> TestResponse {
    req(
        app,
        t,
        Method::PATCH,
        &format!("{}/{id}", clients()),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn client_v10_fields_round_trip() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;

    // Defaults, always present on output.
    let plain = create(&app, &t, json!({})).await;
    let c = get_client(&app, &t, &plain).await;
    assert_eq!(c["require_pushed_authorization_requests"], false);
    assert_eq!(c["client_kind"], "application");
    assert_eq!(c["headless_native"], false);

    // Set on create.
    let agent = create(
        &app,
        &t,
        json!({"require_pushed_authorization_requests": true, "client_kind": "agent"}),
    )
    .await;
    let c = get_client(&app, &t, &agent).await;
    assert_eq!(c["require_pushed_authorization_requests"], true);
    assert_eq!(c["client_kind"], "agent");
    assert_eq!(c["consent_mode"], "required");

    // Patch: a first-party native headless client.
    let resp = patch_client(
        &app,
        &t,
        &plain,
        json!({"consent_mode": "skip_first_party", "headless_native": true}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let c = get_client(&app, &t, &plain).await;
    assert_eq!(c["headless_native"], true);
    assert_eq!(c["consent_mode"], "skip_first_party");

    // Patch back; other fields are untouched.
    let resp = patch_client(
        &app,
        &t,
        &agent,
        json!({"client_kind": "application", "require_pushed_authorization_requests": false}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let c = get_client(&app, &t, &agent).await;
    assert_eq!(c["client_kind"], "application");
    assert_eq!(c["require_pushed_authorization_requests"], false);
    assert_eq!(c["name"], "RP");

    // Unknown kinds are refused by the wire enum.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients(),
        Some(client_body(json!({"client_kind": "robot"}))),
    )
    .await;
    assert!(resp.status.is_client_error(), "{}", resp.text());
}

#[tokio::test]
async fn agent_client_cannot_skip_consent() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;

    // On create.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients(),
        Some(client_body(
            json!({"client_kind": "agent", "consent_mode": "skip_first_party"}),
        )),
    )
    .await;
    assert_field_error(&resp, "consent_mode");

    // Marking a first-party client as an agent.
    let first_party = create(&app, &t, json!({"consent_mode": "skip_first_party"})).await;
    let resp = patch_client(&app, &t, &first_party, json!({"client_kind": "agent"})).await;
    assert_field_error(&resp, "consent_mode");
    assert_eq!(
        get_client(&app, &t, &first_party).await["client_kind"],
        "application"
    );

    // Letting an agent skip consent.
    let agent = create(&app, &t, json!({"client_kind": "agent"})).await;
    let resp = patch_client(
        &app,
        &t,
        &agent,
        json!({"consent_mode": "skip_first_party"}),
    )
    .await;
    assert_field_error(&resp, "consent_mode");
    assert_eq!(
        get_client(&app, &t, &agent).await["consent_mode"],
        "required"
    );
}

#[tokio::test]
async fn headless_native_requires_first_party() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients(),
        Some(client_body(json!({"headless_native": true}))),
    )
    .await;
    assert_field_error(&resp, "headless_native");

    // A native headless client cannot go back to asking for consent while flagged.
    let id = create(
        &app,
        &t,
        json!({"headless_native": true, "consent_mode": "skip_first_party"}),
    )
    .await;
    let resp = patch_client(&app, &t, &id, json!({"consent_mode": "required"})).await;
    assert_field_error(&resp, "headless_native");
}

#[tokio::test]
async fn headless_native_requires_pkce() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let confidential = json!({
        "client_type": "confidential",
        "consent_mode": "skip_first_party",
        "headless_native": true,
        "require_pkce": false,
    });
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients(),
        Some(client_body(confidential)),
    )
    .await;
    assert_field_error(&resp, "headless_native");

    let id = create(
        &app,
        &t,
        json!({"client_type": "confidential", "consent_mode": "skip_first_party", "headless_native": true}),
    )
    .await;
    let resp = patch_client(&app, &t, &id, json!({"require_pkce": false})).await;
    assert_field_error(&resp, "headless_native");
    assert_eq!(get_client(&app, &t, &id).await["require_pkce"], true);
}

#[tokio::test]
async fn headless_native_refuses_agent() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients(),
        Some(client_body(
            json!({"client_kind": "agent", "headless_native": true}),
        )),
    )
    .await;
    assert_field_error(&resp, "headless_native");

    let agent = create(&app, &t, json!({"client_kind": "agent"})).await;
    let resp = patch_client(&app, &t, &agent, json!({"headless_native": true})).await;
    assert_field_error(&resp, "headless_native");
    assert_eq!(get_client(&app, &t, &agent).await["headless_native"], false);
}

#[tokio::test]
async fn tenant_par_and_headless_settings_round_trip() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let tenant = format!("{API}/tenants/default");

    let resp = req(&app, &t, Method::GET, &tenant, None).await;
    let s = &body_json(&resp)["settings"];
    assert_eq!(s["par"]["require_pushed_authorization_requests"], false);
    assert_eq!(s["headless"]["allowed_origins"], json!([]));

    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &tenant,
        Some(json!({"settings": {
            "par": {"require_pushed_authorization_requests": true},
            "headless": {"allowed_origins": ["https://spa.example.test", "https://app.example.test:8443"]},
        }})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = req(&app, &t, Method::GET, &tenant, None).await;
    let s = &body_json(&resp)["settings"];
    assert_eq!(s["par"]["require_pushed_authorization_requests"], true);
    assert_eq!(
        s["headless"]["allowed_origins"],
        json!(["https://spa.example.test", "https://app.example.test:8443"])
    );

    // An unrelated settings patch keeps both.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &tenant,
        Some(json!({"settings": {"auto_link": false}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = &body_json(&resp)["settings"];
    assert_eq!(s["par"]["require_pushed_authorization_requests"], true);
    assert_eq!(
        s["headless"]["allowed_origins"][0],
        "https://spa.example.test"
    );

    // A new tenant takes them on create.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{API}/tenants"),
        Some(json!({
            "slug": "spa-shop",
            "display_name": "SPA shop",
            "settings": {
                "par": {"require_pushed_authorization_requests": true},
                "headless": {"allowed_origins": ["https://shop.example.test"]},
            },
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let s = &body_json(&resp)["settings"];
    assert_eq!(s["par"]["require_pushed_authorization_requests"], true);
    assert_eq!(
        s["headless"]["allowed_origins"],
        json!(["https://shop.example.test"])
    );
}

#[tokio::test]
async fn headless_origins_reject_wildcard_and_path() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let tenant = format!("{API}/tenants/default");
    for bad in [
        "https://*.example.test",
        "https://a.example.test/path",
        "*",
        "http://spa.example.test",
        // Production mode: no localhost http.
        "http://localhost:5173",
    ] {
        let resp = req(
            &app,
            &t,
            Method::PATCH,
            &tenant,
            Some(json!({"settings": {"headless": {"allowed_origins": ["https://ok.example.test", bad]}}})),
        )
        .await;
        assert_field_error(&resp, "headless.allowed_origins");
        let resp = req(
            &app,
            &t,
            Method::POST,
            &format!("{API}/tenants"),
            Some(json!({
                "slug": "bad-origins",
                "display_name": "Bad",
                "settings": {"headless": {"allowed_origins": [bad]}},
            })),
        )
        .await;
        assert_field_error(&resp, "headless.allowed_origins");
    }
    // Nothing was stored.
    let resp = req(&app, &t, Method::GET, &tenant, None).await;
    assert_eq!(
        body_json(&resp)["settings"]["headless"]["allowed_origins"],
        json!([])
    );
    let resp = req(
        &app,
        &t,
        Method::GET,
        &format!("{API}/tenants/bad-origins"),
        None,
    )
    .await;
    assert_eq!(resp.status, 404);

    // Development mode accepts localhost http, still not wildcards.
    let dev = app_with(true).await;
    let t = admin_token(&dev, "admin:read admin:write").await;
    let resp = req(
        &dev,
        &t,
        Method::PATCH,
        &tenant,
        Some(json!({"settings": {"headless": {"allowed_origins": ["http://localhost:5173"]}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = req(
        &dev,
        &t,
        Method::PATCH,
        &tenant,
        Some(json!({"settings": {"headless": {"allowed_origins": ["http://*.localhost"]}}})),
    )
    .await;
    assert_field_error(&resp, "headless.allowed_origins");
}

/// The published JSON Schema of the tenant configuration document.
fn schema_validator() -> jsonschema::Validator {
    let schema: Value =
        serde_json::from_str(include_str!("../../../docs/schemas/tenant-config-v1.json"))
            .expect("schema is JSON");
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .expect("schema compiles")
}

fn schema_errors(v: &jsonschema::Validator, doc: &Value) -> Vec<String> {
    v.iter_errors(doc)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect()
}

#[tokio::test]
async fn config_document_carries_v10_fields_and_matches_the_schema() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let config = format!("{API}/tenants/default/config");
    let doc = json!({
        "version": 1,
        "kind": "TenantConfig",
        "tenant": {
            "slug": "default",
            "display_name": "Default",
            "settings": {
                "par": {"require_pushed_authorization_requests": true},
                "headless": {"allowed_origins": ["https://spa.example.test"]},
            },
        },
        "clients": [
            {
                "client_id": "agent-app",
                "name": "Agent",
                "client_type": "public",
                "application_type": "web",
                "auth_method": "none",
                "redirect_uris": ["https://rp.example/cb"],
                "grant_types": ["authorization_code"],
                "client_kind": "agent",
                "require_pushed_authorization_requests": true,
            },
            {
                "client_id": "native-app",
                "name": "Native",
                "client_type": "public",
                "application_type": "native",
                "auth_method": "none",
                "redirect_uris": ["http://127.0.0.1/callback"],
                "grant_types": ["authorization_code"],
                "consent_mode": "skip_first_party",
                "headless_native": true,
            },
        ],
    });
    let v = schema_validator();
    assert_eq!(schema_errors(&v, &doc), Vec::<String>::new());
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{config}/apply"),
        Some(doc.clone()),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = req(&app, &t, Method::GET, &config, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let exported = body_json(&resp);
    assert_eq!(schema_errors(&v, &exported), Vec::<String>::new());
    let s = &exported["tenant"]["settings"];
    assert_eq!(s["par"]["require_pushed_authorization_requests"], true);
    assert_eq!(
        s["headless"]["allowed_origins"],
        json!(["https://spa.example.test"])
    );
    let by_id = |id: &str| {
        exported["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["client_id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("{id} exported"))
    };
    assert_eq!(by_id("agent-app")["client_kind"], "agent");
    assert_eq!(
        by_id("agent-app")["require_pushed_authorization_requests"],
        true
    );
    assert_eq!(by_id("native-app")["headless_native"], true);
    // The admin API shows the same values.
    assert_eq!(
        get_client(&app, &t, "native-app").await["headless_native"],
        true
    );

    // The schema refuses an unknown kind and a wildcard origin.
    let mut bad = doc.clone();
    bad["clients"][0]["client_kind"] = json!("robot");
    bad["tenant"]["settings"]["headless"]["allowed_origins"] = json!(["https://*.example.test"]);
    assert_eq!(
        schema_errors(&v, &bad).len(),
        2,
        "{:?}",
        schema_errors(&v, &bad)
    );
    // The server refuses an agent that skips consent by path (422, nothing written).
    let mut agent_skip = doc.clone();
    agent_skip["clients"][0]["consent_mode"] = json!("skip_first_party");
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{config}/apply"),
        Some(agent_skip),
    )
    .await;
    assert_eq!(resp.status, 422, "{}", resp.text());
    assert!(
        resp.text().contains("clients[0].consent_mode"),
        "{}",
        resp.text()
    );
    assert_eq!(
        get_client(&app, &t, "agent-app").await["consent_mode"],
        "required"
    );
}
