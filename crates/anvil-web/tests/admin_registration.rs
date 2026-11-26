//! Registration policy and initial access tokens through the admin API (OIDC-17, AGT-02,
//! ORG-01): DCR/CIMD tenant settings reflected in discovery and validated (system tenant always
//! disabled), the tenant view's computed issuer, initial access tokens (value once, list without
//! values, revoke), and dynamic/CIMD clients visible and deletable in the client list.

mod admin_support;
mod authz;
mod cimd_support;
mod dcr_support;
mod support;

use admin_support::{API, admin_token, assert_field_error, assert_problem, call};
use anvil_core::model::{AuditAction, AuditQuery, ClientSource};
use axum::http::Method;
use cimd_support::{DOC_PATH, DocServer, authorize_path, doc, stored};
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};

async fn patch_tenant(app: &TestApp, token: &str, slug: &str, settings: Value) -> TestResponse {
    call(
        app,
        Method::PATCH,
        &format!("{API}/tenants/{slug}"),
        Some(token),
        Some(json!({ "settings": settings })),
    )
    .await
}

async fn discovery(app: &TestApp) -> Value {
    let resp = call(
        app,
        Method::GET,
        "/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

#[tokio::test]
async fn dcr_and_cimd_policies_are_tenant_settings_reflected_in_discovery() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:tenants:write").await;

    // Defaults: both disabled, nothing advertised.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default"),
        Some(&token),
        None,
    )
    .await;
    let view = body_json(&resp);
    assert_eq!(view["settings"]["dcr"]["policy"], "disabled");
    assert_eq!(view["settings"]["dcr"]["max_clients"], 1000);
    assert_eq!(view["settings"]["cimd"]["policy"], "disabled");
    assert_eq!(view["settings"]["cimd"]["min_cache_secs"], 300);
    let disc = discovery(&app).await;
    assert!(disc.get("registration_endpoint").is_none(), "{disc}");
    assert!(
        disc.get("client_id_metadata_document_supported").is_none(),
        "{disc}"
    );

    let resp = patch_tenant(
        &app,
        &token,
        "default",
        json!({
            "dcr": {
                "policy": "open",
                "allowed_scopes": ["openid", "profile"],
                "allowed_resources": ["https://mcp.example/"],
                "allow_client_credentials": true,
                "max_clients": 50
            },
            "cimd": {"policy": "allow_listed", "allowed_hosts": ["mcp.example"]}
        }),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let view = body_json(&resp);
    assert_eq!(
        view["settings"]["dcr"],
        json!({
            "policy": "open",
            "allowed_redirect_hosts": [],
            "allowed_scopes": ["openid", "profile"],
            "allowed_resources": ["https://mcp.example/"],
            "allow_client_credentials": true,
            "max_clients": 50
        })
    );
    assert_eq!(view["settings"]["cimd"]["policy"], "allow_listed");
    assert_eq!(
        view["settings"]["cimd"]["allowed_hosts"],
        json!(["mcp.example"])
    );
    let disc = discovery(&app).await;
    assert_eq!(disc["registration_endpoint"], "https://op.test/register");
    assert_eq!(disc["client_id_metadata_document_supported"], true);

    // Field-by-field merge: other fields keep their values.
    let resp = patch_tenant(&app, &token, "default", json!({"dcr": {"max_clients": 5}})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let view = body_json(&resp);
    assert_eq!(view["settings"]["dcr"]["policy"], "open");
    assert_eq!(view["settings"]["dcr"]["max_clients"], 5);
    assert_eq!(view["settings"]["cimd"]["policy"], "allow_listed");

    // Invalid settings are 422 naming the field, and change nothing.
    for (settings, field) in [
        (
            json!({"cimd": {"min_cache_secs": 7200, "max_cache_secs": 600}}),
            "cimd.min_cache_secs",
        ),
        (json!({"cimd": {"allowed_hosts": []}}), "cimd.allowed_hosts"),
        (
            json!({"cimd": {"max_cache_secs": 999999999}}),
            "cimd.max_cache_secs",
        ),
        (
            json!({"dcr": {"allowed_redirect_hosts": ["app.example:8443"]}}),
            "dcr.allowed_redirect_hosts",
        ),
        (
            json!({"dcr": {"allowed_redirect_hosts": ["https://app.example"]}}),
            "dcr.allowed_redirect_hosts",
        ),
        (
            json!({"dcr": {"allowed_scopes": ["admin:write"]}}),
            "dcr.allowed_scopes",
        ),
        (
            json!({"dcr": {"allowed_resources": ["https://mcp.example/#x"]}}),
            "dcr.allowed_resources",
        ),
        (json!({"dcr": {"max_clients": 2000000}}), "dcr.max_clients"),
    ] {
        let resp = patch_tenant(&app, &token, "default", settings.clone()).await;
        assert_field_error(&resp, field);
    }
    let resp = patch_tenant(
        &app,
        &token,
        "default",
        json!({"dcr": {"policy": "sometimes"}}),
    )
    .await;
    assert_field_error(&resp, "body");
    let resp = patch_tenant(&app, &token, "default", json!({"dcr": {"unknown": 1}})).await;
    assert_field_error(&resp, "body");

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default"),
        Some(&token),
        None,
    )
    .await;
    let view = body_json(&resp);
    assert_eq!(view["settings"]["dcr"]["max_clients"], 5, "unchanged");
    assert_eq!(
        view["settings"]["cimd"]["allowed_hosts"],
        json!(["mcp.example"])
    );

    // Back to disabled: discovery stops advertising both.
    let resp = patch_tenant(
        &app,
        &token,
        "default",
        json!({"dcr": {"policy": "disabled"}, "cimd": {"policy": "disabled"}}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let disc = discovery(&app).await;
    assert!(disc.get("registration_endpoint").is_none());
    assert!(disc.get("client_id_metadata_document_supported").is_none());
}

#[tokio::test]
async fn new_tenants_take_registration_settings() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:tenants:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&token),
        Some(json!({
            "slug": "partners",
            "display_name": "Partners",
            "settings": {"dcr": {"policy": "allow_listed", "allowed_redirect_hosts": ["rp.example"]}}
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let view = body_json(&resp);
    assert_eq!(view["settings"]["dcr"]["policy"], "allow_listed");
    assert_eq!(view["settings"]["dcr"]["max_clients"], 1000);
    assert_eq!(view["settings"]["cimd"]["policy"], "disabled");

    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&token),
        Some(json!({
            "slug": "broken",
            "display_name": "Broken",
            "settings": {"cimd": {"policy": "allow_listed"}}
        })),
    )
    .await;
    assert_field_error(&resp, "cimd.allowed_hosts");
}

#[tokio::test]
async fn tenant_view_carries_the_computed_issuer() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:tenants:write").await;
    for (slug, host) in [("acme", None), ("hosted", Some("id.hosted.test"))] {
        let resp = call(
            &app,
            Method::POST,
            &format!("{API}/tenants"),
            Some(&token),
            Some(json!({"slug": slug, "display_name": slug, "host": host})),
        )
        .await;
        assert_eq!(resp.status, 201, "{}", resp.text());
    }
    let expect = [
        ("default", "https://op.test"),
        ("system", "https://op.test/t/system"),
        ("acme", "https://op.test/t/acme"),
        ("hosted", "https://id.hosted.test"),
    ];
    for (slug, issuer) in expect {
        let resp = call(
            &app,
            Method::GET,
            &format!("{API}/tenants/{slug}"),
            Some(&token),
            None,
        )
        .await;
        let view = body_json(&resp);
        assert_eq!(view["issuer"], issuer, "{slug}");
        assert_eq!(
            view["discovery_url"],
            format!("{issuer}/.well-known/openid-configuration"),
            "{slug}"
        );
    }
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants?limit=200"),
        Some(&token),
        None,
    )
    .await;
    let list = body_json(&resp);
    for (slug, issuer) in expect {
        let item = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["slug"] == slug)
            .unwrap_or_else(|| panic!("{slug} listed"));
        assert_eq!(item["issuer"], issuer);
    }
    // The issuer is what the tenant's discovery document says.
    let disc = discovery(&app).await;
    assert_eq!(disc["issuer"], "https://op.test");
    let resp = call(
        &app,
        Method::GET,
        "/t/acme/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert_eq!(body_json(&resp)["issuer"], "https://op.test/t/acme");
}

#[tokio::test]
async fn initial_access_tokens_issue_list_and_revoke() {
    let app = dcr_support::app().await;
    let token = admin_token(&app, "admin:clients:write admin:tenants:write").await;
    let iats = format!("{API}/tenants/default/initial-access-tokens");
    let resp = patch_tenant(
        &app,
        &token,
        "default",
        json!({"dcr": {"policy": "allow_listed"}}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    let resp = call(
        &app,
        Method::POST,
        &iats,
        Some(&token),
        Some(json!({"description": "partner onboarding", "expires_in": 3600, "uses": 2})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let issued = body_json(&resp);
    let value = issued["value"].as_str().unwrap().to_owned();
    assert!(value.len() >= 32, "{value}");
    let id = issued["token"]["id"].as_str().unwrap().to_owned();
    assert_eq!(issued["token"]["description"], "partner onboarding");
    assert_eq!(issued["token"]["uses_remaining"], 2);
    assert_eq!(issued["token"]["usable"], true);
    assert!(issued["token"]["expires_at"].is_string());

    // Listing never shows the value.
    let resp = call(&app, Method::GET, &iats, Some(&token), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(!resp.text().contains(&value));
    let list = body_json(&resp);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["items"][0]["id"], id.as_str());
    assert!(list["items"][0].get("value").is_none());

    // It authorizes a registration.
    let resp = dcr_support::register(&app, &dcr_support::web_request(), Some(&value)).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let registered = body_json(&resp);
    let resp = call(&app, Method::GET, &iats, Some(&token), None).await;
    assert_eq!(body_json(&resp)["items"][0]["uses_remaining"], 1);

    // Revoked: registration refused, a second revoke is 404.
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{iats}/{id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = dcr_support::register(&app, &dcr_support::web_request(), Some(&value)).await;
    assert_eq!(resp.status, 401, "{}", resp.text());
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{iats}/{id}"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    let resp = call(&app, Method::GET, &iats, Some(&token), None).await;
    let item = &body_json(&resp)["items"][0];
    assert!(item["revoked_at"].is_string());
    assert_eq!(item["usable"], false);

    // Input validation.
    for (body, field) in [
        (json!({"uses": 0}), "uses"),
        (json!({"uses": 100001}), "uses"),
        (json!({"expires_in": 10}), "expires_in"),
        (json!({"expires_in": 40000000}), "expires_in"),
        (json!({"expires_in": u64::MAX}), "expires_in"),
        (json!({"description": "x".repeat(201)}), "description"),
        (json!({"value": "mine"}), "body"),
    ] {
        let resp = call(&app, Method::POST, &iats, Some(&token), Some(body.clone())).await;
        assert_field_error(&resp, field);
    }
    // Never for the system tenant.
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/system/initial-access-tokens"),
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_field_error(&resp, "tenant");
    // Unknown and malformed ids.
    for id in ["0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a99", "nope"] {
        let resp = call(
            &app,
            Method::DELETE,
            &format!("{iats}/{id}"),
            Some(&token),
            None,
        )
        .await;
        assert_problem(&resp, 404);
    }

    // The dynamic client is in the client list with its source.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/clients?limit=200"),
        Some(&token),
        None,
    )
    .await;
    let clients = body_json(&resp);
    let dynamic = clients["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["client_id"] == registered["client_id"])
        .expect("dynamic client listed");
    assert_eq!(dynamic["registration_source"], "dynamic");
    assert_eq!(dynamic["metadata_expires_at"], Value::Null);

    // Audit.
    let tenant = dcr_support::tenant(&app, None).await;
    let log = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    let created = log
        .iter()
        .find(|e| e.action == AuditAction::InitialAccessTokenCreated)
        .expect("issue audited");
    assert_eq!(created.target.as_deref(), Some(id.as_str()));
    assert!(
        log.iter()
            .any(|e| e.action == AuditAction::InitialAccessTokenRevoked)
    );
}

#[tokio::test]
async fn cimd_clients_are_listed_deleted_and_blocked_by_the_allow_list() {
    let app = TestApp::dev().await;
    let token = admin_token(&app, "admin:clients:write admin:tenants:write").await;
    let docs = DocServer::start().await;
    let client_id = docs.url(DOC_PATH);
    docs.serve(DOC_PATH, &doc(&client_id), Some("max-age=600"))
        .await;
    let resp = patch_tenant(
        &app,
        &token,
        "default",
        json!({"cimd": {"policy": "allow_listed", "allowed_hosts": ["127.0.0.1"]}}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    // First use materialises the client.
    authz::get(&app, &authorize_path(&client_id, &[]), None).await;
    let row = stored(&app, &client_id).await.expect("materialised");
    assert_eq!(row.registration_source, ClientSource::Cimd);
    assert_eq!(docs.hits(DOC_PATH).await, 1);

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/clients?limit=200"),
        Some(&token),
        None,
    )
    .await;
    let clients = body_json(&resp);
    let listed = clients["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["client_id"] == client_id.as_str())
        .expect("CIMD client listed");
    assert_eq!(listed["registration_source"], "cimd");
    assert!(listed["metadata_expires_at"].is_string(), "{listed}");

    // Delete (URL client id percent-encoded in the path): the row is gone ...
    let encoded: String = url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect();
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/clients/{encoded}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    assert!(stored(&app, &client_id).await.is_none());

    // ... and the next use fetches the document again while the policy allows the host.
    authz::get(&app, &authorize_path(&client_id, &[]), None).await;
    assert!(stored(&app, &client_id).await.is_some());
    assert_eq!(docs.hits(DOC_PATH).await, 2);

    // Blocking is done with the allow-list: without the host, nothing is fetched and the
    // materialised row is no longer served.
    let resp = patch_tenant(
        &app,
        &token,
        "default",
        json!({"cimd": {"allowed_hosts": ["mcp.example"]}}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/clients/{encoded}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = authz::get(&app, &authorize_path(&client_id, &[]), None).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(stored(&app, &client_id).await.is_none());
    assert_eq!(docs.hits(DOC_PATH).await, 2, "blocked host is not fetched");
}

#[tokio::test]
async fn system_tenant_registration_settings_stay_disabled() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    for (settings, field) in [
        (json!({"dcr": {"policy": "open"}}), "dcr.policy"),
        (json!({"dcr": {"policy": "allow_listed"}}), "dcr.policy"),
        (json!({"cimd": {"policy": "open"}}), "cimd.policy"),
    ] {
        let resp = patch_tenant(&app, &token, "system", settings).await;
        assert_field_error(&resp, field);
    }
    // Other settings of the system tenant still update; the view shows disabled.
    let resp = patch_tenant(&app, &token, "system", json!({"dcr": {"max_clients": 3}})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let view = body_json(&resp);
    assert_eq!(view["settings"]["dcr"]["policy"], "disabled");
    assert_eq!(view["settings"]["cimd"]["policy"], "disabled");
}
