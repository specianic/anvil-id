//! The organization admin scope `org:admin` (decision Q1) and the client organization policy in
//! the existing client paths (ORG-02, ORG-03). Each test proves a refusal or its positive
//! control: dynamic registration and Client ID Metadata Documents can never obtain `org:admin`
//! and always store the policy `off`; system-tenant clients can neither allow `org:admin` nor use
//! a policy other than `off` (organizations do not exist there); static clients of application
//! tenants may do both.

mod admin_support;
mod authz;
mod cimd_support;
mod dcr_support;
mod support;

use admin_support::{API, admin_token, assert_field_error, assert_problem, call};
use anvil_core::model::{CimdPolicy, ClientSource, DcrPolicy, OrgClientPolicy, PageRequest};
use axum::http::{Method, StatusCode};
use cimd_support::{DocServer, authorize_path, doc, set_policy as set_cimd_policy, stored};
use dcr_support::{register, set_dcr_of, tenant, web_request};
use serde_json::{Value, json};
use support::{TestApp, json as body_json};

/// Asserts an RFC 7591 `invalid_client_metadata` error (400).
fn assert_invalid_metadata(resp: &support::TestResponse) {
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.text());
    let body = body_json(resp);
    assert_eq!(body["error"], "invalid_client_metadata", "{body}");
}

async fn dynamic_clients(app: &TestApp) -> usize {
    let t = tenant(app, None).await;
    app.storage()
        .clients()
        .list(t.id, PageRequest::default())
        .await
        .expect("client list")
        .items
        .iter()
        .filter(|c| c.registration_source == ClientSource::Dynamic)
        .count()
}

fn web_client(scopes: &[&str]) -> Value {
    json!({
        "name": "Web app",
        "client_type": "confidential",
        "auth_method": "client_secret_basic",
        "redirect_uris": ["https://rp.example/cb"],
        "grant_types": ["authorization_code"],
        "scopes": scopes,
    })
}

fn issue_fields(body: &Value) -> Vec<String> {
    body["errors"]
        .as_array()
        .expect("errors")
        .iter()
        .map(|e| e["field"].as_str().unwrap().to_owned())
        .collect()
}

/// A client section for a configuration document with the given organization policy.
fn config_client(client_id: &str, organization: &str) -> Value {
    json!({
        "client_id": client_id,
        "name": "Org app",
        "client_type": "public",
        "application_type": "web",
        "auth_method": "none",
        "redirect_uris": ["https://org-app.example.test/cb"],
        "grant_types": ["authorization_code"],
        "scopes": ["openid"],
        "organization": organization,
    })
}

async fn export(app: &TestApp, token: &str, slug: &str) -> Value {
    let resp = call(
        app,
        Method::GET,
        &format!("{API}/tenants/{slug}/config"),
        Some(token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

#[tokio::test]
async fn dcr_cannot_register_org_admin_scope() {
    let app = dcr_support::app().await;
    // The tenant settings refuse listing it in the first place (422, nothing stored).
    let token = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default"),
        Some(&token),
        Some(json!({"settings": {"dcr": {"policy": "open", "allowed_scopes": ["openid", "org:admin"]}}})),
    )
    .await;
    assert_field_error(&resp, "dcr.allowed_scopes");
    let stored = tenant(&app, None).await.settings.dcr;
    assert!(
        !stored.allowed_scopes.iter().any(|s| s == "org:admin"),
        "{stored:?}"
    );
    // Even when the tenant's stored settings (mis)list org:admin as registrable.
    set_dcr_of(&app, None, |d| {
        d.policy = DcrPolicy::Open;
        d.allowed_scopes = vec!["openid".into(), "org:admin".into()];
    })
    .await;
    for scope in ["openid org:admin", "org:admin"] {
        let req = json!({"redirect_uris": [authz::RP], "scope": scope});
        assert_invalid_metadata(&register(&app, &req, None).await);
    }
    assert_eq!(dynamic_clients(&app).await, 0, "nothing stored");
    // The default scope (every allowed scope) drops it.
    let resp = register(&app, &web_request(), None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    assert_eq!(body_json(&resp)["scope"], "openid");
}

#[tokio::test]
async fn dcr_client_organization_policy_is_off() {
    let app = dcr_support::app().await;
    set_dcr_of(&app, None, |d| d.policy = DcrPolicy::Open).await;
    let mut req = web_request();
    req["organization"] = json!("required");
    let resp = register(&app, &req, None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let client_id = body_json(&resp)["client_id"].as_str().unwrap().to_owned();
    let t = tenant(&app, None).await;
    let client = app
        .storage()
        .clients()
        .get(t.id, &client_id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(client.registration_source, ClientSource::Dynamic);
    assert_eq!(client.organization, OrgClientPolicy::Off);
}

#[tokio::test]
async fn cimd_document_with_org_admin_scope_rejected() {
    let app = TestApp::dev().await;
    set_cimd_policy(&app, CimdPolicy::Open, &[], &[]).await;
    let docs = DocServer::start().await;

    let client_id = docs.url("/org-admin.json");
    let mut body = doc(&client_id);
    body["scope"] = json!("openid org:admin");
    docs.serve("/org-admin.json", &body, None).await;
    let resp = app.get(&authorize_path(&client_id, &[])).await;
    authz::assert_error_page(&resp, "unknown_client");
    assert!(stored(&app, &client_id).await.is_none(), "nothing stored");

    // Positive control: the same document without the scope is accepted, with policy off.
    let client_id = docs.url("/plain.json");
    docs.serve("/plain.json", &doc(&client_id), None).await;
    let resp = app.get(&authorize_path(&client_id, &[])).await;
    assert!(resp.status.as_u16() < 400, "{}", resp.text());
    let client = stored(&app, &client_id).await.expect("cimd client stored");
    assert_eq!(client.registration_source, ClientSource::Cimd);
    assert_eq!(client.organization, OrgClientPolicy::Off);
}

#[tokio::test]
async fn system_tenant_client_cannot_allow_org_admin() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let base = format!("{API}/tenants/system/clients");
    let resp = call(
        &app,
        Method::POST,
        &base,
        Some(&token),
        Some(web_client(&["openid", "org:admin"])),
    )
    .await;
    assert_field_error(&resp, "scopes");

    // An existing system client cannot be patched to it either.
    let resp = call(
        &app,
        Method::POST,
        &base,
        Some(&token),
        Some(web_client(&["openid"])),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let client_id = body_json(&resp)["client_id"].as_str().unwrap().to_owned();
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{base}/{client_id}"),
        Some(&token),
        Some(json!({"scopes": ["openid", "org:admin"]})),
    )
    .await;
    assert_field_error(&resp, "scopes");
    let system = app.system.as_ref().unwrap().tenant.id;
    let client = app
        .storage()
        .clients()
        .get(system, &client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(client.scopes, ["openid"]);

    // Nor through the declarative configuration.
    let mut doc = export(&app, &token, "system").await;
    let mut c = config_client("ops-app", "off");
    c["scopes"] = json!(["openid", "org:admin"]);
    doc["clients"] = json!([c]);
    for op in ["plan", "apply"] {
        let resp = call(
            &app,
            Method::POST,
            &format!("{API}/tenants/system/config/{op}"),
            Some(&token),
            Some(doc.clone()),
        )
        .await;
        let body = assert_problem(&resp, 422);
        assert!(
            issue_fields(&body).contains(&"clients[0].scopes".to_owned()),
            "{body}"
        );
    }
    assert!(
        app.storage()
            .clients()
            .get(system, "ops-app")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn system_tenant_client_organization_policy_must_be_off() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let system = app.system.as_ref().unwrap().tenant.id;
    for policy in ["optional", "required"] {
        let mut doc = export(&app, &token, "system").await;
        doc["clients"] = json!([config_client("ops-app", policy)]);
        for op in ["plan", "apply"] {
            let resp = call(
                &app,
                Method::POST,
                &format!("{API}/tenants/system/config/{op}"),
                Some(&token),
                Some(doc.clone()),
            )
            .await;
            let body = assert_problem(&resp, 422);
            assert!(
                issue_fields(&body).contains(&"clients[0].organization".to_owned()),
                "{policy} {op}: {body}"
            );
        }
        assert!(
            app.storage()
                .clients()
                .get(system, "ops-app")
                .await
                .unwrap()
                .is_none(),
            "{policy}: nothing stored"
        );
    }
    // Positive control: policy off is accepted in the system tenant.
    let mut doc = export(&app, &token, "system").await;
    doc["clients"] = json!([config_client("ops-app", "off")]);
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/system/config/apply"),
        Some(&token),
        Some(doc),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn application_tenant_static_client_may_allow_org_admin() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/clients"),
        Some(&token),
        Some(web_client(&["openid", "org:admin"])),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(body_json(&resp)["scopes"], json!(["openid", "org:admin"]));
}

#[tokio::test]
async fn application_tenant_static_client_may_use_organization_required() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let tenant = app.default.as_ref().unwrap().tenant.id;
    let mut doc = export(&app, &token, "default").await;
    let mut c = config_client("org-app", "required");
    c["scopes"] = json!(["openid", "org:admin"]);
    doc["clients"] = json!([c]);
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/config/apply"),
        Some(&token),
        Some(doc),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let client = app
        .storage()
        .clients()
        .get(tenant, "org-app")
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(client.organization, OrgClientPolicy::Required);
    assert_eq!(client.scopes, ["openid", "org:admin"]);
}
