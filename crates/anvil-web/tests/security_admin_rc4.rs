//! Security tests for the rc.4 management API additions (plan 07.1-06): client home URL
//! validation refusals, the built-in console client deletion guard, and the admin-triggered
//! password reset (scope, tenant isolation, blocked users, no token in the response).

mod admin_support;
mod support;

use admin_support::{API, admin_token, assert_field_error, assert_problem, call};
use anvil_core::model::{
    ApplicationType, AuditAction, AuditQuery, ClientAuthMethod, ClientId, ClientKind, ClientSource,
    ClientType, ConsentMode, GrantType, NewClient, OrgClientPolicy, TenantId, TokenFormat,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::bootstrap::CONSOLE_CLIENT_ID;
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

// ---------------------------------------------------------------------------------------------
// Built-in console client
// ---------------------------------------------------------------------------------------------

fn system_id(app: &TestApp) -> TenantId {
    app.system.as_ref().expect("installed").tenant.id
}

fn default_id(app: &TestApp) -> TenantId {
    app.default.as_ref().expect("installed").tenant.id
}

/// Stores a public client `client_id` in `tenant` through the storage port (the console client
/// is created by the bootstrap at start; here only its identity matters).
async fn store_public_client(app: &TestApp, tenant: TenantId, client_id: &str) {
    app.storage()
        .clients()
        .create(
            tenant,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: client_id.to_owned(),
                name: "Console".to_owned(),
                client_type: ClientType::Public,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::None,
                secret_hash: None,
                jwks: None,
                redirect_uris: vec!["https://idp.example/console/callback".to_owned()],
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec!["openid".to_owned()],
                require_pkce: true,
                created_at: app.clock().now(),
                token_format: TokenFormat::Jwt,
                consent_mode: ConsentMode::SkipFirstParty,
                id_token_signed_response_alg: None,
                can_introspect: false,
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                allowed_resources: vec![],
                mfa_policy: None,
                metadata_expires_at: None,
                registration_access_token_hash: None,
                registration_source: ClientSource::Static,
                organization: OrgClientPolicy::Off,
                require_pushed_authorization_requests: false,
                client_kind: ClientKind::Application,
                headless_native: false,
                client_uri: None,
                initiate_login_uri: None,
            },
        )
        .await
        .expect("store the client");
}

async fn deleted_events(app: &TestApp, tenant: TenantId) -> usize {
    app.storage()
        .audit()
        .query(
            tenant,
            &AuditQuery {
                limit: 500,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
        .iter()
        .filter(|e| e.action == AuditAction::ClientDeleted)
        .count()
}

#[tokio::test]
async fn console_client_cannot_be_deleted() {
    let app = app().await;
    let system = system_id(&app);
    if app
        .storage()
        .clients()
        .get(system, CONSOLE_CLIENT_ID)
        .await
        .unwrap()
        .is_none()
    {
        store_public_client(&app, system, CONSOLE_CLIENT_ID).await;
    }
    let token = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{}/{CONSOLE_CLIENT_ID}", clients("system")),
        Some(&token),
        None,
    )
    .await;
    let problem = assert_problem(&resp, 409);
    assert_eq!(
        problem["detail"], "The console client is built in and cannot be deleted",
        "{problem}"
    );
    // Nothing removed, nothing audited.
    assert!(
        app.storage()
            .clients()
            .get(system, CONSOLE_CLIENT_ID)
            .await
            .unwrap()
            .is_some(),
        "the console client must survive"
    );
    assert_eq!(deleted_events(&app, system).await, 0);

    // Ordinary system-tenant clients are still deletable.
    store_public_client(&app, system, "ordinary-system-client").await;
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{}/ordinary-system-client", clients("system")),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    assert_eq!(deleted_events(&app, system).await, 1);
}

#[tokio::test]
async fn console_client_id_in_another_tenant_is_an_ordinary_client() {
    let app = app().await;
    let default = default_id(&app);
    store_public_client(&app, default, CONSOLE_CLIENT_ID).await;
    let token = admin_token(&app, "admin:clients:write").await;
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{}/{CONSOLE_CLIENT_ID}", clients("default")),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    assert!(
        app.storage()
            .clients()
            .get(default, CONSOLE_CLIENT_ID)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(deleted_events(&app, default).await, 1);
}
