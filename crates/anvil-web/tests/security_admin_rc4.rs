//! Security tests for the rc.4 management API additions (plan 07.1-06): client home URL
//! validation refusals, the built-in console client deletion guard, and the admin-triggered
//! password reset (scope, tenant isolation, blocked users, no token in the response).

mod admin_support;
mod support;
mod token_support;

use admin_support::{API, admin_token, assert_field_error, assert_problem, call};
use anvil_core::model::{
    ApplicationType, AuditAction, AuditQuery, ClientAuthMethod, ClientId, ClientKind, ClientSource,
    ClientType, ConsentMode, GrantType, NewClient, OrgClientPolicy, TenantId, TokenFormat,
};
use anvil_core::model::{SelfServiceKind, open_payload};
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

// ---------------------------------------------------------------------------------------------
// Administrator-sent password reset
// ---------------------------------------------------------------------------------------------

fn recovery_path(tenant: &str, user: impl std::fmt::Display) -> String {
    format!("{API}/tenants/{tenant}/users/{user}/recovery")
}

/// Creates an active password user in the default tenant; returns its id.
async fn create_user(app: &TestApp, token: &str, email: &str) -> String {
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(token),
        Some(json!({"email": email, "password": "a long enough password"})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    body_json(&resp)["id"].as_str().unwrap().to_owned()
}

async fn queued_emails(app: &TestApp) -> Vec<anvil_core::model::OutboxEmail> {
    app.storage()
        .outbox()
        .claim_due(app.clock().now(), 50, std::time::Duration::from_secs(120))
        .await
        .unwrap()
}

async fn recovery_events(app: &TestApp, tenant: TenantId) -> Vec<anvil_core::model::AuditEvent> {
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
        .into_iter()
        .filter(|e| e.action == AuditAction::UserRecoverySent)
        .collect()
}

#[tokio::test]
async fn admin_recovery_sends_the_self_service_recovery_email() {
    let app = app().await;
    let token = admin_token(&app, "admin:users:write").await;
    let id = create_user(&app, &token, "dora@example.test").await;

    let resp = call(
        &app,
        Method::POST,
        &recovery_path("default", &id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 202, "{}", resp.text());

    // One recovery email to the user's address, sealed, with the self-service link.
    let emails = queued_emails(&app).await;
    assert_eq!(emails.len(), 1);
    let mail = &emails[0];
    assert_eq!(mail.template, "recovery");
    assert_eq!(mail.to, "dora@example.test");
    assert_eq!(mail.tenant_id, default_id(&app));
    let payload = open_payload(app.kek(), default_id(&app), &mail.payload).unwrap();
    let link = &payload["link"];
    let prefix = format!("{}/ui/recovery?token=", app.issuer(None));
    let plaintext = link
        .strip_prefix(&prefix)
        .expect("self-service recovery link");
    assert_eq!(payload["expires_in"], "1 hour");

    // The link opens the reset form (a live Recovery token).
    let path = link
        .strip_prefix(&format!(
            "{}://{}",
            app.config.public_url.scheme(),
            app.config.public_url.host_port()
        ))
        .unwrap();
    let page = app.get(path).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let hash = anvil_core::model::SecretHash(anvil_jose::encoding::secret_hash(plaintext));
    assert!(
        app.storage()
            .users()
            .peek_self_service_token(
                default_id(&app),
                SelfServiceKind::Recovery,
                &hash,
                app.clock().now()
            )
            .await
            .unwrap()
    );

    // Audited with the administrator as the actor, target = the user, no details.
    let events = recovery_events(&app, default_id(&app)).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].target.as_deref(), Some(id.as_str()));
    assert_eq!(events[0].actor.kind, anvil_core::model::ActorKind::Admin);
    assert!(events[0].actor.id.is_some());
    assert!(events[0].details.as_map().is_empty());
}

#[tokio::test]
async fn admin_recovery_requires_users_write_scope() {
    let app = app().await;
    let writer = admin_token(&app, "admin:users:write").await;
    let id = create_user(&app, &writer, "erin@example.test").await;
    for scope in ["admin:users:read", "admin:read", "admin:clients:write"] {
        let token = admin_token(&app, scope).await;
        let resp = call(
            &app,
            Method::POST,
            &recovery_path("default", &id),
            Some(&token),
            None,
        )
        .await;
        assert_problem(&resp, 403);
    }
    // No token at all: 401.
    let resp = call(
        &app,
        Method::POST,
        &recovery_path("default", &id),
        None,
        None,
    )
    .await;
    assert_problem(&resp, 401);
    assert!(queued_emails(&app).await.is_empty());
    assert!(recovery_events(&app, default_id(&app)).await.is_empty());

    // admin:write is the other accepted scope.
    let full = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &recovery_path("default", &id),
        Some(&full),
        None,
    )
    .await;
    assert_eq!(resp.status, 202, "{}", resp.text());
}

#[tokio::test]
async fn admin_recovery_other_tenant_is_404() {
    let app = app().await;
    let token = admin_token(&app, "admin:write").await;
    // A user of the system tenant, addressed through the default tenant's path.
    let other = token_support::seed_user(&app, system_id(&app), "sys@example.test").await;
    let resp = call(
        &app,
        Method::POST,
        &recovery_path("default", other.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    // Unknown and malformed ids: 404 as well.
    for id in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_owned()] {
        let resp = call(
            &app,
            Method::POST,
            &recovery_path("default", &id),
            Some(&token),
            None,
        )
        .await;
        assert_problem(&resp, 404);
    }
    assert!(queued_emails(&app).await.is_empty());
    assert!(recovery_events(&app, default_id(&app)).await.is_empty());
    assert!(recovery_events(&app, system_id(&app)).await.is_empty());
}

#[tokio::test]
async fn admin_recovery_blocked_user_refused() {
    let app = app().await;
    let token = admin_token(&app, "admin:users:write").await;
    let id = create_user(&app, &token, "frank@example.test").await;
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default/users/{id}"),
        Some(&token),
        Some(json!({"status": "blocked"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(
        &app,
        Method::POST,
        &recovery_path("default", &id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 409);
    assert!(queued_emails(&app).await.is_empty());
    assert!(recovery_events(&app, default_id(&app)).await.is_empty());
}

#[tokio::test]
async fn admin_recovery_response_has_no_token() {
    let app = app().await;
    let token = admin_token(&app, "admin:users:write").await;
    let id = create_user(&app, &token, "gina@example.test").await;
    let resp = call(
        &app,
        Method::POST,
        &recovery_path("default", &id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 202, "{}", resp.text());
    // No body at all, so no token or link; no header carries one either.
    assert!(resp.body.is_empty(), "{}", resp.text());
    let emails = queued_emails(&app).await;
    let payload = open_payload(app.kek(), default_id(&app), &emails[0].payload).unwrap();
    let plaintext = payload["link"].split("token=").nth(1).unwrap().to_owned();
    for (name, value) in &resp.headers {
        assert!(
            !value.to_str().unwrap_or_default().contains(&plaintext),
            "header {name} carries the token"
        );
    }
    // The stored payload is sealed (no plaintext link at rest) and the audit event has no
    // details that could carry it.
    for value in emails[0].payload.values() {
        assert!(!value.contains(&plaintext));
    }
    let events = recovery_events(&app, default_id(&app)).await;
    assert!(events[0].details.as_map().is_empty());
}
