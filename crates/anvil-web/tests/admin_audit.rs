//! Admin actions are audited (ADM-04): every management create/update/delete of tenants, clients
//! and users, client secret rotation and setup completion records exactly one typed event with
//! the admin actor (token subject) and the request context; failures record nothing and details
//! never carry a secret. Also covers the 0.2 tenant settings (signing algorithms, CAPTCHA) and
//! the client ID-token algorithm rule through the core services.
//! Selected backend via `ANVILID_TEST_DB`.

mod admin_support;
mod support;
mod ui_helpers;

use std::sync::Arc;

use admin_support::*;
use anvil_core::error::CoreError;
use anvil_core::model::{
    ActorKind, ApplicationType, AuditAction, AuditActor, AuditEvent, AuditOutcome, AuditQuery,
    CaptchaProvider, ClientAuthMethod, ClientType, GrantType, RequestContext, TenantId,
    TenantSettings,
};
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::ports::{Clock, Storage};
use anvil_core::service::client::{ClientInput, ClientOptions, ClientService};
use anvil_core::service::tenant::{CaptchaChange, CaptchaInput, TenantPatch, TenantService};
use axum::http::Method;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use support::{DEFAULT_PEER, TestApp, json as body_json};
use time::OffsetDateTime;

const FULL: &str = "admin:read admin:write";

struct Frozen(OffsetDateTime);

impl Clock for Frozen {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// An admin client of the system tenant and a token for it.
struct Admin {
    client_id: String,
    token: String,
}

async fn admin(app: &TestApp) -> Admin {
    let client_id = system_client(app, &["admin:read", "admin:write"]).await;
    let system = app.system.as_ref().expect("installed");
    let token = mint_access_token(app, system, &system_issuer(app), &client_id, FULL).await;
    Admin { client_id, token }
}

async fn events_in(storage: &dyn Storage, tenant: TenantId) -> Vec<AuditEvent> {
    storage
        .audit()
        .query(
            tenant,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

async fn events(app: &TestApp, tenant: TenantId) -> Vec<AuditEvent> {
    events_in(app.storage(), tenant).await
}

fn of(events: &[AuditEvent], action: AuditAction) -> Vec<&AuditEvent> {
    events.iter().filter(|e| e.action == action).collect()
}

fn system_id(app: &TestApp) -> TenantId {
    app.system.as_ref().expect("installed").tenant.id
}

fn default_id(app: &TestApp) -> TenantId {
    app.default.as_ref().expect("installed").tenant.id
}

/// Asserts the admin actor, target and request context of an admin event.
fn assert_admin_event(e: &AuditEvent, admin: &Admin, target: &str) {
    assert_eq!(e.actor.kind, ActorKind::Admin);
    assert_eq!(e.actor.id.as_deref(), Some(admin.client_id.as_str()));
    assert_eq!(e.target.as_deref(), Some(target));
    assert_eq!(e.outcome, AuditOutcome::Success);
    assert_eq!(e.ctx.ip, Some(DEFAULT_PEER.ip()));
}

fn details_text(events: &[AuditEvent]) -> String {
    events
        .iter()
        .map(|e| serde_json::Value::Object(e.details.as_map().clone()).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn clock(app: &TestApp) -> Arc<dyn Clock> {
    Arc::new(Frozen(app.clock().now()))
}

fn tenants(app: &TestApp) -> TenantService {
    TenantService {
        storage: app.storage_arc(),
        clock: clock(app),
        kek: app.kek_arc(),
    }
}

fn clients(app: &TestApp) -> ClientService {
    ClientService {
        storage: app.storage_arc(),
        clock: clock(app),
        redirect_validator: validate_redirect_uri,
    }
}

#[tokio::test]
async fn client_crud_and_secret_rotation_are_audited_once_each() {
    let app = TestApp::new().await;
    let admin = admin(&app).await;
    let base = format!("{API}/tenants/default/clients");

    let resp = call(
        &app,
        Method::POST,
        &base,
        Some(&admin.token),
        Some(json!({
            "name": "Shop",
            "client_type": "confidential",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let created = body_json(&resp);
    let client_id = created["client_id"].as_str().unwrap().to_owned();
    let first_secret = created["client_secret"].as_str().unwrap().to_owned();
    let path = format!("{base}/{client_id}");

    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&admin.token),
        Some(json!({"name": "Shop 2"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    let resp = call(
        &app,
        Method::POST,
        &format!("{path}/secret"),
        Some(&admin.token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let second_secret = body_json(&resp)["client_secret"]
        .as_str()
        .unwrap()
        .to_owned();

    let resp = call(&app, Method::DELETE, &path, Some(&admin.token), None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());

    let all = events(&app, default_id(&app)).await;
    assert_eq!(all.len(), 4, "{all:?}");
    for action in [
        AuditAction::ClientCreated,
        AuditAction::ClientUpdated,
        AuditAction::ClientSecretRotated,
        AuditAction::ClientDeleted,
    ] {
        let found = of(&all, action);
        assert_eq!(found.len(), 1, "{action:?}");
        assert_admin_event(found[0], &admin, &client_id);
    }
    let updated = of(&all, AuditAction::ClientUpdated)[0];
    assert_eq!(updated.details.as_map()["fields"], json!(["name"]));
    let text = details_text(&all);
    assert!(!text.contains(&first_secret) && !text.contains(&second_secret));
    // Client events are recorded in the client's tenant only.
    assert!(events(&app, system_id(&app)).await.is_empty());
}

#[tokio::test]
async fn tenant_and_user_crud_are_audited_once_each() {
    let app = TestApp::new().await;
    let admin = admin(&app).await;

    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&admin.token),
        Some(json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let acme_id: TenantId = serde_json::from_value(body_json(&resp)["id"].clone()).unwrap();
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/acme"),
        Some(&admin.token),
        Some(json!({"display_name": "Acme Inc"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    let password = "a long user passphrase";
    let users = format!("{API}/tenants/acme/users");
    let resp = call(
        &app,
        Method::POST,
        &users,
        Some(&admin.token),
        Some(json!({"email": "ada@example.com", "password": password})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let user_id = body_json(&resp)["id"].as_str().unwrap().to_owned();
    let user_path = format!("{users}/{user_id}");
    let resp = call(
        &app,
        Method::PATCH,
        &user_path,
        Some(&admin.token),
        Some(json!({"status": "blocked", "email_verified": true})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let acme_events = events(&app, acme_id).await;
    let resp = call(&app, Method::DELETE, &user_path, Some(&admin.token), None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let acme_events_after = events(&app, acme_id).await;

    // User events live in the user's tenant.
    assert_eq!(acme_events.len(), 2, "{acme_events:?}");
    assert_eq!(acme_events_after.len(), 3, "{acme_events_after:?}");
    for action in [
        AuditAction::UserCreated,
        AuditAction::UserUpdated,
        AuditAction::UserDeleted,
    ] {
        let found = of(&acme_events_after, action);
        assert_eq!(found.len(), 1, "{action:?}");
        assert_admin_event(found[0], &admin, &user_id);
    }
    let updated = of(&acme_events_after, AuditAction::UserUpdated)[0];
    assert_eq!(
        updated.details.as_map()["fields"],
        json!(["email_verified", "status"])
    );
    let text = details_text(&acme_events_after);
    assert!(!text.contains(password) && !text.contains("ada@example.com"));

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/acme"),
        Some(&admin.token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());

    // Tenant events live in the system tenant (a deleted tenant's own log is gone).
    let system = events(&app, system_id(&app)).await;
    assert_eq!(system.len(), 3, "{system:?}");
    let target = acme_id.to_string();
    for action in [
        AuditAction::TenantCreated,
        AuditAction::TenantUpdated,
        AuditAction::TenantDeleted,
    ] {
        let found = of(&system, action);
        assert_eq!(found.len(), 1, "{action:?}");
        assert_admin_event(found[0], &admin, &target);
    }
}

#[tokio::test]
async fn failed_admin_actions_record_nothing() {
    let app = TestApp::new().await;
    let admin = admin(&app).await;
    let t = Some(admin.token.as_str());
    let cases = [
        (
            Method::POST,
            format!("{API}/tenants/default/clients"),
            Some(json!({
                "name": "Bad",
                "client_type": "public",
                "auth_method": "client_secret_basic",
                "redirect_uris": ["https://rp.example/cb"],
            })),
            422,
        ),
        (
            Method::PATCH,
            format!("{API}/tenants/default/clients/nope"),
            Some(json!({"name": "x"})),
            404,
        ),
        (
            Method::DELETE,
            format!("{API}/tenants/default/clients/nope"),
            None,
            404,
        ),
        (
            Method::POST,
            format!("{API}/tenants/default/clients/nope/secret"),
            None,
            404,
        ),
        (
            Method::POST,
            format!("{API}/tenants/default/users"),
            Some(json!({"email": "not-an-email", "password": "a long user passphrase"})),
            422,
        ),
        (
            Method::DELETE,
            format!("{API}/tenants/default/users/{}", uuid::Uuid::now_v7()),
            None,
            404,
        ),
        (Method::DELETE, format!("{API}/tenants/default"), None, 403),
        (
            Method::POST,
            format!("{API}/tenants"),
            Some(json!({"slug": "system", "display_name": "x"})),
            422,
        ),
    ];
    for (method, path, body, status) in cases {
        let resp = call(&app, method.clone(), &path, t, body).await;
        assert_eq!(resp.status, status, "{method} {path}: {}", resp.text());
    }
    assert!(events(&app, default_id(&app)).await.is_empty());
    assert!(events(&app, system_id(&app)).await.is_empty());
}

#[tokio::test]
async fn signing_algs_enable_keys_and_gate_client_id_token_alg() {
    let app = TestApp::new().await;
    let ctx = RequestContext::new(Some(DEFAULT_PEER.ip()), Some("test"), None);
    let actor = AuditActor::admin("tester");
    let default = tenants(&app).get("default").await.unwrap();
    let es256_client = || {
        (
            ClientInput {
                name: "ES app".into(),
                client_type: ClientType::Confidential,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::ClientSecretBasic,
                redirect_uris: vec!["https://rp.example/cb".into()],
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec!["openid".into()],
                require_pkce: None,
                jwks: None,
                jwks_uri: None,
            },
            ClientOptions {
                id_token_signed_response_alg: Some("ES256".into()),
                ..ClientOptions::default()
            },
        )
    };

    // ES256 is not enabled yet: the client is refused and nothing is recorded.
    let (input, options) = es256_client();
    let err = clients(&app)
        .create(&default, input, options, actor.clone(), &ctx)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CoreError::Validation {
            field: "id_token_signed_response_alg",
            ..
        }
    ));

    // Unknown algorithms are rejected.
    let bad = TenantPatch {
        settings: Some(TenantSettings {
            signing_algs: vec!["HS256".into()],
            ..default.settings.clone()
        }),
        ..TenantPatch::default()
    };
    let err = tenants(&app)
        .update("default", bad, None, actor.clone(), &ctx)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CoreError::Validation {
            field: "signing_algs",
            ..
        }
    ));
    assert!(events(&app, default_id(&app)).await.is_empty());
    assert!(events(&app, system_id(&app)).await.is_empty());

    // Enabling ES256 stores RS256 + ES256 and creates an active ES256 key right away.
    let enable = TenantPatch {
        settings: Some(TenantSettings {
            signing_algs: vec!["ES256".into()],
            ..default.settings.clone()
        }),
        ..TenantPatch::default()
    };
    let updated = tenants(&app)
        .update("default", enable, None, actor.clone(), &ctx)
        .await
        .unwrap();
    assert_eq!(updated.settings.signing_algs, vec!["RS256", "ES256"]);
    assert!(
        app.storage()
            .keys()
            .active(updated.id, "ES256")
            .await
            .unwrap()
            .is_some()
    );
    let system = events(&app, system_id(&app)).await;
    let tenant_updated = of(&system, AuditAction::TenantUpdated);
    assert_eq!(tenant_updated.len(), 1);
    assert_eq!(
        tenant_updated[0].details.as_map()["fields"],
        json!(["settings"])
    );

    let (input, options) = es256_client();
    let created = clients(&app)
        .create(&updated, input, options, actor, &ctx)
        .await
        .unwrap();
    assert_eq!(
        created.client.id_token_signed_response_alg.as_deref(),
        Some("ES256")
    );
}

#[tokio::test]
async fn captcha_settings_are_sealed_and_cleared() {
    let app = TestApp::new().await;
    let ctx = RequestContext::new(Some(DEFAULT_PEER.ip()), None, None);
    let actor = AuditActor::admin("tester");
    let secret = "0x-captcha-secret-value";
    let set = CaptchaChange::Set(CaptchaInput {
        provider: CaptchaProvider::Hcaptcha,
        site_key: "site-key-1".into(),
        secret: SecretString::from(secret.to_owned()),
    });
    let t = tenants(&app)
        .update(
            "default",
            TenantPatch::default(),
            Some(set),
            actor.clone(),
            &ctx,
        )
        .await
        .unwrap();
    let captcha = t.settings.captcha.clone().expect("captcha enabled");
    assert_eq!(captcha.provider, CaptchaProvider::Hcaptcha);
    assert_eq!(captcha.site_key, "site-key-1");
    assert!(!captcha.secret_sealed.contains(secret));
    let opened = anvil_web::adapters::captcha::open_secret(app.kek(), t.id, &captcha).unwrap();
    assert_eq!(opened.expose_secret(), secret);
    // The stored tenant holds the same sealed value.
    let stored = tenants(&app).get("default").await.unwrap();
    assert_eq!(stored.settings.captcha.as_ref(), Some(&captcha));

    // A plain settings patch keeps the CAPTCHA.
    let patch = TenantPatch {
        settings: Some(TenantSettings {
            require_verified_email: true,
            ..TenantSettings::default()
        }),
        ..TenantPatch::default()
    };
    let t = tenants(&app)
        .update("default", patch, None, actor.clone(), &ctx)
        .await
        .unwrap();
    assert_eq!(t.settings.captcha.as_ref(), Some(&captcha));

    let t = tenants(&app)
        .update(
            "default",
            TenantPatch::default(),
            Some(CaptchaChange::Clear),
            actor,
            &ctx,
        )
        .await
        .unwrap();
    assert_eq!(t.settings.captcha, None);

    let system = events(&app, system_id(&app)).await;
    assert_eq!(of(&system, AuditAction::TenantUpdated).len(), 3);
    assert!(!details_text(&system).contains(secret));
}

#[tokio::test]
async fn completing_setup_is_audited() {
    use ui_helpers::{Client as _, OwnApp, open_form};

    let app = OwnApp::installed().await;
    let (action, csrf) = open_form(&app, &format!("/setup?token={}", app.setup_token)).await;
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", csrf.as_str()),
                ("token", app.setup_token.as_str()),
                ("email", "root@example.com"),
                ("password", "a long admin passphrase"),
            ],
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let system = app.tenant("system").await;
    let all = events_in(app.storage.as_ref(), system.id).await;
    let done = of(&all, AuditAction::AdminSetupCompleted);
    assert_eq!(done.len(), 1, "{all:?}");
    let admin = app
        .storage
        .users()
        .get_by_email(system.id, "root@example.com")
        .await
        .unwrap()
        .expect("administrator created");
    assert_eq!(done[0].actor.kind, ActorKind::Admin);
    assert_eq!(done[0].actor.id, Some(admin.id.to_string()));
    assert_eq!(done[0].target, Some(admin.id.to_string()));
    assert_eq!(done[0].ctx.ip, Some(DEFAULT_PEER.ip()));
    assert!(!details_text(&all).contains("a long admin passphrase"));
}
