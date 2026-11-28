//! The built-in console client and the system-tenant policy (Research Open Question 5): system
//! tenant users are the administrators, the console signs in as the public client
//! `anvil-console` of the system tenant, the system tenant never allows self-registration, and
//! admin scopes are out of reach for users of other tenants.
//! Selected backend via `ANVILID_TEST_DB`.

mod authz;
mod support;
mod token_support;
mod ui_helpers;

use std::sync::Arc;

use anvil_core::model::{
    ActorKind, ApplicationType, AuditAction, AuditEvent, AuditQuery, AuthorizationParams,
    ClientAuthMethod, ClientType, ClientUpdate, ConsentMode, GrantType, PublicUrl,
    RegistrationMode, TenantId, TenantSettings, TokenFormat,
};
use anvil_core::ports::Clock;
use anvil_core::service::bootstrap::{BootstrapService, CONSOLE_CLIENT_ID, build_install_plan};
use anvil_web::adapters::argon2::Argon2Pool;
use authz::{
    assert_error_page, assert_error_redirect, authorize_path, get, pkce_params, web_client,
};
use support::{PROD_URL, TestApp, json, location};
use time::OffsetDateTime;
use ui_helpers::{message_keys, set_settings, system_tenant};

struct Frozen(OffsetDateTime);

impl Clock for Frozen {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

fn bootstrap(app: &TestApp) -> BootstrapService {
    BootstrapService {
        storage: app.storage_arc(),
        clock: Arc::new(Frozen(app.clock().now())),
        kek: app.kek_arc(),
        hasher: Arc::new(
            Argon2Pool::new(
                argon2::Params::new(256, 1, 1, None).expect("test argon2 params"),
                1,
            )
            .expect("argon2 pool"),
        ),
        policy: app.config.password_policy,
        public_url: app.config.public_url.clone(),
    }
}

fn url(s: &str) -> PublicUrl {
    PublicUrl::parse(s).expect("valid public url")
}

fn system_id(app: &TestApp) -> TenantId {
    app.system.as_ref().expect("installed").tenant.id
}

async fn system_events(app: &TestApp) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            system_id(app),
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

fn count(events: &[AuditEvent], action: AuditAction) -> usize {
    events.iter().filter(|e| e.action == action).count()
}

#[tokio::test]
async fn console_client_is_created_with_values_from_the_public_url() {
    let app = TestApp::new().await;
    bootstrap(&app)
        .ensure_console_client(&url(PROD_URL))
        .await
        .unwrap();
    let c = app
        .storage()
        .clients()
        .get(system_id(&app), CONSOLE_CLIENT_ID)
        .await
        .unwrap()
        .expect("console client exists");
    assert_eq!(c.client_type, ClientType::Public);
    assert_eq!(c.application_type, ApplicationType::Web);
    assert_eq!(c.auth_method, ClientAuthMethod::None);
    assert!(c.secret_hash.is_none());
    assert!(c.require_pkce);
    assert_eq!(
        c.redirect_uris,
        vec![format!("{PROD_URL}/console/callback")]
    );
    let mut grants = c.grant_types.clone();
    grants.sort();
    assert_eq!(
        grants,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
    );
    assert_eq!(
        c.scopes,
        vec!["openid", "profile", "email", "admin:read", "admin:write"]
    );
    assert_eq!(c.consent_mode, ConsentMode::SkipFirstParty);
    assert_eq!(c.token_format, TokenFormat::Jwt);
    assert!(!c.can_introspect);

    let events = system_events(&app).await;
    assert_eq!(count(&events, AuditAction::ClientCreated), 1);
    let created = events
        .iter()
        .find(|e| e.action == AuditAction::ClientCreated)
        .unwrap();
    assert_eq!(created.actor.kind, ActorKind::System);
    assert_eq!(created.target.as_deref(), Some(CONSOLE_CLIENT_ID));

    // The console client exists only in the system tenant.
    let default = app.default.as_ref().expect("installed").tenant.id;
    assert!(
        app.storage()
            .clients()
            .get(default, CONSOLE_CLIENT_ID)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn reconciling_is_idempotent_and_follows_the_public_url() {
    let app = TestApp::new().await;
    let svc = bootstrap(&app);
    svc.ensure_console_client(&url(PROD_URL)).await.unwrap();
    let before = system_events(&app).await.len();

    // Same URL: nothing written, nothing audited.
    svc.ensure_console_client(&url(PROD_URL)).await.unwrap();
    assert_eq!(system_events(&app).await.len(), before);

    // New public URL: the redirect URI follows, audited once as client_updated.
    svc.ensure_console_client(&url("https://id.example.org/"))
        .await
        .unwrap();
    let c = app
        .storage()
        .clients()
        .get(system_id(&app), CONSOLE_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        c.redirect_uris,
        vec!["https://id.example.org/console/callback"]
    );
    let events = system_events(&app).await;
    assert_eq!(events.len(), before + 1);
    let updated = events
        .iter()
        .find(|e| e.action == AuditAction::ClientUpdated)
        .expect("client_updated");
    assert_eq!(updated.actor.kind, ActorKind::System);
    assert_eq!(
        updated.details.as_map()["fields"],
        serde_json::json!(["redirect_uris"])
    );
}

#[tokio::test]
async fn system_tenant_registration_is_disabled_on_install_and_enforced_later() {
    // A fresh installation creates the system tenant with registration disabled.
    let (plan, _) =
        build_install_plan(OffsetDateTime::UNIX_EPOCH, &anvil_jose::Kek::generate()).unwrap();
    let system = plan
        .tenants
        .iter()
        .find(|t| t.slug == "system")
        .expect("system tenant");
    assert_eq!(system.settings.registration, RegistrationMode::Disabled);

    // An existing installation with open system registration is fixed and audited once.
    let app = TestApp::new().await;
    set_settings(
        &app,
        system_tenant(&app).id,
        TenantSettings {
            registration: RegistrationMode::Open,
            ..TenantSettings::default()
        },
    )
    .await;
    let svc = bootstrap(&app);
    svc.ensure_console_client(&url(PROD_URL)).await.unwrap();
    let stored = app
        .storage()
        .tenants()
        .get(system_id(&app))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.settings.registration, RegistrationMode::Disabled);
    let events = system_events(&app).await;
    assert_eq!(count(&events, AuditAction::TenantUpdated), 1);
    let fixed = events
        .iter()
        .find(|e| e.action == AuditAction::TenantUpdated)
        .unwrap();
    assert_eq!(fixed.actor.kind, ActorKind::System);
    svc.ensure_console_client(&url(PROD_URL)).await.unwrap();
    assert_eq!(
        count(&system_events(&app).await, AuditAction::TenantUpdated),
        1
    );

    // Nobody can sign up as an administrator.
    let resp = app.get("/t/system/ui/registration").await;
    assert_eq!(resp.status, 200);
    let html = resp.html();
    assert_eq!(
        message_keys(&html),
        vec!["registration.disabled".to_owned()]
    );
    assert!(!html.contains("registration-submit"), "no form");
}

#[tokio::test]
async fn default_tenant_clients_cannot_obtain_admin_scopes() {
    let app = TestApp::new().await;
    bootstrap(&app)
        .ensure_console_client(&url(PROD_URL))
        .await
        .unwrap();
    let iss = app.issuer(None);
    let tenant = authz::default_tenant(&app);
    let client = web_client(&app, &tenant).await;

    // A scope the client is not registered for is never granted.
    for scope in ["admin:read", "admin:read admin:write"] {
        let mut params = pkce_params(&client.client_id);
        for p in params.iter_mut() {
            if p.0 == "scope" {
                p.1 = scope;
            }
        }
        let resp = get(&app, &authorize_path("", &params), None).await;
        assert_error_redirect(&resp, authz::RP, "invalid_scope", &iss);
    }

    // The console client is unknown outside the system tenant.
    let resp = get(
        &app,
        &authorize_path("", &pkce_params(CONSOLE_CLIENT_ID)),
        None,
    )
    .await;
    assert_error_page(&resp, "unknown_client");
}

/// Scopes of the console client before rc.4.
const RC3_CONSOLE_SCOPES: [&str; 3] = ["openid", "admin:read", "admin:write"];

/// The console scopes from rc.4 on (C-M9): `profile` and `email` let the console show who is
/// signed in.
const CONSOLE_SCOPES: [&str; 5] = ["openid", "profile", "email", "admin:read", "admin:write"];

#[tokio::test]
async fn an_rc3_console_client_gets_profile_and_email_on_the_next_start() {
    let app = TestApp::new().await;
    let svc = bootstrap(&app);
    svc.ensure_console_client(&url(PROD_URL)).await.unwrap();
    let system = system_id(&app);

    // An installation upgraded from rc.3: the stored console client has the old scope list.
    app.storage()
        .clients()
        .update(
            system,
            CONSOLE_CLIENT_ID,
            &ClientUpdate {
                scopes: Some(RC3_CONSOLE_SCOPES.map(str::to_owned).to_vec()),
                ..ClientUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .unwrap()
        .expect("console client exists");
    let before = system_events(&app).await;

    // The next start reconciles the scopes, audited once as client_updated (scopes only).
    svc.ensure_console_client(&url(PROD_URL)).await.unwrap();
    let c = app
        .storage()
        .clients()
        .get(system, CONSOLE_CLIENT_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.scopes, CONSOLE_SCOPES);
    let events = system_events(&app).await;
    assert_eq!(events.len(), before.len() + 1);
    assert_eq!(
        count(&events, AuditAction::ClientUpdated),
        count(&before, AuditAction::ClientUpdated) + 1
    );
    let updated = events
        .iter()
        .find(|e| e.action == AuditAction::ClientUpdated)
        .expect("client_updated");
    assert_eq!(updated.actor.kind, ActorKind::System);
    assert_eq!(updated.target.as_deref(), Some(CONSOLE_CLIENT_ID));
    assert_eq!(
        updated.details.as_map()["fields"],
        serde_json::json!(["scopes"])
    );

    // A second start changes nothing.
    svc.ensure_console_client(&url(PROD_URL)).await.unwrap();
    assert_eq!(system_events(&app).await.len(), events.len());
}

#[tokio::test]
async fn console_sign_in_with_profile_and_email_returns_email_from_userinfo() {
    use token_support::{CHALLENGE, Rp, VERIFIER};

    let app = TestApp::new().await;
    bootstrap(&app)
        .ensure_console_client(&url(PROD_URL))
        .await
        .unwrap();
    let system = system_id(&app);
    let console = app
        .storage()
        .clients()
        .get(system, CONSOLE_CLIENT_ID)
        .await
        .unwrap()
        .expect("console client exists");
    let redirect = console.redirect_uris[0].clone();
    let scope = CONSOLE_SCOPES.join(" ");

    // The authorization endpoint accepts the full console scope list (no invalid_scope): with
    // no session it sends the browser to sign in.
    let resp = get(
        &app,
        &authorize_path(
            "/t/system",
            &[
                ("response_type", "code"),
                ("client_id", CONSOLE_CLIENT_ID),
                ("redirect_uri", &redirect),
                ("scope", &scope),
                ("state", "st-1"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ],
        ),
        None,
    )
    .await;
    assert!(resp.status.is_redirection(), "{}", resp.text());
    let to = location(&resp);
    assert!(!to.contains("error="), "no error redirect: {to}");
    assert!(
        !to.starts_with(&redirect),
        "not answered to the client: {to}"
    );

    // A system administrator signed in through the console gets the scopes and their email.
    let admin = token_support::seed_user(&app, system, "console-admin@example.test").await;
    let role = app
        .storage()
        .roles()
        .get_by_name(system, anvil_core::model::SYSTEM_ADMIN_ROLE)
        .await
        .unwrap()
        .expect("the system tenant has the administrator role");
    assert!(
        app.storage()
            .roles()
            .assign(system, role.id, admin.id, app.clock().now())
            .await
            .unwrap()
    );
    let session = token_support::seed_session(&app, system, &admin).await;
    let params = AuthorizationParams {
        redirect_uri: redirect.clone(),
        ..token_support::params(&scope, Some(CHALLENGE))
    };
    let rp = Rp {
        client: console,
        secret: None,
    };
    let code = token_support::issue_code(&app, system, &rp, &session, &params).await;
    let resp = token_support::token_at(
        &app,
        "/t/system/token",
        &rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    let granted: Vec<&str> = body["scope"].as_str().expect("scope").split(' ').collect();
    // The granted admin scopes are bounded by the administrator role (admin:write covers
    // admin:read, so only admin:write is listed).
    for s in ["openid", "profile", "email", "admin:write"] {
        assert!(granted.contains(&s), "{s} granted: {granted:?}");
    }
    let access_token = body["access_token"].as_str().expect("access_token");
    let resp = token_support::get_with_auth(
        &app,
        "/t/system/userinfo",
        &format!("Bearer {access_token}"),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let info = json(&resp);
    assert_eq!(info["sub"], admin.id.to_string());
    assert_eq!(info["email"], "console-admin@example.test");
    assert_eq!(info["email_verified"], true);
    assert!(info.get("name").is_some(), "profile claims: {info}");
}
