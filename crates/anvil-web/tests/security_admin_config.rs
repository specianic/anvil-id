//! Declarative configuration negative tests (security map, ADM-06/ADM-07):
//!
//! - the API never resolves secret references (`{env}` / `{file}`): refused with a 422 naming
//!   the field, nothing written;
//! - an export never contains a secret, a secret hash or sealed bytes;
//! - planning and applying need `admin:write` (reading needs `admin:read`);
//! - an invalid document changes nothing (every issue reported by path);
//! - a document cannot lock the system tenant's administrators out: role changes go through
//!   `RoleService`, and the whole batch is refused before any write.

mod admin_support;
mod support;
mod token_support;

use admin_support::{API, admin_token, assert_problem, call};
use anvil_core::model::{
    AuditEvent, AuditQuery, NewRole, Role, RoleId, SYSTEM_ADMIN_ROLE, TenantId, User,
};
use anvil_core::service::bootstrap::{CONSOLE_CLIENT_ID, build_console_client};
use anvil_jose::encoding::{b64url, secret_hash};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::{ClockNow as _, default_tenant, seed_user};

const CLIENT_SECRET: &str = "billing-client-secret-0123456789-abcdef";
const WHSEC: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const SMTP_PASSWORD: &str = "smtp-password-do-not-leak";
const CONNECTION_SECRET: &str = "google-upstream-secret-do-not-leak";

fn system(app: &TestApp) -> TenantId {
    app.system.as_ref().expect("installed").tenant.id
}

async fn events(app: &TestApp, tenant: TenantId) -> Vec<AuditEvent> {
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

async fn post(
    app: &TestApp,
    token: Option<&str>,
    path: &str,
    doc: &Value,
) -> support::TestResponse {
    call(app, Method::POST, path, token, Some(doc.clone())).await
}

fn with_secrets(mut doc: Value) -> Value {
    doc["clients"] = json!([{
        "client_id": "billing-web",
        "name": "Billing",
        "client_type": "confidential",
        "application_type": "web",
        "auth_method": "client_secret_basic",
        "secret": {"value": CLIENT_SECRET},
        "redirect_uris": ["https://billing.example.test/cb"],
        "grant_types": ["authorization_code"],
        "scopes": ["openid"],
    }]);
    doc["connections"] = json!([{
        "slug": "google",
        "display_name": "Google",
        "config": {"type": "social", "provider": "google", "client_id": "abc.apps.example.test"},
        "secret": {"value": CONNECTION_SECRET},
    }]);
    doc["webhooks"] = json!([{
        "name": "crm",
        "url": "https://hooks.example/in",
        "events": ["user.created"],
        "secret": {"value": WHSEC},
    }]);
    doc["smtp"] = json!({
        "host": "smtp.example.test",
        "port": 587,
        "username": "mailer",
        "password": {"value": SMTP_PASSWORD},
        "from": "id@example.test",
        "tls": "starttls",
    });
    doc
}

#[tokio::test]
async fn config_apply_never_reads_server_env_or_files() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let base = with_secrets(export(&app, &token, "default").await);
    let before = events(&app, tenant).await.len();
    // PATH is set in every process; a file that exists everywhere.
    for (pointer, reference, field) in [
        (
            "/clients/0/secret",
            json!({"env": "PATH"}),
            "clients[0].secret",
        ),
        (
            "/connections/0/secret",
            json!({"file": "/etc/hostname"}),
            "connections[0].secret",
        ),
        (
            "/webhooks/0/secret",
            json!({"env": "PATH"}),
            "webhooks[0].secret",
        ),
        (
            "/smtp/password",
            json!({"file": "/etc/passwd"}),
            "smtp.password",
        ),
    ] {
        let mut doc = base.clone();
        *doc.pointer_mut(pointer).expect("secret field") = reference;
        for op in ["plan", "apply"] {
            let resp = post(
                &app,
                Some(&token),
                &format!("{API}/tenants/default/config/{op}"),
                &doc,
            )
            .await;
            let body = assert_problem(&resp, 422);
            assert_eq!(body["errors"][0]["field"], field, "{body}");
            assert!(
                body["errors"][0]["message"]
                    .as_str()
                    .unwrap()
                    .contains("resolved by the anvilid CLI"),
                "{body}"
            );
            // Nothing of the server's environment or files comes back.
            let text = resp.text();
            assert!(
                !text.contains("/usr/bin") && !text.contains("root:"),
                "{text}"
            );
        }
    }
    assert_eq!(events(&app, tenant).await.len(), before);
    assert!(
        app.storage()
            .clients()
            .get(tenant, "billing-web")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn config_export_contains_no_secrets_or_hashes() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let doc = with_secrets(export(&app, &token, "default").await);
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/default/config/apply"),
        &doc,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    let exported = export(&app, &token, "default").await;
    let text = exported.to_string();
    let client_hash = secret_hash(CLIENT_SECRET);
    let mut forbidden = vec![
        CLIENT_SECRET.to_owned(),
        WHSEC.to_owned(),
        WHSEC.trim_start_matches("whsec_").to_owned(),
        SMTP_PASSWORD.to_owned(),
        CONNECTION_SECRET.to_owned(),
        b64url(&client_hash),
        client_hash.iter().map(|b| format!("{b:02x}")).collect(),
    ];
    // Sealed bytes as stored, in the encodings an API could leak them in.
    let conn = &app.storage().connections().list(tenant).await.unwrap()[0];
    let sealed = conn.secret_enc.clone().expect("sealed connection secret");
    forbidden.push(b64url(&sealed));
    let hook = &app
        .storage()
        .webhooks()
        .list_endpoints(tenant)
        .await
        .unwrap()[0];
    forbidden.push(b64url(&hook.secret_enc));
    for f in &forbidden {
        assert!(!text.contains(f.as_str()), "export leaks {f}");
    }
    for key in [
        "secret_hash",
        "secret_enc",
        "password_enc",
        "secret_sealed",
        "\"value\"",
    ] {
        assert!(!text.contains(key), "export has {key}: {text}");
    }
    assert_eq!(
        exported["clients"][0]["secret"],
        json!({"configured": true})
    );
    assert_eq!(
        exported["connections"][0]["secret"],
        json!({"configured": true})
    );
    assert_eq!(
        exported["webhooks"][0]["secret"],
        json!({"configured": true})
    );
    assert_eq!(exported["smtp"]["password"], json!({"configured": true}));
}

#[tokio::test]
async fn config_apply_requires_admin_write() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let write = admin_token(&app, "admin:write").await;
    let doc = with_secrets(export(&app, &write, "default").await);
    for slug in ["default", "system"] {
        let path = format!("{API}/tenants/{slug}/config");
        assert_problem(&call(&app, Method::GET, &path, None, None).await, 401);
        let settings = admin_token(&app, "admin:settings:read").await;
        assert_problem(
            &call(&app, Method::GET, &path, Some(&settings), None).await,
            403,
        );
        let read = admin_token(&app, "admin:read").await;
        let resp = call(&app, Method::GET, &path, Some(&read), None).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
    }
    for op in ["plan", "apply"] {
        let path = format!("{API}/tenants/default/config/{op}");
        assert_problem(&post(&app, None, &path, &doc).await, 401);
        for scope in [
            "admin:read",
            "admin:settings:write",
            "admin:clients:write admin:settings:write admin:tenants:write",
        ] {
            let token = admin_token(&app, scope).await;
            assert_problem(&post(&app, Some(&token), &path, &doc).await, 403);
        }
    }
    assert!(
        app.storage()
            .clients()
            .get(tenant, "billing-web")
            .await
            .unwrap()
            .is_none()
    );
    let resp = post(
        &app,
        Some(&write),
        &format!("{API}/tenants/default/config/apply"),
        &doc,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn config_apply_invalid_document_changes_nothing() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let mut doc = with_secrets(export(&app, &token, "default").await);
    doc["roles"] = json!([{"name": "editor", "permissions": ["docs:write"]}]);
    let first = doc["clients"][0].clone();
    for id in ["second", "third"] {
        let mut c = first.clone();
        c["client_id"] = json!(id);
        doc["clients"].as_array_mut().unwrap().push(c);
    }
    doc["clients"][2]["redirect_uris"] = json!(["javascript:alert(1)"]);
    doc["webhooks"][0]["url"] = json!("https://127.0.0.1/hook");
    doc["tenant"]["settings"]["captcha"] =
        json!({"provider": "turnstile", "site_key": "k", "secret_sealed": "x"});
    let before = events(&app, tenant).await.len();
    for op in ["plan", "apply", "apply?prune=true"] {
        let resp = post(
            &app,
            Some(&token),
            &format!("{API}/tenants/default/config/{op}"),
            &doc,
        )
        .await;
        let body = assert_problem(&resp, 422);
        let fields: Vec<&str> = body["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["field"].as_str().unwrap())
            .collect();
        for want in [
            "tenant.settings.captcha",
            "clients[2].redirect_uris[0]",
            "webhooks[0].url",
        ] {
            assert!(fields.contains(&want), "{want} missing: {body}");
        }
        assert!(!resp.text().contains(CLIENT_SECRET));
    }
    assert_eq!(events(&app, tenant).await.len(), before);
    let storage = app.storage();
    assert!(
        storage
            .roles()
            .get_by_name(tenant, "editor")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .clients()
            .get(tenant, "billing-web")
            .await
            .unwrap()
            .is_none()
    );
    assert!(storage.connections().list(tenant).await.unwrap().is_empty());
    assert!(
        storage
            .webhooks()
            .list_endpoints(tenant)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .mail_settings()
            .smtp(tenant)
            .await
            .unwrap()
            .is_none()
    );

    // Unknown fields and other versions are refused too.
    let mut extra = doc.clone();
    extra["bogus"] = json!(true);
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/default/config/plan"),
        &extra,
    )
    .await;
    assert_problem(&resp, 422);
}

async fn administrator(app: &TestApp) -> Role {
    app.storage()
        .roles()
        .get_by_name(system(app), SYSTEM_ADMIN_ROLE)
        .await
        .expect("lookup")
        .expect("install creates the administrator role")
}

async fn system_admin(app: &TestApp, email: &str) -> User {
    let user = seed_user(app, system(app), email).await;
    assert!(
        app.storage()
            .roles()
            .assign(
                system(app),
                administrator(app).await.id,
                user.id,
                app.clock_now()
            )
            .await
            .unwrap()
    );
    user
}

#[tokio::test]
async fn config_apply_cannot_lock_out_system_admins() {
    let app = TestApp::new().await;
    system_admin(&app, "root@example.test").await;
    let token = admin_token(&app, "admin:write").await;
    let base = export(&app, &token, "system").await;
    // The export omits the console client and never carries role assignments.
    assert!(
        base["clients"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["client_id"] != "anvil-console")
    );
    assert!(!base.to_string().contains("root@example.test"));
    let roles = base["roles"].as_array().unwrap();
    assert!(roles.iter().any(|r| r["name"] == SYSTEM_ADMIN_ROLE));
    let before = events(&app, system(&app)).await.len();

    // Editing `administrator` so no admin:write holder remains, together with other changes:
    // refused before anything is written (the new role is not created).
    let mut edit = base.clone();
    for r in edit["roles"].as_array_mut().unwrap() {
        if r["name"] == SYSTEM_ADMIN_ROLE {
            r["permissions"] = json!(["admin:read"]);
        }
    }
    edit["roles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "auditors", "permissions": ["admin:audit:read"]}));
    // Pruning `administrator` away is the same removal.
    let mut pruned = base.clone();
    pruned["roles"] = json!([{"name": "auditors", "permissions": ["admin:audit:read"]}]);
    for (doc, op) in [
        (&edit, "plan"),
        (&edit, "apply"),
        (&edit, "apply?prune=true"),
        (&pruned, "apply?prune=true"),
    ] {
        let resp = post(
            &app,
            Some(&token),
            &format!("{API}/tenants/system/config/{op}"),
            doc,
        )
        .await;
        let body = assert_problem(&resp, 409);
        assert!(
            body["detail"].as_str().unwrap().contains("administrator"),
            "{body}"
        );
    }
    assert_eq!(administrator(&app).await.permissions, ["admin:write"]);
    assert!(
        app.storage()
            .roles()
            .get_by_name(system(&app), "auditors")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(events(&app, system(&app)).await.len(), before);

    // Without prune the missing role stays, so that document is fine (only the new role).
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/system/config/apply"),
        &pruned,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(administrator(&app).await.permissions, ["admin:write"]);

    // With another administrator through another role, the edit is allowed.
    let other = seed_user(&app, system(&app), "second@example.test").await;
    let ops = app
        .storage()
        .roles()
        .create(
            system(&app),
            &NewRole {
                id: RoleId::new_v7(),
                org_id: None,
                name: "ops-admin".into(),
                description: String::new(),
                permissions: vec!["admin:write".into()],
                created_at: app.clock_now(),
            },
        )
        .await
        .unwrap();
    app.storage()
        .roles()
        .assign(system(&app), ops.id, other.id, app.clock_now())
        .await
        .unwrap();
    let mut edit = export(&app, &token, "system").await;
    for r in edit["roles"].as_array_mut().unwrap() {
        if r["name"] == SYSTEM_ADMIN_ROLE {
            r["permissions"] = json!(["admin:read"]);
        }
    }
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/system/config/apply"),
        &edit,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(administrator(&app).await.permissions, ["admin:read"]);
}

#[tokio::test]
async fn system_document_keeps_registration_disabled_and_the_console_client_out() {
    let app = TestApp::new().await;
    // The console client as startup reconciliation creates it.
    app.storage()
        .clients()
        .create(
            system(&app),
            &build_console_client(app.clock_now(), &app.config.public_url),
        )
        .await
        .expect("console client");
    let token = admin_token(&app, "admin:write").await;
    let base = export(&app, &token, "system").await;
    assert!(
        base["clients"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["client_id"] != CONSOLE_CLIENT_ID),
        "{base}"
    );
    assert_eq!(base["tenant"]["settings"]["dcr"]["policy"], "disabled");
    assert_eq!(base["tenant"]["settings"]["cimd"]["policy"], "disabled");
    let mut doc = base.clone();
    doc["tenant"]["settings"]["dcr"]["policy"] = json!("open");
    doc["tenant"]["settings"]["cimd"]["policy"] = json!("allow_listed");
    doc["clients"].as_array_mut().unwrap().push(json!({
        "client_id": "anvil-console",
        "name": "Hijack",
        "client_type": "public",
        "application_type": "web",
        "auth_method": "none",
        "redirect_uris": ["https://evil.example.test/cb"],
        "grant_types": ["authorization_code"],
        "scopes": ["openid", "admin:write"],
    }));
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/system/config/apply"),
        &doc,
    )
    .await;
    let body = assert_problem(&resp, 422);
    let fields: Vec<&str> = body["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["field"].as_str().unwrap())
        .collect();
    assert!(fields.contains(&"tenant.settings.dcr.policy"), "{body}");
    assert!(fields.contains(&"tenant.settings.cimd.policy"), "{body}");
    assert!(fields.iter().any(|f| f.ends_with(".client_id")), "{body}");
    // The console client is untouched; the base export applies as a no-op.
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/system/config/apply?prune=true"),
        &base,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["applied"], false);
    assert!(
        app.storage()
            .clients()
            .get(system(&app), CONSOLE_CLIENT_ID)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn config_apply_refuses_admin_scope_on_non_system_client() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let mut doc = with_secrets(export(&app, &token, "default").await);
    doc["clients"][0]["scopes"] = json!(["openid", "admin:write"]);
    let before = events(&app, tenant).await.len();
    for op in ["plan", "apply"] {
        let resp = post(
            &app,
            Some(&token),
            &format!("{API}/tenants/default/config/{op}"),
            &doc,
        )
        .await;
        let body = assert_problem(&resp, 422);
        let fields: Vec<&str> = body["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["field"].as_str().unwrap())
            .collect();
        assert!(fields.contains(&"clients[0].scopes"), "{body}");
    }
    assert_eq!(events(&app, tenant).await.len(), before);
    let storage = app.storage();
    assert!(
        storage
            .clients()
            .get(tenant, "billing-web")
            .await
            .unwrap()
            .is_none()
    );
    assert!(storage.connections().list(tenant).await.unwrap().is_empty());

    // An existing client cannot be updated to the scope either.
    doc["clients"][0]["scopes"] = json!(["openid"]);
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/default/config/apply"),
        &doc,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    doc["clients"][0]["scopes"] = json!(["openid", "admin:write"]);
    let before = events(&app, tenant).await.len();
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/default/config/apply"),
        &doc,
    )
    .await;
    assert_problem(&resp, 422);
    assert_eq!(events(&app, tenant).await.len(), before);
    let stored = storage
        .clients()
        .get(tenant, "billing-web")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.scopes, vec!["openid"]);
}

// ---------------------------------------------------------------------------------------------
// Organizations and logos in the document (07.1-11)
// ---------------------------------------------------------------------------------------------

const ORG_SECRET: &str = "org-upstream-secret-do-not-leak";

/// A PNG by magic bytes (the server sniffs, it does not decode images).
const PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, b'I', b'H', b'D', b'R', 7,
];

fn b64(bytes: &[u8]) -> String {
    anvil_jose::encoding::b64std(bytes)
}

async fn apply_ok(app: &TestApp, token: &str, doc: &Value, prune: bool) -> Value {
    let query = if prune { "?prune=true" } else { "" };
    let resp = post(
        app,
        Some(token),
        &format!("{API}/tenants/default/config/apply{query}"),
        doc,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

fn fields_of(body: &Value) -> Vec<String> {
    body["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["field"].as_str().unwrap().to_owned())
        .collect()
}

/// An organization `acme` with an enabled OIDC connection `acme-sso`, seeded through storage
/// (enabling through a service would fetch the issuer's discovery document).
async fn seed_org_with_connection(app: &TestApp, tenant: TenantId) -> anvil_core::model::OrgId {
    use anvil_core::model::{ConnectionId, NewConnection, NewOrganization, OrgId};
    let now = app.clock_now();
    let org = app
        .storage()
        .organizations()
        .create(
            tenant,
            &NewOrganization {
                id: OrgId::new_v7(),
                slug: "acme".into(),
                display_name: "Acme".into(),
                mfa_policy: None,
                settings: Default::default(),
                metadata: json!({}),
                created_at: now,
            },
        )
        .await
        .expect("org");
    app.storage()
        .connections()
        .create(
            tenant,
            &NewConnection {
                id: ConnectionId::new_v7(),
                org_id: Some(org.id),
                slug: "acme-sso".into(),
                display_name: "Acme SSO".into(),
                enabled: true,
                config: serde_json::from_value(json!({
                    "type": "oidc",
                    "issuer": "https://idp.acme-corp.com",
                    "client_id": "anvil",
                }))
                .expect("oidc config"),
                secret_enc: None,
                trust_email_verified: false,
                created_at: now,
            },
        )
        .await
        .expect("org connection");
    org.id
}

#[tokio::test]
async fn config_cannot_mark_domain_verified() {
    use anvil_core::model::OrgDomainStatus;
    use anvil_core::policy::domain_verification::{record_name, record_value};
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let org = seed_org_with_connection(&app, tenant).await;
    let mut doc = export(&app, &token, "default").await;
    doc["organizations"][0]["domains"] = json!([
        {"domain": "acme-corp.com", "connection": "acme-sso", "routing": true},
        {"domain": "acme-corp.net"},
    ]);

    // Any verification field is an unknown key: refused, nothing written.
    for (key, value) in [
        ("verified", json!(true)),
        ("status", json!("verified")),
        ("token", json!("anvil-domain-verification=attacker")),
        ("verified_at", json!("2026-01-01T00:00:00Z")),
        ("last_checked_at", json!("2026-01-01T00:00:00Z")),
    ] {
        let mut bad = doc.clone();
        bad["organizations"][0]["domains"][0][key] = value;
        let resp = post(
            &app,
            Some(&token),
            &format!("{API}/tenants/default/config/apply"),
            &bad,
        )
        .await;
        let body = assert_problem(&resp, 422);
        assert!(body.to_string().contains(key), "{key}: {body}");
    }
    let domains = app.storage().organizations();
    assert!(domains.list_domains(tenant, org).await.unwrap().is_empty());

    // Applied: pending claims with fresh tokens; routing held back until DNS verification.
    apply_ok(&app, &token, &doc, false).await;
    let claims = domains.list_domains(tenant, org).await.unwrap();
    assert_eq!(claims.len(), 2);
    for c in &claims {
        assert_eq!(c.status, OrgDomainStatus::Pending, "{}", c.domain);
        assert!(c.verified_at.is_none());
        assert!(!c.routing, "routing inactive until verified");
        assert!(!c.token.is_empty());
    }
    assert_ne!(claims[0].token, claims[1].token, "a fresh token per claim");
    let com = claims.iter().find(|c| c.domain == "acme-corp.com").unwrap();
    assert!(com.connection_id.is_some(), "the routing target is set");
    // The export carries neither the status nor the token.
    let exported = export(&app, &token, "default").await;
    let text = exported.to_string();
    assert!(
        !text.contains(&com.token) && !text.contains("pending"),
        "{text}"
    );
    // Re-applying plans nothing (the held-back routing is no pending change).
    let p = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/default/config/plan"),
        &doc,
    )
    .await;
    assert_eq!(body_json(&p)["empty"], true, "{}", p.text());

    // After verification through DNS, the next apply turns routing on.
    app.txt()
        .set(&record_name(&com.domain), &[&record_value(&com.token)]);
    let resp = call(
        &app,
        Method::POST,
        &format!(
            "{API}/tenants/default/organizations/acme/domains/{}/verify",
            com.id
        ),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let out = apply_ok(&app, &token, &doc, false).await;
    assert_eq!(out["plan"]["updates"][0]["key"], "acme/acme-corp.com");
    let claims = domains.list_domains(tenant, org).await.unwrap();
    let com = claims.iter().find(|c| c.domain == "acme-corp.com").unwrap();
    assert!(com.routing && com.status == OrgDomainStatus::Verified);
    let net = claims.iter().find(|c| c.domain == "acme-corp.net").unwrap();
    assert_eq!(
        net.status,
        OrgDomainStatus::Pending,
        "the other claim is untouched"
    );
}

#[tokio::test]
async fn config_absent_organizations_touches_nothing_even_with_prune() {
    use anvil_core::model::BrandingScope;
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    // An rc.3-shaped document: no organizations, tenant branding without a logo key.
    let mut rc3 = with_secrets(export(&app, &token, "default").await);
    rc3["branding"] = json!([{"tokens": {"radius_px": 4}}]);
    apply_ok(&app, &token, &rc3, false).await;
    assert!(
        export(&app, &token, "default")
            .await
            .get("organizations")
            .is_none()
    );

    let mut doc = export(&app, &token, "default").await;
    doc["branding"][0]["logo"] = json!({"data": b64(PNG)});
    doc["organizations"] = json!([{
        "slug": "globex",
        "display_name": "Globex",
        "roles": [{"name": "member", "permissions": ["docs:read"]}],
        "connections": [{
            "slug": "globex-sso",
            "display_name": "Globex SSO",
            "enabled": false,
            "config": {"type": "oidc", "issuer": "https://idp.globex-corp.com", "client_id": "anvil"},
            "secret": {"value": ORG_SECRET},
        }],
        "domains": [{"domain": "globex-corp.com"}],
        "branding": {"tokens": {"radius_px": 2}, "logo": {"data": b64(PNG)}},
    }]);
    apply_ok(&app, &token, &doc, false).await;
    let org = app
        .storage()
        .organizations()
        .get_by_slug(tenant, "globex")
        .await
        .unwrap()
        .expect("org")
        .id;

    // The rc.3 document with prune deletes nothing it did not delete before (nothing), keeps
    // the tenant logo and every organization object.
    let out = apply_ok(&app, &token, &rc3, true).await;
    assert_eq!(out["plan"]["deletes"], json!([]), "{}", out["plan"]["text"]);
    assert_eq!(out["plan"]["empty"], true, "{}", out["plan"]["text"]);
    let storage = app.storage();
    assert_eq!(
        storage
            .roles()
            .list_org_roles(tenant, org)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        storage
            .connections()
            .list_for_org(tenant, org)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        storage
            .organizations()
            .list_domains(tenant, org)
            .await
            .unwrap()
            .len(),
        1
    );
    let org_branding = storage
        .branding()
        .get(tenant, &BrandingScope::Org(org).scope_key())
        .await
        .unwrap()
        .expect("org branding kept");
    assert!(org_branding.logo_sha256.is_some());
    let tenant_branding = storage
        .branding()
        .get(tenant, &BrandingScope::Tenant.scope_key())
        .await
        .unwrap()
        .expect("tenant branding kept");
    assert!(
        tenant_branding.logo_sha256.is_some(),
        "absent logo keeps the logo"
    );
}

#[tokio::test]
async fn config_org_connection_secret_is_write_only() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let mut doc = export(&app, &token, "default").await;
    doc["organizations"] = json!([{
        "slug": "globex",
        "display_name": "Globex",
        "connections": [{
            "slug": "globex-sso",
            "display_name": "Globex SSO",
            "enabled": false,
            "config": {"type": "oidc", "issuer": "https://idp.globex-corp.com", "client_id": "anvil"},
            "secret": {"value": ORG_SECRET},
        }],
    }]);
    let out = apply_ok(&app, &token, &doc, false).await;
    assert!(!out.to_string().contains(ORG_SECRET));
    let exported = export(&app, &token, "default").await;
    assert_eq!(
        exported["organizations"][0]["connections"][0]["secret"],
        json!({"configured": true})
    );
    assert!(!exported.to_string().contains(ORG_SECRET));
    let audit = format!("{:?}", events(&app, tenant).await);
    assert!(!audit.contains(ORG_SECRET));
    // The same inline value is no change; another one changes without printing either.
    let p = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/default/config/plan"),
        &doc,
    )
    .await;
    assert_eq!(body_json(&p)["empty"], true, "{}", p.text());
    doc["organizations"][0]["connections"][0]["secret"] = json!({"value": "another-org-secret"});
    let p = body_json(
        &post(
            &app,
            Some(&token),
            &format!("{API}/tenants/default/config/plan"),
            &doc,
        )
        .await,
    );
    let text = p["text"].as_str().unwrap();
    assert!(text.contains("secret: (secret changed)"), "{text}");
    assert!(!p.to_string().contains("another-org-secret"));
    // A reference is resolved by the CLI only.
    doc["organizations"][0]["connections"][0]["secret"] = json!({"env": "HOME"});
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/default/config/apply"),
        &doc,
    )
    .await;
    let body = assert_problem(&resp, 422);
    assert_eq!(fields_of(&body), ["organizations[0].connections[0].secret"]);
}

#[tokio::test]
async fn config_logo_refusals_name_the_path() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let base = export(&app, &token, "default").await;
    let svg = b64(br#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>"#);
    let mut big = PNG.to_vec();
    big.resize(256 * 1024 + 1, 0);
    let unknown = "ab".repeat(32);
    let tenant_logo = |logo: Value| {
        let mut d = base.clone();
        d["branding"] = json!([{"tokens": {}, "logo": logo}]);
        d
    };
    let org_logo = |logo: Value| {
        let mut d = base.clone();
        d["organizations"] =
            json!([{"slug": "globex", "display_name": "Globex", "branding": {"logo": logo}}]);
        d
    };
    let cases = [
        (
            tenant_logo(json!({"data": svg})),
            "branding[0].logo",
            "PNG, JPEG or WebP",
        ),
        (
            org_logo(json!({"data": b64(b"just text")})),
            "organizations[0].branding.logo",
            "PNG, JPEG or WebP",
        ),
        (
            tenant_logo(json!({"data": b64(&big)})),
            "branding[0].logo",
            "256 KiB",
        ),
        (
            tenant_logo(json!({"data": "not base64!"})),
            "branding[0].logo",
            "base64",
        ),
        (
            tenant_logo(json!({"sha256": unknown, "content_type": "image/png"})),
            "branding[0].logo",
            "unknown logo hash",
        ),
        (
            org_logo(json!({"sha256": unknown, "content_type": "image/png"})),
            "organizations[0].branding.logo",
            "unknown logo hash",
        ),
        (
            tenant_logo(json!({"sha256": "ABC", "content_type": "image/svg+xml"})),
            "branding[0].logo.sha256",
            "SHA-256",
        ),
        (
            tenant_logo(json!({"file": "logo.png"})),
            "branding[0].logo",
            "anvilid CLI",
        ),
    ];
    let before = events(&app, tenant).await.len();
    for (doc, path, message) in cases {
        for op in ["plan", "apply"] {
            let resp = post(
                &app,
                Some(&token),
                &format!("{API}/tenants/default/config/{op}"),
                &doc,
            )
            .await;
            let body = assert_problem(&resp, 422);
            let issue = body["errors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["field"] == path)
                .unwrap_or_else(|| panic!("{path}: {body}"));
            assert!(
                issue["message"].as_str().unwrap().contains(message),
                "{path}: {body}"
            );
        }
    }
    // Nothing was written.
    assert_eq!(events(&app, tenant).await.len(), before);
    assert!(
        app.storage()
            .organizations()
            .get_by_slug(tenant, "globex")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn config_system_tenant_refuses_organizations() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let base = export(&app, &token, "system").await;
    assert!(base.get("organizations").is_none());
    for orgs in [json!([]), json!([{"slug": "ops", "display_name": "Ops"}])] {
        let mut doc = base.clone();
        doc["organizations"] = orgs;
        for op in ["plan", "apply"] {
            let resp = post(
                &app,
                Some(&token),
                &format!("{API}/tenants/system/config/{op}"),
                &doc,
            )
            .await;
            let body = assert_problem(&resp, 422);
            assert_eq!(fields_of(&body), ["organizations"], "{body}");
        }
    }
    assert!(
        app.storage()
            .organizations()
            .get_by_slug(system(&app), "ops")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn config_client_home_urls_use_the_shared_rule() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let mut doc = export(&app, &token, "default").await;
    doc["clients"] = json!([{
        "client_id": "portal",
        "name": "Portal",
        "client_type": "public",
        "application_type": "web",
        "auth_method": "none",
        "redirect_uris": ["https://portal.example.test/cb"],
        "grant_types": ["authorization_code"],
        "scopes": ["openid"],
        "client_uri": "javascript:alert(1)",
        "initiate_login_uri": "https://user:pw@portal.example.test/login#x",
    }]);
    let resp = post(
        &app,
        Some(&token),
        &format!("{API}/tenants/default/config/apply"),
        &doc,
    )
    .await;
    let body = assert_problem(&resp, 422);
    assert_eq!(
        fields_of(&body),
        ["clients[0].client_uri", "clients[0].initiate_login_uri"]
    );
    assert!(
        app.storage()
            .clients()
            .get(tenant, "portal")
            .await
            .unwrap()
            .is_none()
    );
}
