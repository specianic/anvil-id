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
