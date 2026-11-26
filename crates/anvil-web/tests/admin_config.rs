//! Declarative tenant configuration through the admin API (ADM-06, ADM-07): export, plan and
//! apply. Covers the exported shape (static clients only, secrets as `{configured}`), creating a
//! tenant's objects through the services (with their audit events), idempotent re-apply (empty
//! plan, no writes, no audit rows), prune-only deletes, inline secret comparison, generated
//! secrets shown once, and a document creating a new tenant.

mod admin_support;
mod support;
mod token_support;

use admin_support::{API, admin_token, assert_problem, call};
use anvil_core::model::{
    AuditAction, AuditEvent, AuditQuery, ClientId, ClientSource, ConsentMode, NewClient,
    SecretHash, TenantId, TokenFormat, WebhookEndpoint,
};
use anvil_core::service::webhook::signing_keys;
use anvil_jose::webhook::parse_webhook_secret;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::{ClockNow as _, default_tenant, register, web_input};

const WHSEC_A: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const WHSEC_B: &str = "whsec_dGhpcyBpcyBhbm90aGVyIHNlY3JldCBrZXk=";

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

fn count(events: &[AuditEvent], action: AuditAction) -> usize {
    events.iter().filter(|e| e.action == action).count()
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
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    body_json(&resp)
}

async fn apply(app: &TestApp, token: &str, slug: &str, doc: &Value, prune: bool) -> Value {
    let query = if prune { "?prune=true" } else { "" };
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/{slug}/config/apply{query}"),
        Some(token),
        Some(doc.clone()),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

async fn plan(app: &TestApp, token: &str, slug: &str, doc: &Value) -> Value {
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/{slug}/config/plan"),
        Some(token),
        Some(doc.clone()),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

fn keys(list: &Value) -> Vec<String> {
    list.as_array()
        .expect("array")
        .iter()
        .map(|c| {
            format!(
                "{} {}",
                c["kind"].as_str().unwrap(),
                c["key"].as_str().unwrap()
            )
        })
        .collect()
}

/// The default tenant's export plus a role, an attribute, a confidential client with branding,
/// a webhook (inline secret) and SMTP settings.
async fn configured_doc(app: &TestApp, token: &str) -> Value {
    let mut doc = export(app, token, "default").await;
    doc["roles"] = json!([
        {"name": "editor", "description": "Edits documents", "permissions": ["docs:write", "docs:read"]},
        {"name": "viewer", "permissions": ["docs:read"]},
    ]);
    doc["attributes"] = json!([
        {"name": "department", "schema": {"type": "string", "maxLength": 64}, "user_editable": true},
    ]);
    doc["clients"] = json!([{
        "client_id": "billing-web",
        "name": "Billing",
        "client_type": "confidential",
        "application_type": "web",
        "auth_method": "client_secret_basic",
        "secret": {"configured": true},
        "redirect_uris": ["https://billing.example.test/cb"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
    }]);
    doc["branding"] = json!([
        {"client_id": "billing-web", "tokens": {"radius_px": 4}},
    ]);
    doc["webhooks"] = json!([{
        "name": "crm",
        "url": "https://hooks.example/in",
        "events": ["user.created", "user.deleted"],
        "secret": {"value": WHSEC_A},
    }]);
    doc["smtp"] = json!({
        "host": "smtp.example.test",
        "port": 587,
        "username": "mailer",
        "password": {"value": "smtp-pass-1"},
        "from": "id@example.test",
        "tls": "starttls",
    });
    doc
}

async fn seed_runtime_client(
    app: &TestApp,
    tenant: TenantId,
    client_id: &str,
    source: ClientSource,
) {
    let now = app.clock_now();
    let new = NewClient {
        id: ClientId::new_v7(),
        client_id: client_id.into(),
        name: "Runtime".into(),
        client_type: anvil_core::model::ClientType::Public,
        application_type: anvil_core::model::ApplicationType::Web,
        auth_method: anvil_core::model::ClientAuthMethod::None,
        secret_hash: None,
        jwks: None,
        redirect_uris: vec!["https://rp.example.test/cb".into()],
        grant_types: vec![anvil_core::model::GrantType::AuthorizationCode],
        scopes: vec!["openid".into()],
        require_pkce: true,
        created_at: now,
        token_format: TokenFormat::Jwt,
        consent_mode: ConsentMode::Required,
        id_token_signed_response_alg: None,
        can_introspect: false,
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        allowed_resources: vec![],
        mfa_policy: None,
        metadata_expires_at: (source == ClientSource::Cimd).then(|| now + time::Duration::hours(1)),
        registration_access_token_hash: (source == ClientSource::Dynamic)
            .then_some(SecretHash([3; 32])),
        registration_source: source,
    };
    match source {
        ClientSource::Cimd => {
            app.storage()
                .clients()
                .upsert_cimd(tenant, &new, now + time::Duration::hours(1), now)
                .await
                .expect("cimd client");
        }
        _ => {
            app.storage()
                .clients()
                .create(tenant, &new)
                .await
                .expect("dynamic client");
        }
    }
}

#[tokio::test]
async fn export_has_static_clients_only_with_secrets_as_configured() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(
        &app,
        tenant,
        web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    seed_runtime_client(&app, tenant, "dyn-client-1", ClientSource::Dynamic).await;
    seed_runtime_client(
        &app,
        tenant,
        "https://mcp.example.test/client.json",
        ClientSource::Cimd,
    )
    .await;
    let token = admin_token(&app, "admin:read").await;
    let doc = export(&app, &token, "default").await;
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["kind"], "TenantConfig");
    assert_eq!(doc["tenant"]["slug"], "default");
    let clients = doc["clients"].as_array().unwrap();
    assert_eq!(clients.len(), 1, "{doc}");
    assert_eq!(clients[0]["client_id"], rp.id());
    assert_eq!(clients[0]["secret"], json!({"configured": true}));
    let text = doc.to_string();
    assert!(!text.contains(&tenant.to_string()), "database id in export");
    assert!(
        !text.contains(&rp.client.id.to_string()),
        "database id in export"
    );
    assert!(!text.contains(rp.secret.as_deref().unwrap()));

    // Unknown tenants are a 404.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/nope/config"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
}

#[tokio::test]
async fn apply_writes_through_the_services_and_reapply_is_a_no_op() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let doc = configured_doc(&app, &token).await;

    // Plan first: nothing is written.
    let before = events(&app, tenant).await.len();
    let p = plan(&app, &token, "default", &doc).await;
    assert_eq!(
        keys(&p["creates"]),
        [
            "client billing-web",
            "branding billing-web",
            "role editor",
            "role viewer",
            "attribute department",
            "smtp smtp",
            "webhook crm",
        ]
    );
    assert!(p["text"].as_str().unwrap().contains("+ role editor"));
    assert_eq!(events(&app, tenant).await.len(), before);

    let out = apply(&app, &token, "default", &doc, false).await;
    assert_eq!(out["applied"], true);
    // The client secret was generated and is shown once; the webhook secret was provided.
    let generated = out["generated_secrets"].as_array().unwrap();
    assert_eq!(generated.len(), 1, "{out}");
    assert_eq!(generated[0]["kind"], "client");
    assert_eq!(generated[0]["key"], "billing-web");
    assert!(generated[0]["value"].as_str().unwrap().len() >= 32);

    let ev = events(&app, tenant).await;
    for (action, n) in [
        (AuditAction::RoleCreated, 2),
        (AuditAction::AttributeDefined, 1),
        (AuditAction::ClientCreated, 1),
        (AuditAction::BrandingUpdated, 1),
        (AuditAction::SmtpSettingsUpdated, 1),
        (AuditAction::WebhookEndpointCreated, 1),
        (AuditAction::TenantConfigApplied, 1),
    ] {
        assert_eq!(count(&ev, action), n, "{action:?}");
    }
    let applied = ev
        .iter()
        .find(|e| e.action == AuditAction::TenantConfigApplied)
        .unwrap();
    let details = serde_json::to_value(applied.details.as_map()).unwrap();
    assert_eq!(details, json!({"creates": 7, "updates": 0, "deletes": 0}));

    // Re-applying the same document (inline secrets included) changes nothing.
    let after_first = ev.len();
    let p = plan(&app, &token, "default", &doc).await;
    assert_eq!(p["empty"], true, "{p}");
    let out = apply(&app, &token, "default", &doc, false).await;
    assert_eq!(out["applied"], false);
    assert_eq!(events(&app, tenant).await.len(), after_first);

    // Re-applying the export is a no-op too, and the export carries what was applied.
    let exported = export(&app, &token, "default").await;
    assert_eq!(
        exported["roles"][0]["permissions"],
        json!(["docs:read", "docs:write"])
    );
    assert_eq!(
        exported["webhooks"][0]["secret"],
        json!({"configured": true})
    );
    assert_eq!(exported["smtp"]["password"], json!({"configured": true}));
    let out = apply(&app, &token, "default", &exported, true).await;
    assert_eq!(out["applied"], false, "{out}");
    assert_eq!(events(&app, tenant).await.len(), after_first);
}

#[tokio::test]
async fn deletes_are_prune_only() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let doc = configured_doc(&app, &token).await;
    apply(&app, &token, "default", &doc, false).await;

    let mut fewer = doc.clone();
    fewer["roles"] = json!([doc["roles"][0].clone()]);
    let p = plan(&app, &token, "default", &fewer).await;
    assert_eq!(keys(&p["deletes"]), ["role viewer"]);
    assert!(
        p["text"]
            .as_str()
            .unwrap()
            .contains("- role viewer (prune only)")
    );

    let out = apply(&app, &token, "default", &fewer, false).await;
    assert_eq!(out["applied"], false);
    assert!(
        app.storage()
            .roles()
            .get_by_name(tenant, "viewer")
            .await
            .unwrap()
            .is_some()
    );

    let out = apply(&app, &token, "default", &fewer, true).await;
    assert_eq!(
        (out["applied"].clone(), out["pruned"].clone()),
        (json!(true), json!(true))
    );
    assert!(
        app.storage()
            .roles()
            .get_by_name(tenant, "viewer")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        count(&events(&app, tenant).await, AuditAction::RoleDeleted),
        1
    );
}

async fn endpoint(app: &TestApp, tenant: TenantId, name: &str) -> WebhookEndpoint {
    app.storage()
        .webhooks()
        .list_endpoints(tenant)
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.name == name)
        .expect("endpoint")
}

#[tokio::test]
async fn inline_secrets_are_compared_not_rewritten() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let mut doc = configured_doc(&app, &token).await;
    doc["clients"][0]["secret"] = json!({"value": "billing-client-secret-0123456789-abcdef"});
    apply(&app, &token, "default", &doc, false).await;
    let rotations = |ev: &[AuditEvent]| {
        (
            count(ev, AuditAction::WebhookSecretRotated),
            count(ev, AuditAction::ClientSecretRotated),
        )
    };
    assert_eq!(rotations(&events(&app, tenant).await), (0, 0));

    // Same values: no change.
    assert_eq!(plan(&app, &token, "default", &doc).await["empty"], true);

    // Different values: one secret update each, without the values in the plan.
    doc["webhooks"][0]["secret"] = json!({"value": WHSEC_B});
    doc["clients"][0]["secret"] = json!({"value": "another-billing-secret-0123456789-xyz"});
    doc["smtp"]["password"] = json!({"value": "smtp-pass-2"});
    let p = plan(&app, &token, "default", &doc).await;
    assert_eq!(
        keys(&p["updates"]),
        ["client billing-web", "smtp smtp", "webhook crm"]
    );
    for u in p["updates"].as_array().unwrap() {
        assert_eq!(u["fields"].as_array().unwrap().len(), 1, "{u}");
        assert_eq!(u["fields"][0]["secret"], true);
        assert_eq!(u["fields"][0]["before"], Value::Null);
        assert_eq!(u["fields"][0]["after"], Value::Null);
    }
    let text = p.to_string();
    for value in [WHSEC_B, "another-billing-secret", "smtp-pass-2"] {
        assert!(!text.contains(value), "{value} in plan");
    }
    let out = apply(&app, &token, "default", &doc, false).await;
    assert_eq!(out["generated_secrets"], json!([]));
    assert_eq!(rotations(&events(&app, tenant).await), (1, 1));
    // The new webhook secret signs; the previous one stays for the rotation window.
    let w = endpoint(&app, tenant, "crm").await;
    let keys = signing_keys(app.kek(), &w, app.clock_now()).unwrap();
    assert_eq!(*keys[0], *parse_webhook_secret(WHSEC_B).unwrap());
    assert_eq!(*keys[1], *parse_webhook_secret(WHSEC_A).unwrap());
    assert_eq!(plan(&app, &token, "default", &doc).await["empty"], true);
}

#[tokio::test]
async fn field_changes_update_only_what_changed() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:write").await;
    let mut doc = configured_doc(&app, &token).await;
    apply(&app, &token, "default", &doc, false).await;

    doc["clients"][0]["redirect_uris"] = json!(["https://billing.example.test/callback"]);
    doc["webhooks"][0]["enabled"] = json!(false);
    doc["tenant"]["display_name"] = json!("Default Inc");
    let p = plan(&app, &token, "default", &doc).await;
    assert_eq!(
        keys(&p["updates"]),
        ["tenant default", "client billing-web", "webhook crm"]
    );
    apply(&app, &token, "default", &doc, false).await;
    let client = app
        .storage()
        .clients()
        .get(tenant, "billing-web")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client.redirect_uris,
        ["https://billing.example.test/callback"]
    );
    assert!(!endpoint(&app, tenant, "crm").await.enabled);
    let ev = events(&app, tenant).await;
    let updated = ev
        .iter()
        .find(|e| e.action == AuditAction::ClientUpdated)
        .expect("client_updated");
    assert_eq!(
        serde_json::to_value(updated.details.as_map()).unwrap()["fields"],
        json!(["redirect_uris"])
    );
    assert_eq!(plan(&app, &token, "default", &doc).await["empty"], true);
}

#[tokio::test]
async fn a_document_creates_a_missing_tenant() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let mut doc = configured_doc(&app, &token).await;
    doc["tenant"]["slug"] = json!("acme");
    doc["tenant"]["display_name"] = json!("Acme");
    doc["tenant"]["host"] = Value::Null;
    let p = plan(&app, &token, "acme", &doc).await;
    assert_eq!(keys(&p["creates"])[0], "tenant acme");
    let out = apply(&app, &token, "acme", &doc, false).await;
    assert_eq!(out["applied"], true);
    let acme = app
        .storage()
        .tenants()
        .get_by_slug("acme")
        .await
        .unwrap()
        .expect("tenant created");
    assert_eq!(acme.display_name, "Acme");
    assert!(
        app.storage()
            .clients()
            .get(acme.id, "billing-web")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(plan(&app, &token, "acme", &doc).await["empty"], true);

    // The slug in the URL must match the document.
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/config/plan"),
        Some(&token),
        Some(doc),
    )
    .await;
    let body = assert_problem(&resp, 422);
    assert_eq!(body["errors"][0]["field"], "tenant.slug");
}

/// The published JSON Schema of the document.
fn published_schema() -> Value {
    serde_json::from_str(include_str!("../../../docs/schemas/tenant-config-v1.json"))
        .expect("schema is JSON")
}

fn schema_validator() -> jsonschema::Validator {
    let schema = published_schema();
    jsonschema::draft202012::meta::validate(&schema).expect("schema is valid draft 2020-12");
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .expect("schema compiles")
}

fn errors(v: &jsonschema::Validator, doc: &Value) -> Vec<String> {
    v.iter_errors(doc)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect()
}

#[tokio::test]
async fn json_schema_matches_the_document_types() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let mut doc = configured_doc(&app, &token).await;
    doc["connections"] = json!([
        {
            "slug": "google",
            "display_name": "Google",
            "config": {"type": "social", "provider": "google", "client_id": "abc.apps.example.test"},
            "secret": {"value": "google-secret"},
        },
        {
            "slug": "corp",
            "display_name": "Corp IdP",
            "config": {"type": "oidc", "issuer": "https://idp.example.test", "client_id": "anvil"},
            "secret": {"value": "corp-secret"},
            "trust_email_verified": true,
        },
    ]);
    doc["branding"]
        .as_array_mut()
        .unwrap()
        .push(json!({"tokens": {"colors": {"primary": "#0b5fff"}}, "custom_css": ".anvil-card { border-radius: 2px; }"}));
    let v = schema_validator();
    // The input document (inline secrets) and the export both validate.
    assert_eq!(errors(&v, &doc), Vec::<String>::new());
    apply(&app, &token, "default", &doc, false).await;
    let exported = export(&app, &token, "default").await;
    assert_eq!(errors(&v, &exported), Vec::<String>::new());
    let system = export(&app, &token, "system").await;
    assert_eq!(errors(&v, &system), Vec::<String>::new());

    // Every settings field the server writes is described (settings ignore unknown keys, so
    // the schema lists them explicitly).
    let schema = published_schema();
    let described = &schema["$defs"]["settings"]["properties"];
    for (key, value) in exported["tenant"]["settings"].as_object().unwrap() {
        assert!(
            described.get(key).is_some(),
            "settings.{key} missing in the schema"
        );
        if let (Some(inner), Some(props)) = (value.as_object(), described[key].get("properties")) {
            for k in inner.keys() {
                assert!(
                    props.get(k).is_some(),
                    "settings.{key}.{k} missing in the schema"
                );
            }
        }
    }

    // CLI references validate; unknown keys, other versions and malformed secrets do not.
    let mut with_ref = exported.clone();
    with_ref["smtp"]["password"] = json!({"env": "SMTP_PASSWORD"});
    assert_eq!(errors(&v, &with_ref), Vec::<String>::new());
    for (pointer, bad) in [
        ("/bogus", json!(true)),
        ("/version", json!(2)),
        ("/kind", json!("Other")),
        ("/smtp/password", json!({"configured": true, "value": "x"})),
        ("/clients/0/extra", json!(1)),
        ("/webhooks/0/events", json!(["test"])),
    ] {
        let mut d = exported.clone();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        let target = if parent.is_empty() {
            &mut d
        } else {
            d.pointer_mut(parent).unwrap()
        };
        target[key] = bad;
        assert!(!v.is_valid(&d), "{pointer} accepted");
        // The server refuses the same documents.
        if pointer != "/smtp/password" {
            let resp = call(
                &app,
                Method::POST,
                &format!("{API}/tenants/default/config/plan"),
                Some(&token),
                Some(d),
            )
            .await;
            assert_problem(&resp, 422);
        }
    }
}

#[tokio::test]
async fn schema_encodes_registration_bounds() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let v = schema_validator();
    let mut doc = configured_doc(&app, &token).await;
    // A configured tenant with registration enabled still validates.
    doc["tenant"]["settings"]["dcr"] = json!({
        "policy": "allow_listed",
        "allowed_redirect_hosts": ["app.example.test"],
        "allowed_scopes": ["openid"],
        "max_clients": 1_000_000,
    });
    doc["tenant"]["settings"]["cimd"] = json!({
        "policy": "allow_listed",
        "allowed_hosts": ["mcp.example.test"],
        "min_cache_secs": 60,
        "max_cache_secs": 604_800,
    });
    assert_eq!(errors(&v, &doc), Vec::<String>::new());
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/config/apply"),
        Some(&token),
        Some(doc.clone()),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let exported = export(&app, &token, "default").await;
    assert_eq!(errors(&v, &exported), Vec::<String>::new());

    let hosts: Vec<String> = (0..101).map(|i| format!("h{i}.example.test")).collect();
    let cases: Vec<(&str, Value)> = vec![
        ("/tenant/settings/dcr/allowed_redirect_hosts", json!(hosts)),
        (
            "/tenant/settings/dcr/allowed_redirect_hosts",
            json!(["a.example.test", "a.example.test"]),
        ),
        ("/tenant/settings/cimd/allowed_hosts", json!(hosts)),
        (
            "/tenant/settings/cimd/allowed_hosts",
            json!(["mcp.example.test", "mcp.example.test"]),
        ),
        ("/tenant/settings/dcr/max_clients", json!(1_000_001)),
        ("/tenant/settings/cimd/min_cache_secs", json!(59)),
        ("/tenant/settings/cimd/max_cache_secs", json!(604_801)),
    ];
    for (pointer, value) in cases {
        let mut d = doc.clone();
        *d.pointer_mut(pointer).expect(pointer) = value;
        assert!(!v.is_valid(&d), "{pointer} accepted");
        // The server refuses the same document.
        let resp = call(
            &app,
            Method::POST,
            &format!("{API}/tenants/default/config/plan"),
            Some(&token),
            Some(d),
        )
        .await;
        assert_problem(&resp, 422);
    }
}
