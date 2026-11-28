//! Security tests for the 0.4 admin routes (attributes, webhooks with the delivery log, initial
//! access tokens, DCR/CIMD tenant settings): scope enforcement on every route, tenant isolation,
//! write-only webhook secrets, initial access tokens shown once and stored hashed, and the system
//! tenant's registration policies forced to `disabled`.

mod admin_support;
mod support;
mod token_support;
mod webhook_support;

use admin_support::{API, admin_token, assert_field_error, assert_problem, call};
use anvil_core::model::{CimdPolicy, DcrPolicy, TenantUpdate};
use anvil_jose::encoding::secret_hash;
use axum::http::Method;
use secrecy::SecretString;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::{ClockNow as _, acme, seed_user};
use webhook_support::{dev_app, dev_worker, hook_url, sink, verified_by};

/// An installed production-mode app without rate limiting (the tables send many requests).
async fn no_rate_limit() -> TestApp {
    TestApp::with(|c| c.rate_limits.enabled = false).await
}

const UNKNOWN: &str = "0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a99";

/// One route of the table: method, path, body, the scope that grants it, and a scope of the
/// same resource that must not (read scope for writes; `None` for reads).
struct Route {
    method: Method,
    path: String,
    body: Option<Value>,
    grant: &'static str,
    read_only: Option<&'static str>,
    other_resource: &'static str,
}

fn routes(user: &str) -> Vec<Route> {
    let t = format!("{API}/tenants/default");
    let r = |method: Method,
             path: String,
             body: Option<Value>,
             grant: &'static str,
             read_only: Option<&'static str>,
             other_resource: &'static str| Route {
        method,
        path,
        body,
        grant,
        read_only,
        other_resource,
    };
    let def = json!({"schema": {"type": "string"}});
    let hook =
        json!({"name": "h", "url": "https://hooks.example.com/x", "events": ["user.created"]});
    vec![
        // Attribute definitions: settings scope.
        r(
            Method::GET,
            format!("{t}/attributes"),
            None,
            "admin:settings:read",
            None,
            "admin:users:write",
        ),
        r(
            Method::GET,
            format!("{t}/attributes/dept"),
            None,
            "admin:settings:read",
            None,
            "admin:users:write",
        ),
        r(
            Method::PUT,
            format!("{t}/attributes/dept"),
            Some(def),
            "admin:settings:write",
            Some("admin:settings:read"),
            "admin:users:write",
        ),
        r(
            Method::DELETE,
            format!("{t}/attributes/dept"),
            None,
            "admin:settings:write",
            Some("admin:settings:read"),
            "admin:users:write",
        ),
        // User values: users scope.
        r(
            Method::GET,
            format!("{t}/users/{user}/attributes"),
            None,
            "admin:users:read",
            None,
            "admin:settings:write",
        ),
        r(
            Method::PUT,
            format!("{t}/users/{user}/attributes"),
            Some(json!({"values": {}})),
            "admin:users:write",
            Some("admin:users:read"),
            "admin:settings:write",
        ),
        // Webhooks: settings scope.
        r(
            Method::GET,
            format!("{t}/webhooks"),
            None,
            "admin:settings:read",
            None,
            "admin:clients:write",
        ),
        r(
            Method::POST,
            format!("{t}/webhooks"),
            Some(hook),
            "admin:settings:write",
            Some("admin:settings:read"),
            "admin:clients:write",
        ),
        r(
            Method::GET,
            format!("{t}/webhooks/{UNKNOWN}"),
            None,
            "admin:settings:read",
            None,
            "admin:clients:write",
        ),
        r(
            Method::PATCH,
            format!("{t}/webhooks/{UNKNOWN}"),
            Some(json!({"enabled": false})),
            "admin:settings:write",
            Some("admin:settings:read"),
            "admin:clients:write",
        ),
        r(
            Method::DELETE,
            format!("{t}/webhooks/{UNKNOWN}"),
            None,
            "admin:settings:write",
            Some("admin:settings:read"),
            "admin:clients:write",
        ),
        r(
            Method::POST,
            format!("{t}/webhooks/{UNKNOWN}/secret"),
            None,
            "admin:settings:write",
            Some("admin:settings:read"),
            "admin:clients:write",
        ),
        r(
            Method::POST,
            format!("{t}/webhooks/{UNKNOWN}/test"),
            None,
            "admin:settings:write",
            Some("admin:settings:read"),
            "admin:clients:write",
        ),
        r(
            Method::GET,
            format!("{t}/webhooks/{UNKNOWN}/deliveries"),
            None,
            "admin:settings:read",
            None,
            "admin:clients:write",
        ),
        r(
            Method::POST,
            format!("{t}/webhooks/deliveries/{UNKNOWN}/redeliver"),
            None,
            "admin:settings:write",
            Some("admin:settings:read"),
            "admin:clients:write",
        ),
        // Initial access tokens: clients scope.
        r(
            Method::GET,
            format!("{t}/initial-access-tokens"),
            None,
            "admin:clients:read",
            None,
            "admin:settings:write",
        ),
        r(
            Method::POST,
            format!("{t}/initial-access-tokens"),
            Some(json!({})),
            "admin:clients:write",
            Some("admin:clients:read"),
            "admin:settings:write",
        ),
        r(
            Method::DELETE,
            format!("{t}/initial-access-tokens/{UNKNOWN}"),
            None,
            "admin:clients:write",
            Some("admin:clients:read"),
            "admin:settings:write",
        ),
        // DCR/CIMD settings: the tenants scope (PATCH /tenants/{slug}).
        r(
            Method::PATCH,
            t.clone(),
            Some(json!({"settings": {"dcr": {"max_clients": 7}}})),
            "admin:tenants:write",
            Some("admin:tenants:read"),
            "admin:clients:write",
        ),
    ]
}

#[tokio::test]
async fn v04_admin_routes_require_scopes() {
    let app = no_rate_limit().await;
    let tenant = app.default.as_ref().unwrap().tenant.id;
    let user = seed_user(&app, tenant, "ada@example.test")
        .await
        .id
        .to_string();
    let table = routes(&user);
    assert_eq!(
        table.len(),
        19,
        "every 0.4 route of this plan plus the settings PATCH"
    );

    let mut tokens = std::collections::HashMap::new();
    for scope in [
        "admin:settings:read",
        "admin:settings:write",
        "admin:users:read",
        "admin:users:write",
        "admin:clients:read",
        "admin:clients:write",
        "admin:tenants:read",
        "admin:tenants:write",
        "admin:sessions:write",
    ] {
        tokens.insert(scope, admin_token(&app, scope).await);
    }

    for r in &table {
        let what = format!("{} {}", r.method, r.path);
        // No token, a malformed token.
        let resp = call(&app, r.method.clone(), &r.path, None, r.body.clone()).await;
        assert_problem(&resp, 401);
        assert!(resp.header("www-authenticate").is_some(), "{what}");
        let resp = call(
            &app,
            r.method.clone(),
            &r.path,
            Some("garbage"),
            r.body.clone(),
        )
        .await;
        assert_problem(&resp, 401);
        // A scope of an unrelated resource.
        let resp = call(
            &app,
            r.method.clone(),
            &r.path,
            Some(&tokens["admin:sessions:write"]),
            r.body.clone(),
        )
        .await;
        assert_problem(&resp, 403);
        // A write scope of another resource.
        let resp = call(
            &app,
            r.method.clone(),
            &r.path,
            Some(&tokens[r.other_resource]),
            r.body.clone(),
        )
        .await;
        assert_eq!(
            resp.status,
            403,
            "{what} with {}: {}",
            r.other_resource,
            resp.text()
        );
        // Read cannot write.
        if let Some(read) = r.read_only {
            let resp = call(
                &app,
                r.method.clone(),
                &r.path,
                Some(&tokens[read]),
                r.body.clone(),
            )
            .await;
            assert_eq!(resp.status, 403, "{what} with {read}: {}", resp.text());
        }
        // The granting scope passes authorization (the outcome itself is the handler's).
        let resp = call(
            &app,
            r.method.clone(),
            &r.path,
            Some(&tokens[r.grant]),
            r.body.clone(),
        )
        .await;
        assert!(
            ![401, 403].contains(&resp.status.as_u16()),
            "{what} with {}: {} {}",
            r.grant,
            resp.status,
            resp.text()
        );
    }

    // admin:write / admin:read cover every route; admin:read never writes.
    let write = admin_token(&app, "admin:write").await;
    let read = admin_token(&app, "admin:read").await;
    for r in &table {
        let what = format!("{} {}", r.method, r.path);
        let resp = call(
            &app,
            r.method.clone(),
            &r.path,
            Some(&write),
            r.body.clone(),
        )
        .await;
        assert!(
            ![401, 403].contains(&resp.status.as_u16()),
            "{what}: {}",
            resp.text()
        );
        let resp = call(&app, r.method.clone(), &r.path, Some(&read), r.body.clone()).await;
        if r.read_only.is_some() {
            assert_eq!(resp.status, 403, "{what} with admin:read");
        } else {
            assert!(
                ![401, 403].contains(&resp.status.as_u16()),
                "{what}: {}",
                resp.text()
            );
        }
    }
}

#[tokio::test]
async fn v04_admin_routes_isolate_tenants() {
    let app = &no_rate_limit().await;
    let token = admin_token(app, "admin:write").await;
    let other = acme(app).await;
    let user = seed_user(app, other.id, "bob@acme.test").await;
    let acme_t = format!("{API}/tenants/acme");
    let def_t = format!("{API}/tenants/default");
    let hook_target = "https://hooks.example.com/acme";

    // acme objects: a definition with a user value, an endpoint with a delivery, a token.
    let resp = call(
        app,
        Method::PUT,
        &format!("{acme_t}/attributes/dept"),
        Some(&token),
        Some(json!({"schema": {"type": "string"}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(
        app,
        Method::PUT,
        &format!("{acme_t}/users/{}/attributes", user.id),
        Some(&token),
        Some(json!({"values": {"dept": "eng"}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(
        app,
        Method::POST,
        &format!("{acme_t}/webhooks"),
        Some(&token),
        Some(json!({"name": "crm", "url": hook_target, "events": ["user.created"]})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let hook = body_json(&resp)["endpoint"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let resp = call(
        app,
        Method::POST,
        &format!("{acme_t}/webhooks/{hook}/test"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 202, "{}", resp.text());
    let delivery = body_json(&resp)["id"].as_str().unwrap().to_owned();
    let resp = call(
        app,
        Method::POST,
        &format!("{acme_t}/initial-access-tokens"),
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let iat = body_json(&resp)["token"]["id"].as_str().unwrap().to_owned();

    // Through the default tenant every one of them is a 404, and nothing changes.
    let cases: Vec<(Method, String, Option<Value>)> = vec![
        (Method::GET, format!("{def_t}/attributes/dept"), None),
        (Method::DELETE, format!("{def_t}/attributes/dept"), None),
        (
            Method::GET,
            format!("{def_t}/users/{}/attributes", user.id),
            None,
        ),
        (
            Method::PUT,
            format!("{def_t}/users/{}/attributes", user.id),
            Some(json!({"values": {}})),
        ),
        (Method::GET, format!("{def_t}/webhooks/{hook}"), None),
        (
            Method::PATCH,
            format!("{def_t}/webhooks/{hook}"),
            Some(json!({"url": "https://evil.example/x"})),
        ),
        (Method::DELETE, format!("{def_t}/webhooks/{hook}"), None),
        (
            Method::POST,
            format!("{def_t}/webhooks/{hook}/secret"),
            None,
        ),
        (Method::POST, format!("{def_t}/webhooks/{hook}/test"), None),
        (
            Method::GET,
            format!("{def_t}/webhooks/{hook}/deliveries"),
            None,
        ),
        (
            Method::POST,
            format!("{def_t}/webhooks/deliveries/{delivery}/redeliver"),
            None,
        ),
        (
            Method::DELETE,
            format!("{def_t}/initial-access-tokens/{iat}"),
            None,
        ),
    ];
    for (method, path, body) in cases {
        let resp = call(app, method.clone(), &path, Some(&token), body).await;
        assert_eq!(resp.status, 404, "{method} {path}: {}", resp.text());
    }
    for list in ["attributes", "webhooks", "initial-access-tokens"] {
        let resp = call(
            app,
            Method::GET,
            &format!("{def_t}/{list}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(body_json(&resp)["items"], json!([]), "{list}");
    }

    // Still intact in acme.
    let resp = call(
        app,
        Method::GET,
        &format!("{acme_t}/webhooks/{hook}"),
        Some(&token),
        None,
    )
    .await;
    let endpoint = body_json(&resp);
    assert_eq!(endpoint["url"], hook_target);
    assert!(
        endpoint["previous_secret_expires_at"].is_null(),
        "not rotated"
    );
    let resp = call(
        app,
        Method::GET,
        &format!("{acme_t}/users/{}/attributes", user.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(body_json(&resp)["values"], json!({"dept": "eng"}));
    let resp = call(
        app,
        Method::GET,
        &format!("{acme_t}/initial-access-tokens"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(body_json(&resp)["items"][0]["usable"], true);
    let resp = call(
        app,
        Method::GET,
        &format!("{acme_t}/webhooks/{hook}/deliveries"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(
        body_json(&resp)["items"].as_array().unwrap().len(),
        1,
        "no redelivery"
    );
}

#[tokio::test]
async fn webhook_secret_write_only_in_api() {
    let app = dev_app().await;
    let token = admin_token(app, "admin:settings:write").await;
    let server = sink(204).await;
    let base = format!("{API}/tenants/default/webhooks");
    let resp = call(
        app,
        Method::POST,
        &base,
        Some(&token),
        Some(json!({"name": "crm", "url": hook_url(&server), "events": ["user.created"]})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let created = body_json(&resp);
    let id = created["endpoint"]["id"].as_str().unwrap().to_owned();
    let secret = created["secret"].as_str().unwrap().to_owned();
    let rotated = body_json(
        &call(
            app,
            Method::POST,
            &format!("{base}/{id}/secret"),
            Some(&token),
            None,
        )
        .await,
    );
    let new_secret = rotated["secret"].as_str().unwrap().to_owned();
    assert_ne!(secret, new_secret);
    let key_part = |s: &str| s.trim_start_matches("whsec_").to_owned();

    // No other response carries either secret (or its key part).
    let mut texts = Vec::new();
    for (method, path, body) in [
        (Method::GET, base.clone(), None),
        (Method::GET, format!("{base}/{id}"), None),
        (
            Method::PATCH,
            format!("{base}/{id}"),
            Some(json!({"events": ["user.deleted"]})),
        ),
        (Method::POST, format!("{base}/{id}/test"), None),
        (Method::GET, format!("{base}/{id}/deliveries"), None),
    ] {
        let resp = call(app, method, &path, Some(&token), body).await;
        assert!(resp.status.is_success(), "{path}: {}", resp.text());
        texts.push(resp.text());
    }
    for t in &texts {
        for s in [&secret, &new_secret] {
            assert!(!t.contains(s.as_str()) && !t.contains(&key_part(s)), "{t}");
        }
        assert!(!t.contains("\"secret\""), "{t}");
    }

    // The OpenAPI schema of the endpoint view has no secret property.
    let spec = body_json(&call(app, Method::GET, "/api/admin/v1/openapi.json", None, None).await);
    let props = spec["components"]["schemas"]["WebhookEndpointDto"]["properties"]
        .as_object()
        .expect("WebhookEndpointDto schema");
    assert!(props.contains_key("secret_configured"));
    assert!(
        !props
            .keys()
            .any(|k| k == "secret" || k.contains("secret_enc"))
    );

    // Stored sealed: the row never holds the plaintext.
    let tenant = app.default.as_ref().unwrap().tenant.id;
    let row = app
        .storage()
        .webhooks()
        .get_endpoint(
            tenant,
            anvil_core::model::WebhookEndpointId(id.parse().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
    for s in [&secret, &new_secret] {
        let plain = s.as_bytes();
        assert!(!row.secret_enc.windows(plain.len()).any(|w| w == plain));
        let key = key_part(s);
        assert!(
            !row.secret_enc
                .windows(key.len())
                .any(|w| w == key.as_bytes())
        );
    }

    // The secret shown once is the one that signs (both during the rotation window).
    dev_worker(app).run_once().await.expect("worker");
    let received = webhook_support::received(&server).await;
    assert_eq!(received.len(), 1);
    assert!(verified_by(
        &received[0],
        &SecretString::from(new_secret.clone())
    ));
    assert!(verified_by(
        &received[0],
        &SecretString::from(secret.clone())
    ));
}

#[tokio::test]
async fn initial_access_token_shown_once() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:clients:write").await;
    let path = format!("{API}/tenants/default/initial-access-tokens");
    let resp = call(
        &app,
        Method::POST,
        &path,
        Some(&token),
        Some(json!({"uses": 1})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let value = body_json(&resp)["value"].as_str().unwrap().to_owned();

    let resp = call(&app, Method::GET, &path, Some(&token), None).await;
    assert_eq!(resp.status, 200);
    assert!(!resp.text().contains(&value), "{}", resp.text());
    assert!(body_json(&resp)["items"][0].get("value").is_none());

    // The OpenAPI list item has no value property.
    let spec = body_json(&call(&app, Method::GET, "/api/admin/v1/openapi.json", None, None).await);
    let props = spec["components"]["schemas"]["InitialAccessTokenDto"]["properties"]
        .as_object()
        .expect("InitialAccessTokenDto schema");
    assert!(!props.contains_key("value") && !props.contains_key("token_hash"));

    // Stored by hash only.
    let tenant = app.default.as_ref().unwrap().tenant.id;
    let stored = app
        .storage()
        .registration()
        .list_iats(tenant)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    let hash = stored[0].token_hash.0;
    assert!(!value.as_bytes().windows(hash.len()).any(|w| w == hash));
    assert_eq!(hash, secret_hash(&value), "SHA-256 of the value");
}

#[tokio::test]
async fn system_tenant_registration_policies_forced_disabled() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let system = format!("{API}/tenants/system");

    // The API refuses enabling either policy, and nothing is stored.
    for settings in [
        json!({"dcr": {"policy": "open"}}),
        json!({"dcr": {"policy": "allow_listed"}}),
        json!({"cimd": {"policy": "open"}}),
        json!({"cimd": {"policy": "allow_listed", "allowed_hosts": ["mcp.example"]}}),
    ] {
        let resp = call(
            &app,
            Method::PATCH,
            &system,
            Some(&token),
            Some(json!({"settings": settings})),
        )
        .await;
        let body = assert_problem(&resp, 422);
        let field = body["errors"][0]["field"].as_str().unwrap();
        assert!(field == "dcr.policy" || field == "cimd.policy", "{body}");
    }
    let resp = call(
        &app,
        Method::POST,
        &format!("{system}/initial-access-tokens"),
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_field_error(&resp, "tenant");
    let stored = app
        .storage()
        .tenants()
        .get_by_slug("system")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.settings.dcr.policy, DcrPolicy::Disabled);
    assert_eq!(stored.settings.cimd.policy, CimdPolicy::Disabled);

    // Even with enabled policies written behind the API's back, the view and discovery show
    // them disabled and /register stays a 404.
    let mut settings = stored.settings.clone();
    settings.dcr.policy = DcrPolicy::Open;
    settings.cimd.policy = CimdPolicy::Open;
    app.storage()
        .tenants()
        .update(
            stored.id,
            &TenantUpdate {
                settings: Some(settings),
                ..TenantUpdate::default()
            },
        )
        .await
        .unwrap();
    let resp = call(&app, Method::GET, &system, Some(&token), None).await;
    let view = body_json(&resp);
    assert_eq!(view["settings"]["dcr"]["policy"], "disabled");
    assert_eq!(view["settings"]["cimd"]["policy"], "disabled");
    let resp = call(
        &app,
        Method::GET,
        "/t/system/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    let disc = body_json(&resp);
    assert!(disc.get("registration_endpoint").is_none(), "{disc}");
    assert!(disc.get("client_id_metadata_document_supported").is_none());
    let resp = call(
        &app,
        Method::POST,
        "/t/system/register",
        None,
        Some(json!({"redirect_uris": ["https://rp.test/cb"]})),
    )
    .await;
    assert_eq!(resp.status, 404, "{}", resp.text());
}

/// Audit events of `tenant` with `action`.
async fn audit_count(app: &TestApp, tenant: &str, action: anvil_core::model::AuditAction) -> usize {
    let id = app
        .storage()
        .tenants()
        .get_by_slug(tenant)
        .await
        .unwrap()
        .unwrap()
        .id;
    app.storage()
        .audit()
        .query(
            id,
            &anvil_core::model::AuditQuery {
                limit: 500,
                ..anvil_core::model::AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items
        .iter()
        .filter(|e| e.action == action)
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

#[tokio::test]
async fn static_client_admin_scope_refused_outside_system_tenant() {
    use anvil_core::model::AuditAction;
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let base = format!("{API}/tenants/default/clients");
    let created_before = audit_count(&app, "default", AuditAction::ClientCreated).await;

    for scopes in [
        vec!["openid", "admin:read"],
        vec!["openid", "admin"],
        vec!["admin:custom"],
    ] {
        let resp = call(
            &app,
            Method::POST,
            &base,
            Some(&token),
            Some(web_client(&scopes)),
        )
        .await;
        assert_field_error(&resp, "scopes");
    }
    let tenant = app.default.as_ref().unwrap().tenant.id;
    let page = app
        .storage()
        .clients()
        .list(tenant, anvil_core::model::PageRequest::default())
        .await
        .unwrap();
    assert!(page.items.is_empty(), "nothing stored");
    assert_eq!(
        audit_count(&app, "default", AuditAction::ClientCreated).await,
        created_before
    );

    // An existing client cannot be updated to an admin scope.
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
    let updated_before = audit_count(&app, "default", AuditAction::ClientUpdated).await;
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{base}/{client_id}"),
        Some(&token),
        Some(json!({"scopes": ["openid", "admin:clients:write"]})),
    )
    .await;
    assert_field_error(&resp, "scopes");
    let stored = app
        .storage()
        .clients()
        .get(tenant, &client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.scopes, vec!["openid"]);
    assert_eq!(
        audit_count(&app, "default", AuditAction::ClientUpdated).await,
        updated_before
    );
}

#[tokio::test]
async fn system_tenant_static_client_may_hold_admin_scopes() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/system/clients"),
        Some(&token),
        Some(web_client(&["openid", "admin:read"])),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(body_json(&resp)["scopes"], json!(["openid", "admin:read"]));
}

#[tokio::test]
async fn legacy_admin_scope_client_stays_editable() {
    use anvil_core::model::{
        ApplicationType, ClientAuthMethod, ClientId, ClientSource, ClientType, ConsentMode,
        GrantType, NewClient, SecretHash, TokenFormat,
    };
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let tenant = app.default.as_ref().unwrap().tenant.id;
    // A client stored before the rule (written through storage, as an older version could).
    app.storage()
        .clients()
        .create(
            tenant,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: "legacy".to_owned(),
                name: "legacy".to_owned(),
                client_type: ClientType::Confidential,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::ClientSecretBasic,
                secret_hash: Some(SecretHash(secret_hash("a legacy client secret value 0123"))),
                jwks: None,
                redirect_uris: vec!["https://rp.example/cb".to_owned()],
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec!["openid".to_owned(), "admin:read".to_owned()],
                require_pkce: true,
                created_at: app.clock_now(),
                token_format: TokenFormat::Jwt,
                consent_mode: ConsentMode::Required,
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
                organization: anvil_core::model::OrgClientPolicy::Off,
                require_pushed_authorization_requests: false,
                client_kind: anvil_core::model::ClientKind::Application,
                headless_native: false,
                client_uri: None,
                initiate_login_uri: None,
            },
        )
        .await
        .unwrap();
    let path = format!("{API}/tenants/default/clients/legacy");

    // Other fields stay editable.
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"name": "renamed"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    // The scope can be dropped ...
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"scopes": ["openid"]})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["scopes"], json!(["openid"]));
    // ... but not re-added.
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"scopes": ["openid", "admin:read"]})),
    )
    .await;
    assert_field_error(&resp, "scopes");
}
