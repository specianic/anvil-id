//! Roles, permissions and custom attributes in tokens (ORG-05, ADM-06): the default claim
//! mapping per scope and token, refresh picking up role changes, UserInfo, client credentials,
//! attribute values validated against the current schema, system-tenant admin scopes bounded by
//! roles (decision Q3), and the token endpoint counters.

mod support;
mod token_support;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anvil_core::model::{
    AttributeDefinition, ClaimRule, ClientAuthMethod, NewRole, Role, RoleId, SYSTEM_ADMIN_ROLE,
    TenantId, TokenTarget, User,
};
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::*;

async fn role(app: &TestApp, tenant: TenantId, name: &str, perms: &[&str]) -> Role {
    app.storage()
        .roles()
        .create(
            tenant,
            &NewRole {
                id: RoleId::new_v7(),
                org_id: None,
                name: name.into(),
                description: String::new(),
                permissions: perms.iter().map(|p| (*p).to_owned()).collect(),
                created_at: app.clock_now(),
            },
        )
        .await
        .expect("role created")
}

async fn assign(app: &TestApp, tenant: TenantId, role: &Role, user: &User) {
    assert!(
        app.storage()
            .roles()
            .assign(tenant, role.id, user.id, app.clock_now())
            .await
            .expect("assign")
    );
}

async fn unassign(app: &TestApp, tenant: TenantId, role: &Role, user: &User) {
    assert!(
        app.storage()
            .roles()
            .unassign(tenant, role.id, user.id)
            .await
            .expect("unassign")
    );
}

/// A code for `scope` exchanged at `path` (asserting 200).
async fn exchange_at(app: &TestApp, path: &str, flow: &CodeFlow) -> Value {
    let resp = token_at(
        app,
        path,
        &flow.rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", &flow.code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

async fn flow_for(app: &TestApp, tenant: TenantId, rp: &Rp, user: &User, scope: &str) -> CodeFlow {
    let session = seed_session(app, tenant, user).await;
    let code = issue_code(app, tenant, rp, &session, &params(scope, Some(CHALLENGE))).await;
    CodeFlow {
        tenant,
        rp: rp.clone(),
        user: user.clone(),
        session,
        code,
    }
}

fn at_claims(body: &Value) -> Value {
    jwt_claims(body["access_token"].as_str().expect("access_token"))
}

fn id_claims(body: &Value) -> Value {
    jwt_claims(body["id_token"].as_str().expect("id_token"))
}

fn rt(body: &Value) -> String {
    body["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned()
}

#[tokio::test]
async fn roles_and_permissions_follow_the_mapping_and_the_scope() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let editor = role(&app, tenant, "editor", &["docs:write", "docs:read"]).await;
    assign(&app, tenant, &editor, &user).await;

    let body = exchange_at(
        &app,
        "/token",
        &flow_for(&app, tenant, &rp, &user, "openid roles").await,
    )
    .await;
    let at = at_claims(&body);
    assert_eq!(at["roles"], json!(["editor"]), "{at}");
    assert_eq!(
        at["permissions"],
        json!(["docs:read", "docs:write"]),
        "{at}"
    );
    let id = id_claims(&body);
    assert_eq!(id["roles"], json!(["editor"]), "{id}");
    assert!(
        id.get("permissions").is_none(),
        "permissions go to the access token only: {id}"
    );

    // Without the `roles` scope: no roles claim anywhere, permissions still in the access token.
    let body = exchange_at(
        &app,
        "/token",
        &flow_for(&app, tenant, &rp, &user, "openid").await,
    )
    .await;
    let at = at_claims(&body);
    assert!(at.get("roles").is_none(), "{at}");
    assert_eq!(
        at["permissions"],
        json!(["docs:read", "docs:write"]),
        "{at}"
    );
    assert!(id_claims(&body).get("roles").is_none());
    // Protocol claims are untouched.
    assert_eq!(at["sub"], user.id.to_string());
    assert_eq!(at["scope"], "openid");
}

#[tokio::test]
async fn a_user_without_roles_gets_no_role_claims() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid roles").await;
    let at = at_claims(&body);
    assert!(at.get("roles").is_none(), "{at}");
    assert!(
        at.get("permissions").is_none(),
        "empty sets are omitted: {at}"
    );
}

#[tokio::test]
async fn refresh_reflects_role_changes() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let editor = role(&app, tenant, "editor", &["docs:write"]).await;
    let viewer = role(&app, tenant, "viewer", &["docs:read"]).await;
    assign(&app, tenant, &editor, &user).await;

    let body = exchange_at(
        &app,
        "/token",
        &flow_for(&app, tenant, &rp, &user, "openid roles").await,
    )
    .await;
    assert_eq!(at_claims(&body)["roles"], json!(["editor"]));

    assign(&app, tenant, &viewer, &user).await;
    let resp = refresh(&app, &rp, &rt(&body), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = body_json(&resp);
    assert_eq!(at_claims(&body)["roles"], json!(["editor", "viewer"]));
    assert_eq!(id_claims(&body)["roles"], json!(["editor", "viewer"]));
    assert_eq!(
        at_claims(&body)["permissions"],
        json!(["docs:read", "docs:write"])
    );

    unassign(&app, tenant, &editor, &user).await;
    let resp = refresh(&app, &rp, &rt(&body), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = body_json(&resp);
    assert_eq!(at_claims(&body)["roles"], json!(["viewer"]));
    assert_eq!(at_claims(&body)["permissions"], json!(["docs:read"]));
}

#[tokio::test]
async fn userinfo_carries_roles_with_the_roles_scope() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let editor = role(&app, tenant, "editor", &["docs:write"]).await;
    assign(&app, tenant, &editor, &user).await;

    let body = exchange_at(
        &app,
        "/token",
        &flow_for(&app, tenant, &rp, &user, "openid roles").await,
    )
    .await;
    let resp = userinfo_get(&app, body["access_token"].as_str().unwrap()).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let info = body_json(&resp);
    assert_eq!(info["roles"], json!(["editor"]), "{info}");
    assert!(info.get("permissions").is_none(), "{info}");
    assert_eq!(info["sub"], user.id.to_string());

    let body = exchange_at(
        &app,
        "/token",
        &flow_for(&app, tenant, &rp, &user, "openid").await,
    )
    .await;
    let info = body_json(&userinfo_get(&app, body["access_token"].as_str().unwrap()).await);
    assert!(info.get("roles").is_none(), "{info}");
}

#[tokio::test]
async fn client_credentials_tokens_carry_no_role_claims() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    let resp = token(&app, &rp.auth(), &[("grant_type", "client_credentials")]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let at = at_claims(&body_json(&resp));
    assert!(at.get("roles").is_none(), "{at}");
    assert!(at.get("permissions").is_none(), "{at}");
}

#[tokio::test]
async fn attribute_values_reach_tokens_only_when_valid_for_the_current_schema() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let all = vec![
        TokenTarget::AccessToken,
        TokenTarget::IdToken,
        TokenTarget::Userinfo,
    ];
    for (name, claim, schema) in [
        ("dept", "department", json!({"type": "string"})),
        // The stored value below no longer validates against this (tightened) schema.
        ("level", "level", json!({"type": "integer"})),
    ] {
        app.storage()
            .attributes()
            .upsert(
                tenant,
                &AttributeDefinition {
                    name: name.into(),
                    schema,
                    required: false,
                    user_editable: false,
                    claim: Some(ClaimRule {
                        claim: claim.into(),
                        tokens: all.clone(),
                        scope: None,
                    }),
                    position: 0,
                },
                app.clock_now(),
            )
            .await
            .expect("definition");
    }
    let values = json!({"dept": "eng", "level": "high"});
    assert!(
        app.storage()
            .attributes()
            .set_user_values(
                tenant,
                user.id,
                values.as_object().unwrap(),
                app.clock_now()
            )
            .await
            .expect("values")
    );

    let body = exchange_at(
        &app,
        "/token",
        &flow_for(&app, tenant, &rp, &user, "openid").await,
    )
    .await;
    let at = at_claims(&body);
    assert_eq!(at["department"], "eng", "{at}");
    assert!(at.get("level").is_none(), "invalid value omitted: {at}");
    let id = id_claims(&body);
    assert_eq!(id["department"], "eng", "{id}");
    assert!(id.get("level").is_none(), "{id}");
    let info = body_json(&userinfo_get(&app, body["access_token"].as_str().unwrap()).await);
    assert_eq!(info["department"], "eng", "{info}");
    assert!(info.get("level").is_none(), "{info}");
}

// ---------------------------------------------------------------------------------------------
// System tenant: admin scopes bounded by roles (Q3)
// ---------------------------------------------------------------------------------------------

const SYSTEM_TOKEN: &str = "/t/system/token";

async fn system_rp(app: &TestApp) -> (TenantId, Rp) {
    let system = app.system.as_ref().expect("installed").tenant.id;
    let mut input = web_input(ClientAuthMethod::ClientSecretBasic);
    input.scopes = ["openid", "admin:read", "admin:write"]
        .map(String::from)
        .to_vec();
    (system, register(app, system, input).await)
}

async fn administrator(app: &TestApp, system: TenantId) -> Role {
    app.storage()
        .roles()
        .get_by_name(system, SYSTEM_ADMIN_ROLE)
        .await
        .expect("lookup")
        .expect("install creates the administrator role")
}

#[tokio::test]
async fn system_admin_scopes_are_bounded_by_roles() {
    let app = TestApp::new().await;
    let (system, rp) = system_rp(&app).await;
    let admin = seed_user(&app, system, "admin@example.test").await;
    assign(&app, system, &administrator(&app, system).await, &admin).await;
    let reader = seed_user(&app, system, "reader@example.test").await;
    let readers = role(&app, system, "readers", &["admin:read"]).await;
    assign(&app, system, &readers, &reader).await;
    let nobody = seed_user(&app, system, "nobody@example.test").await;

    // The administrator gets what it asked for.
    let body = exchange_at(
        &app,
        SYSTEM_TOKEN,
        &flow_for(&app, system, &rp, &admin, "openid admin:read admin:write").await,
    )
    .await;
    assert_eq!(body["scope"], "admin:write openid", "{body}");
    assert_eq!(at_claims(&body)["scope"], "admin:write openid");

    // admin:read role requesting admin:write -> admin:read only.
    let body = exchange_at(
        &app,
        SYSTEM_TOKEN,
        &flow_for(&app, system, &rp, &reader, "openid admin:write").await,
    )
    .await;
    assert_eq!(body["scope"], "admin:read openid", "{body}");
    assert_eq!(at_claims(&body)["scope"], "admin:read openid");

    // No roles -> no admin scope at all.
    let body = exchange_at(
        &app,
        SYSTEM_TOKEN,
        &flow_for(&app, system, &rp, &nobody, "openid admin:read admin:write").await,
    )
    .await;
    assert_eq!(body["scope"], "openid", "{body}");
    assert_eq!(at_claims(&body)["scope"], "openid");
}

#[tokio::test]
async fn system_admin_scopes_follow_role_changes_on_refresh() {
    let app = TestApp::new().await;
    let (system, rp) = system_rp(&app).await;
    let admin = seed_user(&app, system, "admin@example.test").await;
    let administrator = administrator(&app, system).await;
    assign(&app, system, &administrator, &admin).await;

    let body = exchange_at(
        &app,
        SYSTEM_TOKEN,
        &flow_for(&app, system, &rp, &admin, "openid admin:write").await,
    )
    .await;
    assert_eq!(body["scope"], "admin:write openid");

    // Storage-level removal (the admin API guard is tested elsewhere): the next refresh drops
    // the admin scope, and restoring the role brings it back (the grant itself is unchanged).
    unassign(&app, system, &administrator, &admin).await;
    let resp = token_at(
        &app,
        SYSTEM_TOKEN,
        &rp.auth(),
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &rt(&body)),
        ],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = body_json(&resp);
    assert_eq!(body["scope"], "openid", "{body}");

    assign(&app, system, &administrator, &admin).await;
    let resp = token_at(
        &app,
        SYSTEM_TOKEN,
        &rp.auth(),
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &rt(&body)),
        ],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["scope"], "admin:write openid");
}

// ---------------------------------------------------------------------------------------------
// Token endpoint counters
// ---------------------------------------------------------------------------------------------

mod capture {
    use super::*;
    use metrics::{
        Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };

    #[derive(Default)]
    pub struct Value(AtomicU64);

    impl CounterFn for Value {
        fn increment(&self, v: u64) {
            self.0.fetch_add(v, Ordering::Relaxed);
        }
        fn absolute(&self, v: u64) {
            self.0.store(v, Ordering::Relaxed);
        }
    }

    /// Counters by rendered key (`name{k="v"}`); gauges and histograms are ignored.
    #[derive(Default, Clone)]
    pub struct Rec(pub Arc<Mutex<Vec<Series>>>);

    type Series = (String, Arc<Value>);

    impl Rec {
        pub fn value(&self, key: &str) -> u64 {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.0.load(Ordering::Relaxed))
                .sum()
        }
    }

    impl Recorder for Rec {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}=\"{}\"", l.key(), l.value()))
                .collect();
            let rendered = format!("{}{{{}}}", key.name(), labels.join(","));
            let v = Arc::new(Value::default());
            self.0.lock().unwrap().push((rendered, Arc::clone(&v)));
            Counter::from_arc(v)
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }
}

#[tokio::test]
async fn issuance_and_refresh_reuse_increment_the_token_counters() {
    let app = TestApp::new().await;
    let rec = capture::Rec::default();
    // The test runtime is single-threaded, so the thread-local recorder sees the handler.
    let _guard = metrics::set_default_local_recorder(&rec);

    let (flow, body) = tokens(&app, "openid").await;
    assert_eq!(
        rec.value("anvil_tokens_issued_total{grant=\"authorization_code\"}"),
        1
    );
    let first = rt(&body);
    let resp = refresh(&app, &flow.rp, &first, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        rec.value("anvil_tokens_issued_total{grant=\"refresh_token\"}"),
        1
    );
    assert_eq!(rec.value("anvil_refresh_reuse_total{}"), 0);

    // Presenting the consumed token again: same invalid_grant on the wire, counted as reuse.
    let resp = refresh(&app, &flow.rp, &first, None).await;
    assert_oauth_error(&resp, 400, "invalid_grant");
    assert_eq!(rec.value("anvil_refresh_reuse_total{}"), 1);
    assert_eq!(
        rec.value("anvil_tokens_issued_total{grant=\"refresh_token\"}"),
        1
    );
}
