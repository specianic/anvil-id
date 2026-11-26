//! Organization domains on the management API (ORG-04, plan 06-17): the domain rules with their
//! reasons, the published record, verification through the DNS TXT check with one uniform
//! answer for every failure, one verified org per domain, the routing settings and their guards
//! (verified domain, same-org enabled target, the `allow_local_password` lockout guard), and
//! org-admin isolation.

mod admin_support;
mod support;
mod token_support;

use std::sync::Arc;

use admin_support::{
    API, add_member, admin_token, assert_problem, call, create_org, create_role, org_admin_token,
};
use anvil_core::model::{
    AuditAction, AuditQuery, ConnectionConfig, ConnectionId, ConnectionUpdate, IdentityLinkId,
    NewAuditEvent, NewConnection, NewIdentityLink, OidcConfig, Organization, Tenant,
    WebhookEventType,
};
use anvil_core::ports::{Clock as _, DomainTxtLookup, TxtLookupError};
use anvil_core::service::domain_check::{DomainCheck, check_domain};
use anvil_web::adapters::argon2::Argon2Pool;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use anvil_web::{AppDeps, AppState};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use support::{TestApp, TestClock, json as body_json, start_time};
use token_support::seed_user;
use tower::ServiceExt as _;

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.enabled = false).await
}

fn default_tenant(app: &TestApp) -> Tenant {
    app.default.as_ref().expect("installed").tenant.clone()
}

fn domains(org: &str) -> String {
    format!("{API}/tenants/default/organizations/{org}/domains")
}

async fn sys(app: &TestApp) -> String {
    admin_token(app, "admin:organizations:write").await
}

/// Claims `domain` for `org` through the API; returns the claim view.
async fn claim(app: &TestApp, token: &str, org: &str, domain: &str) -> Value {
    let resp = call(
        app,
        Method::POST,
        &domains(org),
        Some(token),
        Some(json!({"domain": domain})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    body_json(&resp)
}

/// Publishes the claim's record in the fake DNS and verifies it through the API.
async fn verify(app: &TestApp, token: &str, org: &str, view: &Value) -> Value {
    app.txt().set(
        view["record_name"].as_str().unwrap(),
        &[view["record_value"].as_str().unwrap()],
    );
    let resp = call(
        app,
        Method::POST,
        &format!("{}/{}/verify", domains(org), view["id"].as_str().unwrap()),
        Some(token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

/// An OIDC connection of `org` written through storage.
async fn org_connection(
    app: &TestApp,
    tenant: &Tenant,
    org: &Organization,
    slug: &str,
) -> ConnectionId {
    let id = ConnectionId::new_v7();
    app.storage()
        .connections()
        .create(
            tenant.id,
            &NewConnection {
                id,
                slug: slug.to_owned(),
                display_name: slug.to_owned(),
                enabled: true,
                config: ConnectionConfig::Oidc(OidcConfig {
                    issuer: "https://login.acme-corp.com".to_owned(),
                    client_id: "c".to_owned(),
                    scopes: vec![],
                    use_pkce: true,
                    fetch_userinfo: false,
                }),
                secret_enc: None,
                trust_email_verified: true,
                created_at: app.clock().now(),
                org_id: Some(org.id),
            },
        )
        .await
        .expect("create the connection");
    id
}

/// One successful SSO sign-in through `conn`: an identity link.
async fn sign_in_once(app: &TestApp, tenant: &Tenant, conn: ConnectionId) {
    let user = seed_user(app, tenant.id, "first@acme-corp.com").await;
    app.storage()
        .connections()
        .create_link(
            tenant.id,
            &NewIdentityLink {
                id: IdentityLinkId::new_v7(),
                user_id: user.id,
                connection_id: conn,
                subject: "sub-1".to_owned(),
                email_at_link: None,
                metadata: serde_json::Map::new(),
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create the link");
}

async fn patch(
    app: &TestApp,
    token: &str,
    org: &str,
    id: &str,
    body: Value,
) -> support::TestResponse {
    call(
        app,
        Method::PATCH,
        &format!("{}/{id}", domains(org)),
        Some(token),
        Some(body),
    )
    .await
}

async fn routed(app: &TestApp, tenant: &Tenant, domain: &str) -> bool {
    app.storage()
        .organizations()
        .routed_domain(tenant.id, domain)
        .await
        .unwrap()
        .is_some()
}

// ---------------------------------------------------------------------------------------------
// Claims and the domain rules
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn domain_add_normalises_and_returns_record() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let t = sys(&app).await;
    let view = claim(&app, &t, "acme", "  Acme-Corp.COM. ").await;
    assert_eq!(view["domain"], "acme-corp.com");
    assert_eq!(view["status"], "pending");
    assert_eq!(view["record_name"], "_anvilid-challenge.acme-corp.com.");
    let value = view["record_value"].as_str().unwrap();
    let token = value
        .strip_prefix("anvilid-domain-verification=")
        .expect("record value prefix");
    assert_eq!(token.len(), 26);
    assert_eq!(view["routing"], false);
    assert_eq!(view["allow_local_password"], true);
    assert_eq!(view["connection_id"], Value::Null);
    // Each claim gets its own token.
    let other = claim(&app, &t, "acme", "acme-corp.org").await;
    assert_ne!(other["record_value"], view["record_value"]);
    // The same org cannot claim a domain twice.
    let resp = call(
        &app,
        Method::POST,
        &domains("acme"),
        Some(&t),
        Some(json!({"domain": "ACME-CORP.com"})),
    )
    .await;
    assert_problem(&resp, 409);
    // Audited with the org and the domain.
    let events = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::OrgDomainCreated),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|e| e.details.as_map()["org_id"] == org.id.to_string())
    );
    assert!(
        events
            .iter()
            .any(|e| e.details.as_map()["domain"] == "acme-corp.com")
    );
}

async fn assert_refused(input: &str, reason: &str) {
    let app = app().await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let t = sys(&app).await;
    let resp = call(
        &app,
        Method::POST,
        &domains("acme"),
        Some(&t),
        Some(json!({"domain": input})),
    )
    .await;
    let body = assert_problem(&resp, 422);
    assert_eq!(body["errors"][0]["field"], "domain", "{input}: {body}");
    assert!(
        body["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains(reason),
        "{input}: {body}"
    );
    assert!(
        app.storage()
            .organizations()
            .list_domains(tenant.id, create_org_id(&app, &tenant).await)
            .await
            .unwrap()
            .is_empty()
    );
}

async fn create_org_id(app: &TestApp, tenant: &Tenant) -> anvil_core::model::OrgId {
    app.storage()
        .organizations()
        .get_by_slug(tenant.id, "acme")
        .await
        .unwrap()
        .unwrap()
        .id
}

#[tokio::test]
async fn domain_add_refuses_public_suffix() {
    assert_refused("co.uk", "public suffix").await;
    assert_refused("github.io", "public suffix").await;
}

#[tokio::test]
async fn domain_add_refuses_ip_literal() {
    assert_refused("192.0.2.10", "IP addresses").await;
    assert_refused("[2001:db8::1]", "").await;
}

#[tokio::test]
async fn domain_add_refuses_reserved_name() {
    assert_refused("intranet.local", "reserved").await;
    assert_refused("localhost", "").await;
    assert_refused("acme.test", "reserved").await;
}

#[tokio::test]
async fn domain_add_refuses_wildcard() {
    assert_refused("*.acme-corp.com", "wildcard").await;
}

#[tokio::test]
async fn domain_add_refuses_scheme_or_path() {
    assert_refused("https://acme-corp.com", "not a URL").await;
    assert_refused("acme-corp.com/login", "path").await;
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn domain_verify_succeeds_with_matching_txt() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let t = sys(&app).await;
    let view = claim(&app, &t, "acme", "acme-corp.com").await;
    let verified = verify(&app, &t, "acme", &view).await;
    assert_eq!(verified["status"], "verified");
    assert!(verified["verified_at"].is_string());
    assert_eq!(
        app.storage()
            .organizations()
            .verified_domains_of_org(tenant.id, org.id)
            .await
            .unwrap(),
        vec!["acme-corp.com".to_owned()]
    );
    // Verifying again is idempotent (no second event).
    let again = call(
        &app,
        Method::POST,
        &format!(
            "{}/{}/verify",
            domains("acme"),
            view["id"].as_str().unwrap()
        ),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(body_json(&again)["status"], "verified");

    let events = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::OrgDomainVerified),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.target.as_deref(), view["id"].as_str());
    assert_eq!(e.details.as_map()["org_id"], org.id.to_string());
    // Published as organization.domain_verified with the claim and the org (ids only).
    let w = anvil_core::policy::webhook_event::webhook_event(
        &tenant.id.to_string(),
        &NewAuditEvent {
            id: e.id,
            at: e.at,
            actor: e.actor.clone(),
            action: e.action,
            target: e.target.clone(),
            outcome: e.outcome,
            ctx: e.ctx.clone(),
            details: e.details.clone(),
            webhook: None,
        },
    )
    .expect("a webhook event");
    assert_eq!(w.event_type, WebhookEventType::OrganizationDomainVerified);
    let payload: Value = serde_json::from_str(&w.payload_json).unwrap();
    assert_eq!(payload["data"]["domain_id"], view["id"]);
    assert_eq!(payload["data"]["org_id"], org.id.to_string());
    assert!(!w.payload_json.contains("acme-corp.com"));
}

/// A TXT lookup whose every query fails (SERVFAIL, timeout): test code only.
struct FailingTxt;

#[async_trait::async_trait]
impl DomainTxtLookup for FailingTxt {
    async fn txt(&self, _fqdn: &str) -> Result<Vec<Vec<u8>>, TxtLookupError> {
        Err(TxtLookupError::Failed)
    }
}

/// A second router on the same storage whose DNS lookup always fails.
fn failing_dns_router(app: &TestApp) -> axum::Router {
    let hasher = Argon2Pool::new(argon2::Params::new(256, 1, 1, None).unwrap(), 2).unwrap();
    let deps = AppDeps {
        storage: app.storage_arc(),
        clock: Arc::new(TestClock::new(start_time())),
        hasher: Arc::new(hasher),
        breach: breach_checker(BreachCheckMode::Off),
        kek: app.kek_arc(),
        domain_txt: Arc::new(FailingTxt),
    };
    anvil_web::router(AppState::new(app.config.clone(), deps).expect("app builds"))
}

async fn post_raw(router: &axum::Router, app: &TestApp, path: &str, token: &str) -> (u16, Vec<u8>) {
    let mut req = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::HOST, app.config.public_url.host_port())
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(support::DEFAULT_PEER));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    (
        status,
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

#[tokio::test]
async fn domain_verification_failures_are_indistinguishable() {
    let app = app().await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let t = sys(&app).await;
    let view = claim(&app, &t, "acme", "acme-corp.com").await;
    let path = format!(
        "{}/{}/verify",
        domains("acme"),
        view["id"].as_str().unwrap()
    );
    let name = view["record_name"].as_str().unwrap();

    // 1. No record (NXDOMAIN / NODATA).
    let not_found = call(&app, Method::POST, &path, Some(&t), None).await;
    // 2. A record with the wrong value (another token, a near miss).
    app.txt().set(
        name,
        &[
            "anvilid-domain-verification=AAAAAAAAAAAAAAAAAAAAAAAAAA",
            " ".repeat(3).as_str(),
        ],
    );
    let wrong = call(&app, Method::POST, &path, Some(&t), None).await;
    // 3. The lookup fails (SERVFAIL, timeout).
    let (failed_status, failed_body) = post_raw(&failing_dns_router(&app), &app, &path, &t).await;

    assert_eq!(not_found.status, 200, "{}", not_found.text());
    assert_eq!(body_json(&not_found)["status"], "pending");
    assert_eq!(wrong.status, not_found.status);
    assert_eq!(failed_status, not_found.status.as_u16());
    assert_eq!(wrong.body, not_found.body, "wrong value vs. no record");
    assert_eq!(failed_body, not_found.body, "lookup failure vs. no record");
    // The same through the core check, which is the only check.
    let fails = check_domain(&FailingTxt, "acme-corp.com", "TOKEN").await;
    assert_eq!(fails, DomainCheck::NotVerified);
    // Still pending; failures are audited without a cause.
    let stored = app
        .storage()
        .organizations()
        .list_domains(tenant.id, create_org_id(&app, &tenant).await)
        .await
        .unwrap();
    assert!(stored[0].verified_at.is_none());
    let failures = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::OrgDomainVerificationFailed),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    assert_eq!(failures.len(), 3);
    assert!(
        failures
            .iter()
            .all(|e| e.details.as_map().get("reason").is_none())
    );
}

#[tokio::test]
async fn second_org_cannot_verify_verified_domain() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let acme = create_org(&app, tenant.id, "acme").await;
    let globex = create_org(&app, tenant.id, "globex").await;
    let t = sys(&app).await;
    // Pending claims by two orgs are allowed.
    let a = claim(&app, &t, "acme", "shared-corp.com").await;
    let g = claim(&app, &t, "globex", "shared-corp.com").await;
    assert_ne!(a["record_value"], g["record_value"]);
    let verified = verify(&app, &t, "acme", &a).await;
    assert_eq!(verified["status"], "verified");
    // Globex publishes its own record too: still refused, nothing changes.
    app.txt().set(
        g["record_name"].as_str().unwrap(),
        &[g["record_value"].as_str().unwrap()],
    );
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/{}/verify", domains("globex"), g["id"].as_str().unwrap()),
        Some(&t),
        None,
    )
    .await;
    assert_problem(&resp, 409);
    assert!(
        app.storage()
            .organizations()
            .verified_domains_of_org(tenant.id, globex.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        app.storage()
            .organizations()
            .verified_domains_of_org(tenant.id, acme.id)
            .await
            .unwrap(),
        vec!["shared-corp.com".to_owned()]
    );
}

// ---------------------------------------------------------------------------------------------
// Routing settings and guards
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn routing_requires_verified_domain() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let conn = org_connection(&app, &tenant, &org, "acme-sso").await;
    let t = sys(&app).await;
    let view = claim(&app, &t, "acme", "acme-corp.com").await;
    let id = view["id"].as_str().unwrap();
    let resp = patch(
        &app,
        &t,
        "acme",
        id,
        json!({"connection_id": conn.0, "routing": true}),
    )
    .await;
    assert_problem(&resp, 409);
    // A target alone is fine on a pending claim; routing it is not.
    let resp = patch(&app, &t, "acme", id, json!({"connection_id": conn.0})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = patch(&app, &t, "acme", id, json!({"routing": true})).await;
    assert_problem(&resp, 409);
    // Routing without a target, once verified, is refused too.
    let other = claim(&app, &t, "acme", "acme-corp.net").await;
    verify(&app, &t, "acme", &other).await;
    let resp = patch(
        &app,
        &t,
        "acme",
        other["id"].as_str().unwrap(),
        json!({"routing": true}),
    )
    .await;
    assert_problem(&resp, 409);
    assert!(!routed(&app, &tenant, "acme-corp.com").await);
    assert!(!routed(&app, &tenant, "acme-corp.net").await);
}

#[tokio::test]
async fn routing_target_must_be_same_org_connection() {
    let app = app().await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let globex = create_org(&app, tenant.id, "globex").await;
    let foreign = org_connection(&app, &tenant, &globex, "globex-sso").await;
    let t = sys(&app).await;
    let view = verify(
        &app,
        &t,
        "acme",
        &claim(&app, &t, "acme", "acme-corp.com").await,
    )
    .await;
    let id = view["id"].as_str().unwrap();
    for target in [json!(foreign.0), json!(uuid::Uuid::now_v7())] {
        let resp = patch(
            &app,
            &t,
            "acme",
            id,
            json!({"connection_id": target, "routing": true}),
        )
        .await;
        let body = assert_problem(&resp, 422);
        assert_eq!(body["errors"][0]["field"], "connection_id", "{body}");
    }
    // A tenant-level connection is not a target either.
    let admin = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/connections"),
        Some(&admin),
        Some(json!({
            "slug": "tenant-oidc", "display_name": "T",
            "config": {"type": "oidc", "issuer": "https://idp.acme-corp.com", "client_id": "c"},
        })),
    )
    .await;
    let tenant_conn = body_json(&resp)["id"].clone();
    let resp = patch(&app, &t, "acme", id, json!({"connection_id": tenant_conn})).await;
    assert_problem(&resp, 422);
    assert!(!routed(&app, &tenant, "acme-corp.com").await);
}

#[tokio::test]
async fn allow_local_password_defaults_true() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let conn = org_connection(&app, &tenant, &org, "acme-sso").await;
    let t = sys(&app).await;
    let view = verify(
        &app,
        &t,
        "acme",
        &claim(&app, &t, "acme", "acme-corp.com").await,
    )
    .await;
    assert_eq!(view["allow_local_password"], true);
    let resp = patch(
        &app,
        &t,
        "acme",
        view["id"].as_str().unwrap(),
        json!({"connection_id": conn.0, "routing": true}),
    )
    .await;
    assert_eq!(body_json(&resp)["allow_local_password"], true);
}

#[tokio::test]
async fn routing_to_new_connection_without_sign_ins_is_allowed() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let conn = org_connection(&app, &tenant, &org, "acme-sso").await;
    let t = sys(&app).await;
    let view = verify(
        &app,
        &t,
        "acme",
        &claim(&app, &t, "acme", "acme-corp.com").await,
    )
    .await;
    assert!(
        !app.storage()
            .connections()
            .has_links(tenant.id, conn)
            .await
            .unwrap()
    );
    let resp = patch(
        &app,
        &t,
        "acme",
        view["id"].as_str().unwrap(),
        json!({"connection_id": conn.0, "routing": true}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body_json(&resp);
    assert_eq!(v["routing"], true);
    assert_eq!(v["connection_id"], conn.0.to_string());
    assert!(routed(&app, &tenant, "acme-corp.com").await);
}

#[tokio::test]
async fn disabling_local_password_requires_proven_connection() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let conn = org_connection(&app, &tenant, &org, "acme-sso").await;
    let t = sys(&app).await;
    let view = verify(
        &app,
        &t,
        "acme",
        &claim(&app, &t, "acme", "acme-corp.com").await,
    )
    .await;
    let id = view["id"].as_str().unwrap();
    // Not routed yet: refused even in one patch with the routing.
    let resp = patch(&app, &t, "acme", id, json!({"allow_local_password": false})).await;
    assert_problem(&resp, 409);
    let resp = patch(
        &app,
        &t,
        "acme",
        id,
        json!({"connection_id": conn.0, "routing": true, "allow_local_password": false}),
    )
    .await;
    let body = assert_problem(&resp, 409);
    assert!(
        body["detail"].as_str().unwrap().contains("sign-in"),
        "{body}"
    );
    let stored = app
        .storage()
        .organizations()
        .list_domains(tenant.id, org.id)
        .await
        .unwrap();
    assert!(stored[0].allow_local_password && !stored[0].routing);
    // Routed, but no sign-in through the connection yet: still refused.
    let resp = patch(
        &app,
        &t,
        "acme",
        id,
        json!({"connection_id": conn.0, "routing": true}),
    )
    .await;
    assert_eq!(resp.status, 200);
    let resp = patch(&app, &t, "acme", id, json!({"allow_local_password": false})).await;
    assert_problem(&resp, 409);
    // After the first SSO sign-in it is allowed.
    sign_in_once(&app, &tenant, conn).await;
    let resp = patch(&app, &t, "acme", id, json!({"allow_local_password": false})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["allow_local_password"], false);
    // Turning routing off while passwords are off would lock users out: refused.
    let resp = patch(&app, &t, "acme", id, json!({"routing": false})).await;
    assert_problem(&resp, 409);
    // The recovery path always works.
    let resp = patch(
        &app,
        &t,
        "acme",
        id,
        json!({"routing": false, "allow_local_password": true}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn disabled_target_connection_stops_routing() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let conn = org_connection(&app, &tenant, &org, "acme-sso").await;
    let t = sys(&app).await;
    let view = verify(
        &app,
        &t,
        "acme",
        &claim(&app, &t, "acme", "acme-corp.com").await,
    )
    .await;
    let id = view["id"].as_str().unwrap();
    let resp = patch(
        &app,
        &t,
        "acme",
        id,
        json!({"connection_id": conn.0, "routing": true}),
    )
    .await;
    assert_eq!(resp.status, 200);
    assert!(routed(&app, &tenant, "acme-corp.com").await);
    app.storage()
        .connections()
        .update(
            tenant.id,
            conn,
            &ConnectionUpdate {
                enabled: Some(false),
                ..ConnectionUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!routed(&app, &tenant, "acme-corp.com").await);
    // Routing to a disabled connection cannot be (re-)enabled either.
    let resp = patch(&app, &t, "acme", id, json!({"routing": false})).await;
    assert_eq!(resp.status, 200);
    let resp = patch(&app, &t, "acme", id, json!({"routing": true})).await;
    assert_problem(&resp, 409);
}

#[tokio::test]
async fn domain_delete_stops_routing() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let conn = org_connection(&app, &tenant, &org, "acme-sso").await;
    let t = sys(&app).await;
    let view = verify(
        &app,
        &t,
        "acme",
        &claim(&app, &t, "acme", "acme-corp.com").await,
    )
    .await;
    let id = view["id"].as_str().unwrap();
    patch(
        &app,
        &t,
        "acme",
        id,
        json!({"connection_id": conn.0, "routing": true}),
    )
    .await;
    assert!(routed(&app, &tenant, "acme-corp.com").await);
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{}/{id}", domains("acme")),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 204);
    assert!(!routed(&app, &tenant, "acme-corp.com").await);
    let resp = call(
        &app,
        Method::GET,
        &format!("{}/{id}", domains("acme")),
        Some(&t),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    let deleted = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::OrgDomainDeleted),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    assert_eq!(deleted.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Org admins
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn org_admin_cannot_touch_other_org_domains() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let acme = create_org(&app, tenant.id, "acme").await;
    let globex = create_org(&app, tenant.id, "globex").await;
    let role = create_role(&app, tenant.id, Some(acme.id), "org-admins", &["org:admin"]).await;
    let admin = seed_user(&app, tenant.id, "ada@acme-corp.com").await;
    add_member(&app, tenant.id, acme.id, admin.id, &[role.id]).await;
    let token = org_admin_token(&app, &tenant, acme.id, admin.id)
        .await
        .token;

    // Own org: claim, verify, list.
    let own = claim(&app, &token, "acme", "acme-corp.com").await;
    let own = verify(&app, &token, "acme", &own).await;
    assert_eq!(own["status"], "verified");

    let t = sys(&app).await;
    let foreign = claim(&app, &t, "globex", "globex-corp.com").await;
    let fid = foreign["id"].as_str().unwrap();
    app.txt().set(
        foreign["record_name"].as_str().unwrap(),
        &[foreign["record_value"].as_str().unwrap()],
    );
    // Through its own org path the foreign claim does not exist.
    for (m, path, body) in [
        (Method::GET, format!("{}/{fid}", domains("acme")), None),
        (
            Method::PATCH,
            format!("{}/{fid}", domains("acme")),
            Some(json!({"routing": false})),
        ),
        (Method::DELETE, format!("{}/{fid}", domains("acme")), None),
        (
            Method::POST,
            format!("{}/{fid}/verify", domains("acme")),
            None,
        ),
    ] {
        let resp = call(&app, m, &path, Some(&token), body).await;
        assert_problem(&resp, 404);
    }
    // The other org's path is refused outright.
    for (m, path, body) in [
        (Method::GET, domains("globex"), None),
        (
            Method::POST,
            domains("globex"),
            Some(json!({"domain": "evil-corp.com"})),
        ),
        (Method::GET, format!("{}/{fid}", domains("globex")), None),
        (
            Method::POST,
            format!("{}/{fid}/verify", domains("globex")),
            None,
        ),
        (Method::DELETE, format!("{}/{fid}", domains("globex")), None),
    ] {
        let resp = call(&app, m, &path, Some(&token), body).await;
        assert_problem(&resp, 403);
    }
    let stored = app
        .storage()
        .organizations()
        .list_domains(tenant.id, globex.id)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].verified_at.is_none());
}
