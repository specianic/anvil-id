//! Upstream connection management end to end (AUTH-07, SEC-03): CRUD over HTTP, the computed
//! callback URL, the write-only secret (never in any response, sealed in storage, opened only by
//! `ConnectionService::open_secret`), and audit rows without secret material.

mod admin_support;
mod support;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AuditAction, AuditEvent, AuditQuery, CONNECTION_SECRET_PURPOSE, ConnectionId, Tenant,
    connection_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::connection::ConnectionService;
use anvil_jose::keys::Alg;
use axum::http::Method;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};

struct Frozen(time::OffsetDateTime);

impl anvil_core::ports::Clock for Frozen {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

const SECRET: &str = "upstream-client-secret-never-shown-7f3a";

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

async fn full(app: &TestApp) -> String {
    admin_token(app, "admin:read admin:write").await
}

fn base() -> String {
    format!("{API}/tenants/default/connections")
}

async fn req(app: &TestApp, t: &str, m: Method, path: &str, body: Option<Value>) -> TestResponse {
    call(app, m, path, Some(t), body).await
}

fn google(slug: &str) -> Value {
    json!({
        "slug": slug,
        "display_name": "Google",
        "config": {"type": "social", "provider": "google", "client_id": "g-client"},
        "secret": SECRET,
    })
}

/// An ES256 PKCS#8 PEM generated for this run (never a committed key).
fn es256_pem() -> String {
    let der = anvil_jose::generate(Alg::ES256).expect("generate").pkcs8;
    let b64 = anvil_jose::encoding::b64std(&der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

fn assert_secret_free(resp: &TestResponse, secret: &str) {
    assert!(
        !resp.text().contains(secret),
        "the secret must never be returned: {}",
        resp.text()
    );
    assert!(!resp.text().contains("secret_enc"));
}

async fn default_tenant(app: &TestApp) -> Tenant {
    app.storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap()
}

async fn audit(app: &TestApp, tenant: &Tenant) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

#[tokio::test]
async fn crud_round_trip_with_write_only_secret() {
    let app = app().await;
    let t = full(&app).await;

    // Create.
    let resp = req(&app, &t, Method::POST, &base(), Some(google("google"))).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_secret_free(&resp, SECRET);
    let created = body_json(&resp);
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(
        resp.header("location"),
        Some(format!("{}/{id}", base()).as_str())
    );
    assert_eq!(created["slug"], "google");
    assert_eq!(created["kind"], "google");
    assert_eq!(created["enabled"], true);
    assert_eq!(created["secret_configured"], true);
    assert_eq!(
        created["trust_email_verified"], true,
        "Google trusts by default"
    );
    assert_eq!(created["config"]["type"], "social");
    assert_eq!(created["config"]["client_id"], "g-client");
    assert_eq!(
        created["redirect_uri"],
        format!("{}/ui/login/upstream/google/callback", app.issuer(None))
    );
    assert!(created.get("secret").is_none());

    // List and get.
    let resp = req(&app, &t, Method::GET, &base(), None).await;
    assert_eq!(resp.status, 200);
    assert_secret_free(&resp, SECRET);
    let list = body_json(&resp);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["items"][0]["secret_configured"], true);
    let one = format!("{}/{id}", base());
    let resp = req(&app, &t, Method::GET, &one, None).await;
    assert_eq!(resp.status, 200);
    assert_secret_free(&resp, SECRET);

    // Patch: fields change, secret stays configured and hidden.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &one,
        Some(json!({"display_name": "Google Workspace", "enabled": false,
            "config": {"type": "social", "provider": "google", "client_id": "g2",
                       "hosted_domains": ["example.com"]}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_secret_free(&resp, SECRET);
    let patched = body_json(&resp);
    assert_eq!(patched["display_name"], "Google Workspace");
    assert_eq!(patched["enabled"], false);
    assert_eq!(patched["config"]["client_id"], "g2");
    assert_eq!(patched["config"]["hosted_domains"], json!(["example.com"]));
    assert_eq!(patched["secret_configured"], true);
    assert_eq!(patched["slug"], "google");

    // Storage holds only the sealed secret, bound to tenant and connection.
    let tenant = default_tenant(&app).await;
    let cid = ConnectionId(uuid::Uuid::parse_str(&id).unwrap());
    let stored = app
        .storage()
        .connections()
        .get(tenant.id, cid)
        .await
        .unwrap()
        .unwrap();
    let sealed = stored.secret_enc.clone().expect("sealed secret");
    assert!(!sealed.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()));
    let opened = app
        .kek()
        .open(
            CONNECTION_SECRET_PURPOSE,
            &connection_aad(tenant.id, cid),
            &sealed,
        )
        .unwrap();
    assert_eq!(&opened[..], SECRET.as_bytes());
    let service = ConnectionService {
        storage: app.storage_arc(),
        clock: std::sync::Arc::new(Frozen(app.clock().now())),
        kek: app.kek_arc(),
        saml_enabled: app.config.saml_experimental,
        saml_xml: Some(std::sync::Arc::new(
            anvil_web::adapters::saml_xml::SamlXmlAdapter,
        )),
        upstream: None,
    };
    assert_eq!(
        service
            .open_secret(&stored)
            .unwrap()
            .unwrap()
            .expose_secret(),
        SECRET
    );

    // Rotate, then clear the secret.
    let secret_path = format!("{one}/secret");
    let rotated = "rotated-secret-also-never-shown-91";
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &secret_path,
        Some(json!({"secret": rotated})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_secret_free(&resp, rotated);
    assert_eq!(body_json(&resp)["secret_configured"], true);
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &secret_path,
        Some(json!({"secret": null})),
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["secret_configured"], false);
    // The field is required.
    let resp = req(&app, &t, Method::PUT, &secret_path, Some(json!({}))).await;
    assert_field_error(&resp, "secret");

    // Delete.
    let resp = req(&app, &t, Method::DELETE, &one, None).await;
    assert_eq!(resp.status, 204);
    let resp = req(&app, &t, Method::GET, &one, None).await;
    assert_problem(&resp, 404);
    let resp = req(&app, &t, Method::DELETE, &one, None).await;
    assert_problem(&resp, 404);

    // Every change is audited in the tenant, never with secret material.
    let events = audit(&app, &tenant).await;
    let of = |a: AuditAction| events.iter().filter(|e| e.action == a).count();
    assert_eq!(of(AuditAction::ConnectionCreated), 1);
    assert_eq!(of(AuditAction::ConnectionUpdated), 1);
    assert_eq!(of(AuditAction::ConnectionSecretRotated), 2);
    assert_eq!(of(AuditAction::ConnectionDeleted), 1);
    for e in events.iter().filter(|e| {
        matches!(
            e.action,
            AuditAction::ConnectionCreated
                | AuditAction::ConnectionUpdated
                | AuditAction::ConnectionSecretRotated
                | AuditAction::ConnectionDeleted
        )
    }) {
        assert_eq!(e.target.as_deref(), Some(id.as_str()));
        assert_eq!(e.details.as_map()["connection"], "google");
        assert_eq!(e.details.as_map()["kind"], "google");
        let dump = format!("{e:?}");
        assert!(!dump.contains(SECRET) && !dump.contains(rotated), "{dump}");
    }
    let updated = events
        .iter()
        .find(|e| e.action == AuditAction::ConnectionUpdated)
        .unwrap();
    assert_eq!(
        updated.details.as_map()["fields"],
        json!(["display_name", "enabled", "config"])
    );
}

#[tokio::test]
async fn duplicate_slug_is_a_conflict_and_bad_input_is_422() {
    let app = app().await;
    let t = full(&app).await;
    let resp = req(&app, &t, Method::POST, &base(), Some(google("google"))).await;
    assert_eq!(resp.status, 201);
    let resp = req(&app, &t, Method::POST, &base(), Some(google("google"))).await;
    assert_problem(&resp, 409);

    for (body, field) in [
        (google("Bad Slug"), "slug"),
        (google(""), "slug"),
        (
            json!({"slug": "oidc", "display_name": "IdP",
                   "config": {"type": "oidc", "issuer": "http://idp.example", "client_id": "c"}}),
            "config.issuer",
        ),
        (
            json!({"slug": "ms", "display_name": "Microsoft",
                   "config": {"type": "social", "provider": "microsoft", "client_id": "c"},
                   "trust_email_verified": true}),
            "trust_email_verified",
        ),
        (
            json!({"slug": "apple", "display_name": "Apple",
                   "config": {"type": "social", "provider": "apple", "client_id": "c"}}),
            "config.apple",
        ),
    ] {
        let resp = req(&app, &t, Method::POST, &base(), Some(body.clone())).await;
        assert_field_error(&resp, field);
    }
    // Unknown config types and fields are schema errors.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(json!({"slug": "s", "display_name": "S", "config": {"type": "saml"}})),
    )
    .await;
    assert_field_error(&resp, "body");
}

#[tokio::test]
async fn apple_connection_needs_an_es256_p8_key_and_kind_is_fixed() {
    let app = app().await;
    let t = full(&app).await;
    let apple = |secret: &str| {
        json!({"slug": "apple", "display_name": "Apple",
               "config": {"type": "social", "provider": "apple", "client_id": "com.example.web",
                          "apple": {"team_id": "TEAM123456", "key_id": "KEY1234567"}},
               "secret": secret})
    };
    let pem = es256_pem();
    let resp = req(&app, &t, Method::POST, &base(), Some(apple(&pem))).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert!(!resp.text().contains("PRIVATE KEY"));
    let id = body_json(&resp)["id"].as_str().unwrap().to_owned();

    // A wrong key on rotation is refused without echoing it.
    let rsa = {
        let der = anvil_jose::generate(Alg::RS256).unwrap().pkcs8;
        let b64 = anvil_jose::encoding::b64std(&der);
        format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
    };
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{}/{id}/secret", base()),
        Some(json!({"secret": rsa})),
    )
    .await;
    assert_field_error(&resp, "secret");
    assert!(!resp.text().contains("PRIVATE KEY"));

    // The kind cannot change through PATCH.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &format!("{}/{id}", base()),
        Some(json!({"config": {"type": "social", "provider": "google", "client_id": "g"}})),
    )
    .await;
    assert_field_error(&resp, "config");
}

#[tokio::test]
async fn microsoft_email_trust_needs_the_risk_flag_and_is_audited() {
    let app = app().await;
    let t = full(&app).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(json!({"slug": "ms", "display_name": "Microsoft",
                    "config": {"type": "social", "provider": "microsoft", "client_id": "c"},
                    "secret": SECRET,
                    "trust_email_verified": true, "accept_email_trust_risk": true})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(body_json(&resp)["trust_email_verified"], true);
    let tenant = default_tenant(&app).await;
    let events = audit(&app, &tenant).await;
    let created = events
        .iter()
        .find(|e| e.action == AuditAction::ConnectionCreated)
        .unwrap();
    assert_eq!(
        created.details.as_map()["reason"],
        "email_trust_risk_accepted"
    );
}

#[tokio::test]
async fn tenant_connection_list_shows_org_connections_read_only() {
    let app = app().await;
    let t = full(&app).await;
    let tenant = default_tenant(&app).await;
    let org = create_org(&app, tenant.id, "acme").await;
    let resp = req(&app, &t, Method::POST, &base(), Some(google("google"))).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{API}/tenants/default/organizations/acme/connections"),
        Some(json!({
            "slug": "acme-entra",
            "display_name": "Acme Entra",
            // Disabled: enabling would fetch the issuer's discovery document.
            "enabled": false,
            "config": {"type": "oidc", "issuer": "https://login.acme.test", "client_id": "c"},
            "secret": SECRET,
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let org_conn = body_json(&resp)["id"].as_str().unwrap().to_owned();

    // Listed with its organization; the tenant connection has none.
    let resp = req(&app, &t, Method::GET, &base(), None).await;
    let items = body_json(&resp)["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 2);
    let by_slug = |s: &str| items.iter().find(|i| i["slug"] == s).unwrap().clone();
    assert_eq!(by_slug("acme-entra")["organization"], org.id.to_string());
    assert_eq!(by_slug("google")["organization"], Value::Null);
    let one = format!("{}/{org_conn}", base());
    let resp = req(&app, &t, Method::GET, &one, None).await;
    assert_eq!(resp.status, 200);

    // Read-only at tenant level: every change is refused and nothing changes.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &one,
        Some(json!({"display_name": "Hijacked", "enabled": true})),
    )
    .await;
    assert_problem(&resp, 409);
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{one}/secret"),
        Some(json!({"secret": null})),
    )
    .await;
    assert_problem(&resp, 409);
    let resp = req(&app, &t, Method::DELETE, &one, None).await;
    assert_problem(&resp, 409);
    let stored = app
        .storage()
        .connections()
        .get(tenant.id, ConnectionId(org_conn.parse().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.display_name, "Acme Entra");
    assert!(!stored.enabled && stored.secret_enc.is_some());
}
