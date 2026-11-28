//! Organization enterprise connections on the management API (ORG-03, plan 06-17): OIDC with a
//! write-only sealed secret, SAML from explicit fields, pasted metadata or a metadata URL, the
//! service-provider values in the view, the operator flag `saml_experimental` (decision Q3), SAML
//! only per organization, certificate and URL rules, the SSRF guard of the metadata import, and
//! the org-admin principal on every route.

mod admin_support;
mod saml_support;
mod support;
mod token_support;

use admin_support::{
    API, add_member, admin_token, assert_field_error, assert_problem, call, create_org,
    create_role, org_admin_token,
};
use anvil_core::model::{
    AuditAction, AuditQuery, ConnectionConfig, ConnectionId, NameIdFormat, NewConnection,
    Organization, SamlAttributeMapping, SamlConfig, Tenant,
};
use anvil_core::ports::Clock as _;
use anvil_web::adapters::outbound::OutboundPolicy;
use axum::http::Method;
use saml_support::IdpKey;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::seed_user;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET: &str = "org-oidc-client-secret-never-shown-91c2";
const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

async fn app_with(saml: bool) -> TestApp {
    TestApp::with(|c| {
        c.rate_limits.enabled = false;
        c.saml_experimental = saml;
    })
    .await
}

async fn saml_app() -> TestApp {
    app_with(true).await
}

fn default_tenant(app: &TestApp) -> Tenant {
    app.default.as_ref().expect("installed").tenant.clone()
}

async fn write_token(app: &TestApp) -> String {
    admin_token(app, "admin:organizations:write").await
}

fn conns(org: &str) -> String {
    format!("{API}/tenants/default/organizations/{org}/connections")
}

fn all_events() -> AuditQuery {
    AuditQuery {
        limit: 200,
        ..AuditQuery::default()
    }
}

fn issuer(app: &TestApp) -> String {
    anvil_core::service::logout::canonical_issuer(&app.config.public_url, &default_tenant(app))
}

/// A disabled org OIDC connection: enabling one fetches the issuer's discovery document (covered
/// by `security_connection_enable.rs` against a local mock); these tests never go online.
fn oidc_body(slug: &str) -> Value {
    json!({
        "slug": slug,
        "display_name": "Acme Entra",
        "enabled": false,
        "config": {"type": "oidc", "issuer": "https://login.acme.test", "client_id": "acme-client"},
        "secret": SECRET,
    })
}

fn saml_config(certs: &[String]) -> Value {
    json!({
        "type": "saml",
        "idp_entity_id": "https://idp.acme.test/entity",
        "sso_url": "https://idp.acme.test/sso",
        "signing_certs": certs,
        "name_id_format": "persistent",
        "attributes": {"email": "mail", "given_name": "givenName"},
    })
}

fn saml_body(slug: &str, certs: &[String]) -> Value {
    json!({"slug": slug, "display_name": "Acme SAML", "config": saml_config(certs)})
}

fn idp_metadata(cert_b64: &str, sso: &str) -> String {
    format!(
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
xmlns:ds=\"{NS_DSIG}\" entityID=\"https://idp.acme.test/entity\">\
<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\
<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}\
</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>\
<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" \
Location=\"{sso}\"/></md:IDPSSODescriptor></md:EntityDescriptor>"
    )
}

/// A SAML connection of `org` written through storage (`enabled` as given), as if it had been
/// created while the operator flag was on.
async fn stored_saml(
    app: &TestApp,
    tenant: &Tenant,
    org: &Organization,
    enabled: bool,
) -> ConnectionId {
    let id = ConnectionId::new_v7();
    app.storage()
        .connections()
        .create(
            tenant.id,
            &NewConnection {
                id,
                slug: "legacy-saml".to_owned(),
                display_name: "Legacy SAML".to_owned(),
                enabled,
                config: ConnectionConfig::Saml(SamlConfig {
                    idp_entity_id: "https://idp.acme.test/entity".to_owned(),
                    sso_url: "https://idp.acme.test/sso".to_owned(),
                    signing_certs: vec![IdpKey::ecdsa().cert_pem()],
                    name_id_format: NameIdFormat::Persistent,
                    attributes: SamlAttributeMapping::default(),
                    metadata_url: None,
                }),
                secret_enc: None,
                trust_email_verified: false,
                created_at: app.clock().now(),
                org_id: Some(org.id),
            },
        )
        .await
        .expect("store the saml connection");
    id
}

// ---------------------------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn org_oidc_connection_crud_with_write_only_secret() {
    let app = app_with(false).await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let t = write_token(&app).await;

    let resp = call(
        &app,
        Method::POST,
        &conns("acme"),
        Some(&t),
        Some(oidc_body("acme-entra")),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert!(!resp.text().contains(SECRET));
    let view = body_json(&resp);
    assert_eq!(view["organization"], org.id.to_string());
    assert_eq!(view["kind"], "oidc");
    assert_eq!(view["secret_configured"], true);
    assert_eq!(view["sp"], Value::Null);
    assert_eq!(
        view["redirect_uri"],
        format!("{}/ui/login/upstream/acme-entra/callback", issuer(&app))
    );
    let id = view["id"].as_str().unwrap().to_owned();
    let location = resp.header("location").unwrap().to_owned();
    assert_eq!(
        location,
        format!(
            "{API}/tenants/default/organizations/{}/connections/{id}",
            org.id
        )
    );

    // Sealed in storage, bound to the org.
    let stored = app
        .storage()
        .connections()
        .get(tenant.id, ConnectionId(id.parse().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.org_id, Some(org.id));
    let sealed = stored.secret_enc.clone().expect("sealed secret");
    assert!(!String::from_utf8_lossy(&sealed).contains(SECRET));

    // List and get, by org slug and id.
    let one = format!("{}/{id}", conns(&org.id.to_string()));
    let resp = call(&app, Method::GET, &conns("acme"), Some(&t), None).await;
    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["items"].as_array().unwrap().len(), 1);
    assert!(!resp.text().contains(SECRET));
    let resp = call(&app, Method::GET, &one, Some(&t), None).await;
    assert_eq!(resp.status, 200);
    assert!(!resp.text().contains(SECRET));

    // Update, rotate and clear the secret.
    let resp = call(
        &app,
        Method::PATCH,
        &one,
        Some(&t),
        Some(json!({"display_name": "Entra"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["display_name"], "Entra");
    let resp = call(
        &app,
        Method::PUT,
        &format!("{one}/secret"),
        Some(&t),
        Some(json!({"secret": "rotated-secret-1"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(!resp.text().contains("rotated-secret-1"));
    let resp = call(
        &app,
        Method::PUT,
        &format!("{one}/secret"),
        Some(&t),
        Some(json!({"secret": null})),
    )
    .await;
    assert_eq!(body_json(&resp)["secret_configured"], false);

    // Audited with the org in the details, never the secret.
    let events = app
        .storage()
        .audit()
        .query(tenant.id, &all_events())
        .await
        .unwrap();
    let conn_events: Vec<_> = events
        .items
        .iter()
        .filter(|e| e.target.as_deref() == Some(id.as_str()))
        .collect();
    assert_eq!(conn_events.len(), 4, "{conn_events:?}");
    for e in &conn_events {
        assert_eq!(e.details.as_map()["org_id"], org.id.to_string(), "{e:?}");
        assert_eq!(e.details.as_map()["org_slug"], "acme");
        assert!(
            !serde_json::to_string(e.details.as_map())
                .unwrap()
                .contains(SECRET)
        );
    }
    assert!(
        conn_events
            .iter()
            .any(|e| e.action == AuditAction::ConnectionCreated)
    );

    let resp = call(&app, Method::DELETE, &one, Some(&t), None).await;
    assert_eq!(resp.status, 204);
    let resp = call(&app, Method::GET, &one, Some(&t), None).await;
    assert_problem(&resp, 404);
}

#[tokio::test]
async fn org_connections_are_oidc_or_saml_and_share_the_slug_namespace() {
    let app = app_with(false).await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let t = write_token(&app).await;
    let google = json!({
        "slug": "g", "display_name": "Google",
        "config": {"type": "social", "provider": "google", "client_id": "g"},
    });
    let resp = call(&app, Method::POST, &conns("acme"), Some(&t), Some(google)).await;
    assert_field_error(&resp, "config");
    // A tenant-level connection already holds the slug.
    let tenant_conn = json!({
        "slug": "taken", "display_name": "Tenant OIDC", "enabled": false,
        "config": {"type": "oidc", "issuer": "https://idp.test", "client_id": "c"},
    });
    let admin = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/connections"),
        Some(&admin),
        Some(tenant_conn),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let resp = call(
        &app,
        Method::POST,
        &conns("acme"),
        Some(&t),
        Some(oidc_body("taken")),
    )
    .await;
    assert_problem(&resp, 409);
}

// ---------------------------------------------------------------------------------------------
// SAML
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn saml_connection_create_from_fields_returns_sp_values() {
    let app = saml_app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let t = write_token(&app).await;
    let cert = IdpKey::ecdsa().cert_pem();
    let resp = call(
        &app,
        Method::POST,
        &conns("acme"),
        Some(&t),
        Some(saml_body("acme-saml", std::slice::from_ref(&cert))),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let view = body_json(&resp);
    let iss = issuer(&app);
    assert_eq!(view["kind"], "saml");
    assert_eq!(view["organization"], org.id.to_string());
    assert_eq!(view["secret_configured"], false);
    assert_eq!(view["sp"]["entity_id"], format!("{iss}/saml/acme-saml"));
    assert_eq!(
        view["sp"]["acs_url"],
        format!("{iss}/ui/login/saml/acme-saml/acs")
    );
    assert_eq!(
        view["sp"]["metadata_url"],
        format!("{iss}/saml/acme-saml/metadata")
    );
    assert_eq!(view["redirect_uri"], view["sp"]["acs_url"]);
    assert_eq!(view["config"]["type"], "saml");
    assert_eq!(view["config"]["signing_certs"][0], cert);
    assert_eq!(view["config"]["name_id_format"], "persistent");
    assert_eq!(view["config"]["attributes"]["email"], "mail");

    // A SAML connection has no client secret.
    let id = view["id"].as_str().unwrap();
    let resp = call(
        &app,
        Method::PUT,
        &format!("{}/{id}/secret", conns("acme")),
        Some(&t),
        Some(json!({"secret": "x"})),
    )
    .await;
    assert_field_error(&resp, "secret");
    let mut with_secret = saml_body("acme-saml-2", &[cert]);
    with_secret["secret"] = json!("x");
    let resp = call(
        &app,
        Method::POST,
        &conns("acme"),
        Some(&t),
        Some(with_secret),
    )
    .await;
    assert_field_error(&resp, "secret");
}

#[tokio::test]
async fn saml_connection_from_pasted_metadata() {
    let app = saml_app().await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let t = write_token(&app).await;
    let key = IdpKey::ecdsa();
    let xml = idp_metadata(&key.cert_b64(), "https://idp.acme.test/sso");
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/saml-metadata", conns("acme")),
        Some(&t),
        Some(json!({"xml": xml})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let m = body_json(&resp);
    assert_eq!(m["idp_entity_id"], "https://idp.acme.test/entity");
    assert_eq!(m["sso_url"], "https://idp.acme.test/sso");
    assert_eq!(m["metadata_url"], Value::Null);
    let certs: Vec<String> = serde_json::from_value(m["signing_certs"].clone()).unwrap();
    assert_eq!(certs.len(), 1);
    // Nothing was stored.
    assert!(
        app.storage()
            .connections()
            .list(tenant.id)
            .await
            .unwrap()
            .is_empty()
    );
    // The values create a working connection.
    let resp = call(
        &app,
        Method::POST,
        &conns("acme"),
        Some(&t),
        Some(saml_body("from-md", &certs)),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());

    // Not metadata; neither or both inputs.
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/saml-metadata", conns("acme")),
        Some(&t),
        Some(json!({"xml": "<x/>"})),
    )
    .await;
    assert_field_error(&resp, "xml");
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/saml-metadata", conns("acme")),
        Some(&t),
        Some(json!({})),
    )
    .await;
    assert_field_error(&resp, "xml");
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/saml-metadata", conns("acme")),
        Some(&t),
        Some(json!({"xml": "<x/>", "url": "https://idp.test/md"})),
    )
    .await;
    assert_field_error(&resp, "xml");
}

#[tokio::test]
async fn saml_connection_from_metadata_url() {
    let app = TestApp::with(|c| {
        c.rate_limits.enabled = false;
        c.saml_experimental = true;
        // Lets the outbound client reach the local mock IdP (test only).
        c.outbound = OutboundPolicy::loopback_dev();
    })
    .await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let t = write_token(&app).await;
    let key = IdpKey::rsa();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(idp_metadata(&key.cert_b64(), "https://idp.acme.test/sso")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/huge"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<".repeat(1024 * 1024 + 1)))
        .mount(&server)
        .await;
    let url = format!("{}/metadata", server.uri());
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/saml-metadata", conns("acme")),
        Some(&t),
        Some(json!({"url": url})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let m = body_json(&resp);
    assert_eq!(m["idp_entity_id"], "https://idp.acme.test/entity");
    assert_eq!(m["metadata_url"], url);
    assert_eq!(m["signing_certs"].as_array().unwrap().len(), 1);

    // Larger than 1 MiB: refused with the uniform answer.
    let huge = format!("{}/huge", server.uri());
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/saml-metadata", conns("acme")),
        Some(&t),
        Some(json!({"url": huge})),
    )
    .await;
    assert_field_error(&resp, "url");
    assert!(!resp.text().contains(&server.uri()));
}

#[tokio::test]
async fn metadata_url_to_private_address_is_blocked() {
    let app = saml_app().await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let t = write_token(&app).await;
    let mut bodies = Vec::new();
    for url in [
        "https://127.0.0.1/metadata",
        "https://10.1.2.3/metadata",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/metadata",
        "http://idp.acme.test/metadata",
        "file:///etc/passwd",
    ] {
        let resp = call(
            &app,
            Method::POST,
            &format!("{}/saml-metadata", conns("acme")),
            Some(&t),
            Some(json!({"url": url})),
        )
        .await;
        assert_field_error(&resp, "url");
        let host = url.split('/').nth(2).unwrap_or(url);
        assert!(
            host.is_empty() || !resp.text().contains(host),
            "{url}: {}",
            resp.text()
        );
        bodies.push(resp.text());
    }
    // One answer for every refused destination.
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
}

#[tokio::test]
async fn saml_connection_refused_when_flag_off() {
    let app = app_with(false).await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let t = write_token(&app).await;
    let cert = IdpKey::ecdsa().cert_pem();
    let resp = call(
        &app,
        Method::POST,
        &conns("acme"),
        Some(&t),
        Some(saml_body("acme-saml", &[cert])),
    )
    .await;
    let body = assert_problem(&resp, 403);
    assert_eq!(
        body["type"]
            .as_str()
            .map(|s| s.ends_with("feature_disabled")),
        Some(true),
        "{body}"
    );
    assert!(
        app.storage()
            .connections()
            .list(tenant.id)
            .await
            .unwrap()
            .is_empty()
    );
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/saml-metadata", conns("acme")),
        Some(&t),
        Some(json!({"xml": "<x/>"})),
    )
    .await;
    assert_problem(&resp, 403);

    // A disabled SAML connection from when the flag was on cannot be enabled or changed, but it
    // can be disabled and deleted.
    let id = stored_saml(&app, &tenant, &org, false).await;
    let one = format!("{}/{id}", conns("acme"));
    let resp = call(
        &app,
        Method::PATCH,
        &one,
        Some(&t),
        Some(json!({"enabled": true})),
    )
    .await;
    let body = assert_problem(&resp, 403);
    assert_eq!(
        body["type"]
            .as_str()
            .map(|s| s.ends_with("feature_disabled")),
        Some(true),
        "{body}"
    );
    let resp = call(
        &app,
        Method::PATCH,
        &one,
        Some(&t),
        Some(json!({"display_name": "New name"})),
    )
    .await;
    assert_problem(&resp, 403);
    let stored = app
        .storage()
        .connections()
        .get(tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.enabled);
    assert_eq!(stored.display_name, "Legacy SAML");
    let resp = call(
        &app,
        Method::PATCH,
        &one,
        Some(&t),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(&app, Method::DELETE, &one, Some(&t), None).await;
    assert_eq!(resp.status, 204);
}

#[tokio::test]
async fn saml_connection_refused_at_tenant_level() {
    let app = saml_app().await;
    let admin = admin_token(&app, "admin:write").await;
    let cert = IdpKey::ecdsa().cert_pem();
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/connections"),
        Some(&admin),
        Some(saml_body("tenant-saml", &[cert])),
    )
    .await;
    assert_field_error(&resp, "config");
    let tenant = default_tenant(&app);
    assert!(
        app.storage()
            .connections()
            .list(tenant.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn saml_connection_invalid_input_is_422() {
    let app = saml_app().await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let t = write_token(&app).await;
    let cert = IdpKey::ecdsa().cert_pem();
    // A well-formed PEM block whose body is not a certificate.
    let not_x509 = "-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAAAAAA\n-----END CERTIFICATE-----\n";
    let cases: Vec<(Value, &str)> = vec![
        (
            saml_body("s1", &[not_x509.to_owned()]),
            "config.signing_certs",
        ),
        (saml_body("s2", &[]), "config.signing_certs"),
        (
            saml_body("s3", &vec![cert.clone(); 4]),
            "config.signing_certs",
        ),
        (
            {
                let mut b = saml_body("s4", std::slice::from_ref(&cert));
                b["config"]["sso_url"] = json!("http://idp.acme.test/sso");
                b
            },
            "config.sso_url",
        ),
        (
            {
                let mut b = saml_body("s5", std::slice::from_ref(&cert));
                b["config"]["name_id_format"] = json!("transient");
                b
            },
            "config.name_id_format",
        ),
        (
            {
                let mut b = saml_body("s6", std::slice::from_ref(&cert));
                b["config"]["metadata_url"] = json!("http://idp.acme.test/md");
                b
            },
            "config.metadata_url",
        ),
    ];
    for (body, field) in cases {
        let resp = call(&app, Method::POST, &conns("acme"), Some(&t), Some(body)).await;
        assert_field_error(&resp, field);
    }
    // Three certificates (rollover) are fine; a PATCH with a bad certificate is refused too.
    let resp = call(
        &app,
        Method::POST,
        &conns("acme"),
        Some(&t),
        Some(saml_body("ok", &vec![cert.clone(); 3])),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let id = body_json(&resp)["id"].as_str().unwrap().to_owned();
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{}/{id}", conns("acme")),
        Some(&t),
        Some(json!({"config": saml_config(&[not_x509.to_owned()])})),
    )
    .await;
    assert_field_error(&resp, "config.signing_certs");
    assert_eq!(
        app.storage()
            .connections()
            .list(tenant.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------------------------
// Principals and tenant view
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn org_admin_manages_own_connections_only() {
    let app = saml_app().await;
    let tenant = default_tenant(&app);
    let acme = create_org(&app, tenant.id, "acme").await;
    let globex = create_org(&app, tenant.id, "globex").await;
    let role = create_role(&app, tenant.id, Some(acme.id), "org-admins", &["org:admin"]).await;
    let admin = seed_user(&app, tenant.id, "ada@acme.test").await;
    add_member(&app, tenant.id, acme.id, admin.id, &[role.id]).await;
    let token = org_admin_token(&app, &tenant, acme.id, admin.id)
        .await
        .token;

    // Own org: full management, audited as the user.
    let resp = call(
        &app,
        Method::POST,
        &conns("acme"),
        Some(&token),
        Some(oidc_body("acme-entra")),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let own = body_json(&resp)["id"].as_str().unwrap().to_owned();
    let resp = call(&app, Method::GET, &conns("acme"), Some(&token), None).await;
    assert_eq!(resp.status, 200);
    let events = app
        .storage()
        .audit()
        .query(tenant.id, &all_events())
        .await
        .unwrap();
    let created = events
        .items
        .iter()
        .find(|e| e.action == AuditAction::ConnectionCreated)
        .expect("audited");
    assert_eq!(
        created.actor.id.as_deref(),
        Some(admin.id.to_string().as_str())
    );

    // Another org's connection: invisible through the own org, and the other org is refused.
    let sys = write_token(&app).await;
    let resp = call(
        &app,
        Method::POST,
        &conns("globex"),
        Some(&sys),
        Some(oidc_body("globex-entra")),
    )
    .await;
    assert_eq!(resp.status, 201);
    let foreign = body_json(&resp)["id"].as_str().unwrap().to_owned();
    for (m, body) in [
        (Method::GET, None),
        (Method::PATCH, Some(json!({"display_name": "x"}))),
        (Method::DELETE, None),
    ] {
        let resp = call(
            &app,
            m.clone(),
            &format!("{}/{foreign}", conns("acme")),
            Some(&token),
            body.clone(),
        )
        .await;
        assert_problem(&resp, 404);
        let resp = call(
            &app,
            m.clone(),
            &format!("{}/{foreign}", conns("globex")),
            Some(&token),
            body,
        )
        .await;
        assert_problem(&resp, 403);
    }
    let resp = call(
        &app,
        Method::PUT,
        &format!("{}/{foreign}/secret", conns("acme")),
        Some(&token),
        Some(json!({"secret": "x"})),
    )
    .await;
    assert_problem(&resp, 404);
    let resp = call(&app, Method::GET, &conns("globex"), Some(&token), None).await;
    assert_problem(&resp, 403);
    let resp = call(
        &app,
        Method::POST,
        &conns("globex"),
        Some(&token),
        Some(oidc_body("sneaky")),
    )
    .await;
    assert_problem(&resp, 403);
    let resp = call(
        &app,
        Method::POST,
        &format!("{}/saml-metadata", conns("globex")),
        Some(&token),
        Some(json!({"xml": "<x/>"})),
    )
    .await;
    assert_problem(&resp, 403);
    // The tenant-level connection routes stay closed to org admins.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/connections"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 401);
    let stored = app
        .storage()
        .connections()
        .get(tenant.id, ConnectionId(foreign.parse().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.org_id, Some(globex.id));
    assert_eq!(stored.display_name, "Acme Entra");
    let _ = own;
}

#[tokio::test]
async fn tenant_view_reports_saml_availability() {
    for flag in [false, true] {
        let app = app_with(flag).await;
        let t = admin_token(&app, "admin:read").await;
        let resp = call(
            &app,
            Method::GET,
            &format!("{API}/tenants/default"),
            Some(&t),
            None,
        )
        .await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        assert_eq!(body_json(&resp)["features"]["saml"], flag);
        // The system tenant has no organizations, so never SAML.
        let resp = call(
            &app,
            Method::GET,
            &format!("{API}/tenants/system"),
            Some(&t),
            None,
        )
        .await;
        assert_eq!(body_json(&resp)["features"]["saml"], false);
        let resp = call(&app, Method::GET, &format!("{API}/tenants"), Some(&t), None).await;
        let list = body_json(&resp);
        let default = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["slug"] == "default")
            .unwrap()
            .clone();
        assert_eq!(default["features"]["saml"], flag);
    }
}

#[tokio::test]
async fn tenant_settings_expose_org_claim_mapping() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:write").await;
    let path = format!("{API}/tenants/default");
    let resp = call(&app, Method::GET, &path, Some(&t), None).await;
    let claims = body_json(&resp)["settings"]["claims"].clone();
    assert_eq!(claims["org_roles"]["claim"], "org_roles");
    assert_eq!(claims["org_permissions"]["claim"], "org_permissions");
    // Rename, then disable; other rules stay.
    let rule = json!({"claim": "acme_org_roles", "tokens": ["id_token"], "scope": null});
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(json!({"settings": {"claims": {"org_roles": rule}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let claims = body_json(&resp)["settings"]["claims"].clone();
    assert_eq!(claims["org_roles"]["claim"], "acme_org_roles");
    assert_eq!(claims["roles"]["claim"], "roles");
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(json!({"settings": {"claims": {"org_permissions": null}}})),
    )
    .await;
    assert_eq!(
        body_json(&resp)["settings"]["claims"]["org_permissions"],
        Value::Null
    );
    // A reserved name is refused.
    let bad = json!({"claim": "sub", "tokens": ["id_token"]});
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(json!({"settings": {"claims": {"org_roles": bad}}})),
    )
    .await;
    assert_problem(&resp, 422);
}
