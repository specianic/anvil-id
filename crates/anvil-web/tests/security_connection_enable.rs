//! Enabling an upstream connection (C-H6, decision 5 of 07.1) on the selected backend
//! (`ANVILID_TEST_DB`): a connection can always be created, edited, disabled and deleted while
//! it is disabled, but turning it on is refused with 422 naming the missing field until it is
//! complete, and for generic OIDC until `{issuer}/.well-known/openid-configuration` is fetched
//! through the SSRF-guarded upstream port with a matching `issuer`. The rule covers tenant and
//! organization connections. The sign-in page and the link confirmation choices never offer a
//! connection that is enabled but incomplete (rows enabled before this rule, rc.3).
//!
//! No test contacts the internet: discovery targets are local mock servers on loopback (reached
//! with the development outbound policy) or addresses the guard refuses before connecting.

mod admin_support;
mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use admin_support::{API, admin_token, assert_field_error, call, create_org};
use anvil_core::model::{ConnectionConfig, ConnectionId, NewConnection, OidcConfig};
use anvil_core::ports::Clock as _;
use anvil_web::adapters::outbound::OutboundPolicy;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};
use ui_helpers::{default_tenant, register};
use upstream_flow::{
    SLUG, add_connection, form_id, mark_verified, mock_oidc_config, setup, sign_in,
};
use upstream_support::{MOCK_CLIENT_ID, MOCK_EMAIL, MockKind, MockProvider};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET: &str = "enable-check-client-secret-9d1e";

/// The production public URL with the development outbound policy (loopback mocks reachable).
async fn dev_app() -> TestApp {
    TestApp::with(|c| {
        c.rate_limits.enabled = false;
        c.outbound = OutboundPolicy::loopback_dev();
    })
    .await
}

/// The production outbound policy (no allow-list: loopback and private ranges blocked).
async fn production_app() -> TestApp {
    TestApp::with(|c| {
        c.rate_limits.enabled = false;
        c.outbound = OutboundPolicy::default();
    })
    .await
}

fn base() -> String {
    format!("{API}/tenants/default/connections")
}

fn org_base(org: &str) -> String {
    format!("{API}/tenants/default/organizations/{org}/connections")
}

fn oidc_body(slug: &str, issuer: &str, enabled: bool, secret: Option<&str>) -> Value {
    let mut body = json!({
        "slug": slug,
        "display_name": "Acme ID",
        "enabled": enabled,
        "config": {"type": "oidc", "issuer": issuer, "client_id": MOCK_CLIENT_ID},
    });
    if let Some(s) = secret {
        body["secret"] = json!(s);
    }
    body
}

async fn token(app: &TestApp) -> String {
    admin_token(app, "admin:read admin:write").await
}

async fn req(app: &TestApp, t: &str, m: Method, p: &str, body: Option<Value>) -> TestResponse {
    call(app, m, p, Some(t), body).await
}

async fn stored_count(app: &TestApp) -> usize {
    app.storage()
        .connections()
        .list(default_tenant(app).id)
        .await
        .expect("list")
        .len()
}

/// A local discovery server answering `status` with an issuer of `issuer_in_doc` (or the
/// server's own base URL when `None`).
async fn discovery_server(status: u16, issuer_in_doc: Option<&str>) -> MockServer {
    let server = MockServer::start().await;
    let base = server.uri();
    let issuer = issuer_in_doc.map_or_else(|| base.clone(), str::to_owned);
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(status).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })))
        .mount(&server)
        .await;
    server
}

fn error_text(resp: &TestResponse) -> String {
    resp.text().to_owned()
}

#[tokio::test]
async fn create_enabled_without_secret_is_refused_and_stores_nothing() {
    let app = dev_app().await;
    let t = token(&app).await;
    let mock = MockProvider::start(MockKind::Oidc).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(oidc_body("acme", &mock.issuer(), true, None)),
    )
    .await;
    assert_field_error(&resp, "secret");
    assert_eq!(stored_count(&app).await, 0, "nothing is written");
    assert_eq!(
        mock.request_count("/.well-known/openid-configuration")
            .await,
        0,
        "an incomplete connection is refused before anything is fetched"
    );

    // The API default stays enabled = true: omitting the field is the same refusal.
    let mut body = oidc_body("acme", &mock.issuer(), true, None);
    body.as_object_mut().unwrap().remove("enabled");
    let resp = req(&app, &t, Method::POST, &base(), Some(body)).await;
    assert_field_error(&resp, "secret");
}

#[tokio::test]
async fn discovery_failure_or_issuer_mismatch_refuses_enable() {
    let app = dev_app().await;
    let t = token(&app).await;

    let missing = discovery_server(404, None).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(oidc_body("gone", &missing.uri(), true, Some(SECRET))),
    )
    .await;
    assert_field_error(&resp, "config.issuer");
    assert!(error_text(&resp).contains("HTTP 404"), "{}", resp.text());

    let mismatch = discovery_server(200, Some("https://other-issuer.example.test")).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(oidc_body("mismatch", &mismatch.uri(), true, Some(SECRET))),
    )
    .await;
    assert_field_error(&resp, "config.issuer");
    assert!(
        error_text(&resp).contains("does not equal"),
        "{}",
        resp.text()
    );
    assert!(
        !error_text(&resp).contains("other-issuer"),
        "fetched content is never echoed: {}",
        resp.text()
    );
    assert_eq!(stored_count(&app).await, 0);
}

#[tokio::test]
async fn reachable_matching_issuer_with_secret_is_created_enabled() {
    let app = dev_app().await;
    let t = token(&app).await;
    let mock = MockProvider::start(MockKind::Oidc).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(oidc_body("acme", &mock.issuer(), true, Some(SECRET))),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(body_json(&resp)["enabled"], true);
    assert!(
        mock.request_count("/.well-known/openid-configuration")
            .await
            >= 1
    );
}

#[tokio::test]
async fn disabled_connection_can_be_created_edited_disabled_and_deleted_but_not_enabled_while_incomplete()
 {
    let app = dev_app().await;
    let t = token(&app).await;
    let mock = MockProvider::start(MockKind::Oidc).await;

    // Created disabled and incomplete: fine.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(oidc_body("acme", &mock.issuer(), false, None)),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let created = body_json(&resp);
    assert_eq!(created["enabled"], false);
    let item = format!("{}/{}", base(), created["id"].as_str().unwrap());

    // Edited while disabled: fine.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &item,
        Some(json!({"display_name": "Acme Sign-In"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    // Enabling while the secret is missing: refused, nothing changes.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &item,
        Some(json!({"enabled": true})),
    )
    .await;
    assert_field_error(&resp, "secret");
    let stored = app
        .storage()
        .connections()
        .get_by_slug(default_tenant(&app).id, "acme")
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.enabled);

    // With the secret, the issuer check passes and the connection turns on.
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{item}/secret"),
        Some(json!({"secret": SECRET})),
    )
    .await;
    assert!(resp.status.is_success(), "{}", resp.text());
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &item,
        Some(json!({"enabled": true})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["enabled"], true);

    // Moving an enabled connection to an issuer that fails discovery is refused too.
    let missing = discovery_server(404, None).await;
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &item,
        Some(json!({"config": {"type": "oidc", "issuer": missing.uri(), "client_id": "x"}})),
    )
    .await;
    assert_field_error(&resp, "config.issuer");

    // Disabling and deleting always work.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &item,
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = req(&app, &t, Method::DELETE, &item, None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
}

#[tokio::test]
async fn organization_connection_follows_the_same_rule() {
    let app = dev_app().await;
    let t = token(&app).await;
    create_org(&app, default_tenant(&app).id, "acme").await;
    let mock = MockProvider::start(MockKind::Oidc).await;

    let resp = req(
        &app,
        &t,
        Method::POST,
        &org_base("acme"),
        Some(oidc_body("acme-sso", &mock.issuer(), true, None)),
    )
    .await;
    assert_field_error(&resp, "secret");

    let missing = discovery_server(404, None).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &org_base("acme"),
        Some(oidc_body("acme-sso", &missing.uri(), true, Some(SECRET))),
    )
    .await;
    assert_field_error(&resp, "config.issuer");

    let resp = req(
        &app,
        &t,
        Method::POST,
        &org_base("acme"),
        Some(oidc_body("acme-sso", &mock.issuer(), false, None)),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let item = format!(
        "{}/{}",
        org_base("acme"),
        body_json(&resp)["id"].as_str().unwrap()
    );
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &item,
        Some(json!({"enabled": true})),
    )
    .await;
    assert_field_error(&resp, "secret");
    let resp = req(&app, &t, Method::DELETE, &item, None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
}

#[tokio::test]
async fn connection_check_refuses_private_address() {
    let app = production_app().await;
    let t = token(&app).await;

    // A private address: refused by the guard before any connection is made.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(oidc_body(
            "internal",
            "https://10.0.0.1",
            true,
            Some(SECRET),
        )),
    )
    .await;
    assert_field_error(&resp, "config.issuer");
    assert!(error_text(&resp).contains("not allowed"), "{}", resp.text());
    assert!(!error_text(&resp).contains("10.0.0.1"), "{}", resp.text());

    // A live loopback server serving a valid document: still refused in production, nothing
    // is fetched and nothing of the document is echoed.
    let local = discovery_server(200, None).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &base(),
        Some(oidc_body("loopback", &local.uri(), true, Some(SECRET))),
    )
    .await;
    assert_field_error(&resp, "config.issuer");
    assert!(error_text(&resp).contains("not allowed"), "{}", resp.text());
    assert!(!error_text(&resp).contains("/authorize"), "{}", resp.text());
    assert!(
        local
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the guard refuses before connecting"
    );
    assert_eq!(stored_count(&app).await, 0);
}

/// An enabled generic OIDC connection without a secret, written through the storage trait as an
/// rc.3 deployment could have it.
async fn rc3_incomplete_row(app: &TestApp, slug: &str, issuer: &str) {
    app.storage()
        .connections()
        .create(
            default_tenant(app).id,
            &NewConnection {
                id: ConnectionId::new_v7(),
                org_id: None,
                slug: slug.into(),
                display_name: "Broken ID".into(),
                enabled: true,
                config: ConnectionConfig::Oidc(OidcConfig {
                    issuer: issuer.into(),
                    client_id: MOCK_CLIENT_ID.into(),
                    scopes: vec![],
                    use_pkce: true,
                    fetch_userinfo: false,
                }),
                secret_enc: None,
                trust_email_verified: false,
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("store the incomplete connection");
}

#[tokio::test]
async fn incomplete_connection_not_offered_on_sign_in() {
    // Untrusted connection + a verified local account with the upstream email: the unrevealed
    // link confirmation page, which offers the tenant's other connections.
    let u = setup(false).await;
    add_connection(
        &u.app,
        "other-id",
        "Other ID",
        mock_oidc_config(&u.mock),
        false,
    )
    .await;
    rc3_incomplete_row(&u.app, "broken-id", &u.mock.issuer()).await;

    // The sign-in page lists the complete connections only.
    let page = u.app.get("/ui/login").await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(
        html.contains(&format!("id=\"upstream-{SLUG}-form\"")),
        "{html}"
    );
    assert!(html.contains("id=\"upstream-other-id-form\""), "{html}");
    assert!(
        !html.contains("upstream-broken-id"),
        "an enabled connection without its secret is never offered: {html}"
    );

    // The link confirmation choices follow the same rule.
    register(&u.app, "", MOCK_EMAIL, "correct horse battery").await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    assert!(html.contains("id=\"upstream-other-id-form\""), "{html}");
    assert!(!html.contains("upstream-broken-id"), "{html}");
}
