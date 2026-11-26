//! Tenant isolation at the authorization endpoint: a client is only known in its own tenant.
//! Also the unknown-host negative cache (05-18): only misses are cached, for the configured TTL;
//! client and tenant deletion take effect on the very next request.

mod authz;
mod support;
mod token_support;

use std::time::Duration;

use anvil_core::model::{ClientAuthMethod, NewTenant, TenantId, TenantSettings};
use authz::*;
use axum::body::Body;
use axum::http::Request;
use support::{TestApp, json};

#[tokio::test]
async fn client_of_another_tenant_is_unknown() {
    let app = TestApp::new().await;
    let acme = path_tenant(&app, "acme").await;
    let c = web_client(&app, &acme).await;
    let p = pkce_params(&c.client_id);

    let resp = get(&app, &authorize_path("", &p), None).await;
    assert_error_page(&resp, "unknown_client");

    // Sanity: the same request works in its own tenant.
    let resp = get(&app, &authorize_path("/t/acme", &p), None).await;
    assert_login_redirect(&resp, "https://op.test/t/acme");
}

#[tokio::test]
async fn session_of_another_tenant_is_not_used() {
    let app = TestApp::new().await;
    let def = default_tenant(&app);
    let acme = path_tenant(&app, "acme").await;
    let c = web_client(&app, &acme).await;
    let u = user(&app, &def, "alice@example.com").await;
    // A default-tenant session cookie, presented under acme's cookie name.
    let cookie = session(&app, &def, u).await;
    let token = cookie.split_once('=').expect("cookie").1;
    let acme_name = anvil_web::cookies::CookiePolicy::new(true).session_name(&acme);
    let forged = format!("{acme_name}={token}");

    let mut p = pkce_params(&c.client_id);
    p.push(("prompt", "none"));
    let resp = get(&app, &authorize_path("/t/acme", &p), Some(&forged)).await;
    assert_error_redirect(&resp, RP, "login_required", "https://op.test/t/acme");
}

const HOST: &str = "login.acme.test";

/// The issuer of the discovery document served for `Host: host`.
async fn issuer_at(app: &TestApp, host: &str) -> String {
    let req = Request::get("/.well-known/openid-configuration")
        .header("host", host)
        .body(Body::empty())
        .expect("request");
    let resp = app.send(req).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    json(&resp)["issuer"].as_str().expect("issuer").to_owned()
}

async fn host_tenant(app: &TestApp, slug: &str, host: &str) -> TenantId {
    app.storage()
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: slug.into(),
            display_name: slug.into(),
            host: Some(host.into()),
            settings: TenantSettings::default(),
            created_at: support::start_time(),
        })
        .await
        .expect("create host tenant")
        .id
}

#[tokio::test]
async fn unknown_host_miss_is_cached_until_the_ttl_expires() {
    let app = TestApp::with(|c| c.unknown_host_ttl = Duration::from_millis(200)).await;
    // Unknown host: the request falls through to the default tenant at the root.
    assert_eq!(issuer_at(&app, HOST).await, "https://op.test");

    // The host becomes a tenant host. Within the TTL the cached miss is still served, which
    // proves the second request did not look the host up again.
    host_tenant(&app, "acme", HOST).await;
    assert_eq!(issuer_at(&app, HOST).await, "https://op.test");

    // After the TTL (moka expiry uses real time, not the app clock) it resolves.
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(issuer_at(&app, HOST).await, format!("https://{HOST}"));
}

#[tokio::test]
async fn found_host_tenants_are_never_cached_and_deletion_is_immediate() {
    // Default (5 s) TTL: a deleted host tenant must still stop resolving at once.
    let app = TestApp::new().await;
    let id = host_tenant(&app, "acme", HOST).await;
    assert_eq!(issuer_at(&app, HOST).await, format!("https://{HOST}"));
    assert_eq!(issuer_at(&app, HOST).await, format!("https://{HOST}"));

    assert!(app.storage().tenants().delete(id).await.expect("delete"));
    assert_eq!(issuer_at(&app, HOST).await, "https://op.test");
}

#[tokio::test]
async fn deleted_path_tenant_is_unreachable_immediately() {
    let app = TestApp::new().await;
    let acme = path_tenant(&app, "acme").await;
    let doc = "/t/acme/.well-known/openid-configuration";
    assert_eq!(app.get(doc).await.status, 200);
    assert!(
        app.storage()
            .tenants()
            .delete(acme.id)
            .await
            .expect("delete")
    );
    assert_eq!(app.get(doc).await.status, 404);
}

#[tokio::test]
async fn deleted_client_is_rejected_on_the_next_token_request() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app).id;
    let rp = token_support::register(
        &app,
        tenant,
        token_support::cc_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let grant = [("grant_type", "client_credentials")];
    for _ in 0..2 {
        let resp = token_support::token(&app, &rp.auth(), &grant).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
    }
    assert!(
        app.storage()
            .clients()
            .delete(tenant, rp.id())
            .await
            .expect("delete")
    );
    let resp = token_support::token(&app, &rp.auth(), &grant).await;
    token_support::assert_oauth_error(&resp, 401, "invalid_client");
}
