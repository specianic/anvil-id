//! Tenant isolation at the authorization endpoint: a client is only known in its own tenant.

mod authz;
mod support;

use authz::*;
use support::TestApp;

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
