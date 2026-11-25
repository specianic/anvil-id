//! Access-token formats per client (`token_format`): RFC 9068 JWTs (`typ: at+jwt`, `aud` =
//! client id, `fid`) and opaque 256-bit tokens stored only as SHA-256. Both work at UserInfo and
//! introspection, on the selected backend (`ANVILID_TEST_DB`).

mod support;
mod token_support;

use std::time::Duration;

use anvil_core::model::{ClientAuthMethod, ClientUpdate, SecretHash, TenantId, TokenFormat};
use anvil_jose::encoding::secret_hash;
use support::{TestApp, json};
use token_support::*;

async fn set_format(app: &TestApp, tenant: TenantId, rp: &Rp, format: TokenFormat) {
    app.storage()
        .clients()
        .update(
            tenant,
            rp.id(),
            &ClientUpdate {
                token_format: Some(format),
                ..ClientUpdate::default()
            },
            app.clock_now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
}

fn field(body: &serde_json::Value, name: &str) -> String {
    body[name].as_str().expect(name).to_owned()
}

async fn introspect(app: &TestApp, rp: &Rp, token: &str) -> serde_json::Value {
    let resp = token_at(app, "/introspect", &rp.auth(), &[("token", token)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    json(&resp)
}

#[tokio::test]
async fn jwt_client_receives_an_rfc9068_access_token() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, "openid email").await;
    let at = field(&body, "access_token");
    assert_eq!(at.split('.').count(), 3, "a compact JWS");
    assert_eq!(jwt_header(&at)["typ"], "at+jwt");
    let claims = jwt_claims(&at);
    assert_eq!(claims["aud"], flow.rp.id());
    assert_eq!(claims["client_id"], flow.rp.id());
    assert_eq!(claims["sub"], flow.user.id.to_string());
    let fid = claims["fid"].as_str().expect("fid").to_owned();
    let family = app
        .storage()
        .grants()
        .get_family(
            flow.tenant,
            anvil_core::service::userinfo::parse_family_id(&fid).expect("uuid"),
        )
        .await
        .expect("family lookup")
        .expect("fid names a stored family");
    assert_eq!(family.client_id, flow.rp.id());
    // Nothing is stored for JWT access tokens.
    assert!(
        app.storage()
            .grants()
            .find_access_token(flow.tenant, &SecretHash(secret_hash(&at)))
            .await
            .expect("lookup")
            .is_none()
    );
    assert_eq!(userinfo_get(&app, &at).await.status, 200);
    let i = introspect(&app, &flow.rp, &at).await;
    assert_eq!(i["active"], true);
    assert_eq!(i["jti"], claims["jti"]);
}

#[tokio::test]
async fn opaque_client_receives_a_random_reference_token() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid email").await;
    set_format(&app, flow.tenant, &flow.rp, TokenFormat::Opaque).await;
    let resp = exchange(&app, &flow.rp, &flow.code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    // Same response shape as for JWT clients.
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 600);
    assert!(body["id_token"].is_string() && body["refresh_token"].is_string());

    let at = field(&body, "access_token");
    assert!(!at.contains('.'), "not a JWT: {at}");
    assert_eq!(at.len(), 43, "256 bits base64url");

    // Stored only as its SHA-256, linked to the family of the code.
    let (record, family) = app
        .storage()
        .grants()
        .find_access_token(flow.tenant, &SecretHash(secret_hash(&at)))
        .await
        .expect("lookup")
        .expect("opaque token stored by hash");
    assert_eq!(record.client_id, flow.rp.id());
    assert_eq!(record.user_id, Some(flow.user.id));
    let family = family.expect("linked to the family");
    assert_eq!(record.family_id, Some(family.id));
    // The ID token's at_hash covers the opaque value.
    let id = jwt_claims(&field(&body, "id_token"));
    assert_eq!(
        id["at_hash"],
        anvil_jose::encoding::at_hash(&at),
        "at_hash of the opaque token"
    );

    let ui = userinfo_get(&app, &at).await;
    assert_eq!(ui.status, 200, "{}", ui.text());
    assert_eq!(json(&ui)["sub"], flow.user.id.to_string());
    assert_eq!(json(&ui)["email"], "ada@example.test");

    let i = introspect(&app, &flow.rp, &at).await;
    assert_eq!(i["active"], true);
    assert_eq!(i["token_type"], "Bearer");
    assert_eq!(i["client_id"], flow.rp.id());
    assert_eq!(i["sub"], flow.user.id.to_string());
    assert!(i.get("jti").is_none());

    // Refreshing keeps the format.
    let resp = refresh(&app, &flow.rp, &field(&body, "refresh_token"), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let at2 = field(&json(&resp), "access_token");
    assert!(!at2.contains('.'));
    assert_ne!(at, at2);
    assert_eq!(userinfo_get(&app, &at2).await.status, 200);
}

#[tokio::test]
async fn opaque_token_expires_after_ten_minutes() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    set_format(&app, flow.tenant, &flow.rp, TokenFormat::Opaque).await;
    let body = json(&exchange(&app, &flow.rp, &flow.code).await);
    let at = field(&body, "access_token");
    assert_eq!(userinfo_get(&app, &at).await.status, 200);
    app.clock().advance(Duration::from_secs(601));
    assert_invalid_token(&userinfo_get(&app, &at).await);
    assert_eq!(
        introspect(&app, &flow.rp, &at).await,
        serde_json::json!({"active": false})
    );
}

#[tokio::test]
async fn opaque_client_credentials_token_has_no_family() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let svc = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    set_format(&app, tenant, &svc, TokenFormat::Opaque).await;
    let resp = token(&app, &svc.auth(), &[("grant_type", "client_credentials")]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let at = field(&json(&resp), "access_token");
    assert!(!at.contains('.'));
    let (record, family) = app
        .storage()
        .grants()
        .find_access_token(tenant, &SecretHash(secret_hash(&at)))
        .await
        .expect("lookup")
        .expect("stored");
    assert!(record.family_id.is_none() && family.is_none() && record.user_id.is_none());

    let i = introspect(&app, &svc, &at).await;
    assert_eq!(i["active"], true);
    assert_eq!(i["sub"], svc.id());
    assert_eq!(i["client_id"], svc.id());
    assert_eq!(i["scope"], "api:read api:write");
    // No user: UserInfo refuses it.
    assert_eq!(userinfo_get(&app, &at).await.status, 403);
}

#[tokio::test]
async fn opaque_token_of_one_tenant_is_unknown_in_another() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    set_format(&app, flow.tenant, &flow.rp, TokenFormat::Opaque).await;
    let at = field(
        &json(&exchange(&app, &flow.rp, &flow.code).await),
        "access_token",
    );
    acme(&app).await;
    assert_invalid_token(&get_with_auth(&app, "/t/acme/userinfo", &format!("Bearer {at}")).await);
}
