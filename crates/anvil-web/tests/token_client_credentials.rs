//! `grant_type=client_credentials` and grant-type errors at `POST /token`.

mod support;
mod token_support;

use anvil_core::model::ClientAuthMethod;
use anvil_jose::jws::verify_jwt;
use anvil_jose::keys::Alg;
use support::{TestApp, json};
use token_support::*;

#[tokio::test]
async fn confidential_client_gets_an_access_token_only() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    let resp = token(&app, &rp.auth(), &[("grant_type", "client_credentials")]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let body = json(&resp);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "api:read api:write");
    assert!(body.get("refresh_token").is_none(), "{body}");
    assert!(body.get("id_token").is_none(), "{body}");

    let at = body["access_token"].as_str().expect("access_token");
    assert_eq!(jwt_header(at)["typ"], "at+jwt");
    let jwks = published(&app, tenant).await;
    let v = verify_jwt(at, &jwks, &[Alg::RS256]).expect("AT verifies");
    assert_eq!(v.claims["sub"], rp.id());
    assert_eq!(v.claims["client_id"], rp.id());
    assert!(v.claims.get("fid").is_none());
}

#[tokio::test]
async fn requested_scope_is_honoured_within_the_registration() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretPost)).await;
    let resp = token(
        &app,
        &rp.auth(),
        &[("grant_type", "client_credentials"), ("scope", "api:read")],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(json(&resp)["scope"], "api:read");

    let resp = token(
        &app,
        &rp.auth(),
        &[("grant_type", "client_credentials"), ("scope", "api:admin")],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_scope");
}

#[tokio::test]
async fn openid_scope_is_rejected() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    let resp = token(
        &app,
        &rp.auth(),
        &[("grant_type", "client_credentials"), ("scope", "openid")],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_scope");
}

#[tokio::test]
async fn public_client_is_unauthorized() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, public_input()).await;
    let resp = token(&app, &rp.auth(), &[("grant_type", "client_credentials")]).await;
    assert_oauth_error(&resp, 400, "unauthorized_client");
}

#[tokio::test]
async fn code_client_without_the_grant_is_unauthorized() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    let resp = token(&app, &rp.auth(), &[("grant_type", "client_credentials")]).await;
    assert_oauth_error(&resp, 400, "unauthorized_client");
}

#[tokio::test]
async fn cc_client_cannot_use_the_code_grant() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    let resp = token(
        &app,
        &rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", "x"),
            ("redirect_uri", REDIRECT),
        ],
    )
    .await;
    assert_oauth_error(&resp, 400, "unauthorized_client");
}

#[tokio::test]
async fn unsupported_and_missing_grant_types() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    for grant in [
        "password",
        "implicit",
        "urn:ietf:params:oauth:grant-type:device_code",
    ] {
        let resp = token(
            &app,
            &rp.auth(),
            &[("grant_type", grant), ("username", "a"), ("password", "b")],
        )
        .await;
        assert_oauth_error(&resp, 400, "unsupported_grant_type");
    }
    let resp = token(&app, &rp.auth(), &[]).await;
    assert_oauth_error(&resp, 400, "invalid_request");
}
