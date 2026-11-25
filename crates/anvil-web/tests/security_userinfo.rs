//! UserInfo token-confusion and revocation controls: no query tokens, no ID tokens, no other
//! tenant's tokens, no client-credentials tokens, no expired tokens, no revoked families, no
//! blocked users, and RFC 6750 error signalling.
//!
//! Documented choice: a client-credentials access token never carries `openid` (the token
//! endpoint refuses it), so UserInfo answers it with **403 `insufficient_scope`**. A
//! client-credentials token that somehow carried `openid` would still be refused with 401
//! `invalid_token` (no user family) by `userinfo_requirements` in anvil-core.

mod support;
mod token_support;

use std::time::Duration;

use anvil_core::model::ClientAuthMethod;
use support::{TestApp, json};
use token_support::*;

fn at(body: &serde_json::Value) -> String {
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

#[tokio::test]
async fn token_in_the_query_is_refused() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid").await;
    let resp = app
        .get(&format!("/userinfo?access_token={}", at(&body)))
        .await;
    assert_invalid_token(&resp);
}

#[tokio::test]
async fn header_and_body_together_are_invalid_request() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid").await;
    let token = at(&body);
    let resp = post_raw(
        &app,
        "/userinfo",
        Some(&format!("Bearer {token}")),
        &[("access_token", &token)],
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(json(&resp)["error"], "invalid_request");
}

#[tokio::test]
async fn missing_token_is_401() {
    let app = TestApp::new().await;
    assert_invalid_token(&app.get("/userinfo").await);
}

#[tokio::test]
async fn id_token_is_not_an_access_token() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid").await;
    let id_token = body["id_token"].as_str().expect("id_token");
    assert_invalid_token(&userinfo_get(&app, id_token).await);
}

#[tokio::test]
async fn other_tenants_token_is_refused() {
    let app = TestApp::new().await;
    let acme = acme(&app).await;
    let rp = register(
        &app,
        acme.id,
        web_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let user = seed_user(&app, acme.id, "ada@example.test").await;
    let session = seed_session(&app, acme.id, &user).await;
    let code = issue_code(
        &app,
        acme.id,
        &rp,
        &session,
        &params("openid", Some(CHALLENGE)),
    )
    .await;
    let resp = token_at(
        &app,
        "/t/acme/token",
        &rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let token = at(&json(&resp));
    assert_invalid_token(&userinfo_get(&app, &token).await);
}

#[tokio::test]
async fn client_credentials_token_is_refused_with_insufficient_scope() {
    let app = TestApp::new().await;
    let rp = register(
        &app,
        default_tenant(&app),
        cc_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let resp = token(&app, &rp.auth(), &[("grant_type", "client_credentials")]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = userinfo_get(&app, &at(&json(&resp))).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(json(&resp)["error"], "insufficient_scope");
    assert_eq!(
        resp.header("www-authenticate"),
        Some("Bearer error=\"insufficient_scope\"")
    );
}

#[tokio::test]
async fn token_without_openid_is_insufficient_scope() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "profile").await;
    let resp = userinfo_get(&app, &at(&body)).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(json(&resp)["error"], "insufficient_scope");
}

#[tokio::test]
async fn expired_token_is_refused() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid").await;
    let token = at(&body);
    assert_eq!(userinfo_get(&app, &token).await.status, 200);
    app.clock().advance(Duration::from_secs(11 * 60));
    assert_invalid_token(&userinfo_get(&app, &token).await);
}

#[tokio::test]
async fn token_of_a_revoked_family_is_refused() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, "openid").await;
    let token = at(&body);
    assert_eq!(userinfo_get(&app, &token).await.status, 200);
    // Code reuse revokes the family the token belongs to.
    assert_oauth_error(
        &exchange(&app, &flow.rp, &flow.code).await,
        400,
        "invalid_grant",
    );
    assert_invalid_token(&userinfo_get(&app, &token).await);
}

#[tokio::test]
async fn blocked_user_is_refused() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, "openid").await;
    let token = at(&body);
    app.storage()
        .users()
        .update(
            flow.tenant,
            flow.user.id,
            &anvil_core::model::UserUpdate {
                status: Some(anvil_core::model::UserStatus::Blocked),
                ..Default::default()
            },
            app.clock_now(),
        )
        .await
        .expect("update")
        .expect("user exists");
    assert_invalid_token(&userinfo_get(&app, &token).await);
}

#[tokio::test]
async fn malformed_and_tampered_bearers_are_refused() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid").await;
    let token = at(&body);
    for auth in [
        "Bearer".to_owned(),
        "Bearer not-a-jwt".to_owned(),
        "Basic YTpi".to_owned(),
        format!("Bearer {token} extra"),
    ] {
        assert_invalid_token(&get_with_auth(&app, "/userinfo", &auth).await);
    }
    // Flip the last signature character.
    let mut tampered = token.clone();
    let last = tampered.pop().expect("non-empty");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert_invalid_token(&userinfo_get(&app, &tampered).await);
}
