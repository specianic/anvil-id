//! Authorization-code security controls at `POST /token`: single use with family revocation,
//! 60 s lifetime, client binding, redirect_uri binding and PKCE (including downgrade).

mod support;
mod token_support;

use std::time::Duration;

use anvil_core::model::ClientAuthMethod;
use anvil_core::service::client::ClientInput;
use support::{TestApp, json};
use token_support::*;

async fn exchange_with(app: &TestApp, rp: &Rp, pairs: &[(&str, &str)]) -> support::TestResponse {
    let mut all = vec![("grant_type", "authorization_code")];
    all.extend_from_slice(pairs);
    token(app, &rp.auth(), &all).await
}

#[tokio::test]
async fn code_reuse_is_rejected_and_revokes_the_family() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid profile").await;
    let first = exchange(&app, &flow.rp, &flow.code).await;
    assert_eq!(first.status, 200, "{}", first.text());
    let first = json(&first);

    let second = exchange(&app, &flow.rp, &flow.code).await;
    assert_oauth_error(&second, 400, "invalid_grant");

    // Everything issued from the first exchange is now dead: the refresh token...
    let rt = first["refresh_token"].as_str().expect("refresh token");
    assert_oauth_error(
        &refresh(&app, &flow.rp, rt, None).await,
        400,
        "invalid_grant",
    );
}

#[tokio::test]
async fn expired_code_is_rejected() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    app.clock().advance(Duration::from_secs(61));
    assert_oauth_error(
        &exchange(&app, &flow.rp, &flow.code).await,
        400,
        "invalid_grant",
    );
}

#[tokio::test]
async fn code_issued_to_another_client_is_rejected() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    let other = register(
        &app,
        flow.tenant,
        web_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    assert_oauth_error(
        &exchange(&app, &other, &flow.code).await,
        400,
        "invalid_grant",
    );
    // The burned code cannot be redeemed by its owner afterwards either.
    assert_oauth_error(
        &exchange(&app, &flow.rp, &flow.code).await,
        400,
        "invalid_grant",
    );
}

#[tokio::test]
async fn mismatched_redirect_uri_is_rejected() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    let resp = exchange_with(
        &app,
        &flow.rp,
        &[
            ("code", &flow.code),
            ("redirect_uri", "https://rp.test/other"),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_grant");
}

#[tokio::test]
async fn missing_redirect_uri_is_rejected() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    let resp = exchange_with(
        &app,
        &flow.rp,
        &[("code", &flow.code), ("code_verifier", VERIFIER)],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_grant");
}

#[tokio::test]
async fn challenge_without_verifier_is_rejected() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    let resp = exchange_with(
        &app,
        &flow.rp,
        &[("code", &flow.code), ("redirect_uri", REDIRECT)],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_grant");
}

#[tokio::test]
async fn wrong_verifier_is_rejected() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    let resp = exchange_with(
        &app,
        &flow.rp,
        &[
            ("code", &flow.code),
            ("redirect_uri", REDIRECT),
            (
                "code_verifier",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_grant");
}

/// A confidential client that opted out of PKCE gets a code without a challenge; sending a
/// verifier for it anyway is a downgrade attempt (RFC 9700 §4.8.2).
#[tokio::test]
async fn verifier_without_challenge_is_rejected() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(
        &app,
        tenant,
        ClientInput {
            require_pkce: Some(false),
            ..web_input(ClientAuthMethod::ClientSecretBasic)
        },
    )
    .await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let session = seed_session(&app, tenant, &user).await;

    let code = issue_code(&app, tenant, &rp, &session, &params("openid", None)).await;
    let resp = exchange_with(
        &app,
        &rp,
        &[
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_grant");

    // Positive control: the same client without a verifier succeeds.
    let code = issue_code(&app, tenant, &rp, &session, &params("openid", None)).await;
    let resp = exchange_with(&app, &rp, &[("code", &code), ("redirect_uri", REDIRECT)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn unknown_code_is_rejected() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
    let resp = exchange(&app, &flow.rp, "not-a-real-code").await;
    assert_oauth_error(&resp, 400, "invalid_grant");
}

#[tokio::test]
async fn blocked_user_cannot_exchange_a_code() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "openid").await;
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
    assert_oauth_error(
        &exchange(&app, &flow.rp, &flow.code).await,
        400,
        "invalid_grant",
    );
}
