//! Refresh-token security controls at `POST /token`: rotation, reuse detection with family
//! revocation, client binding without collateral revocation, no scope widening, idle expiry and
//! the refreshed ID token (same auth_time, no nonce).

mod support;
mod token_support;

use std::time::Duration;

use anvil_core::model::ClientAuthMethod;
use support::{TestApp, json};
use token_support::*;

const SCOPE: &str = "openid profile email";

fn rt(body: &serde_json::Value) -> String {
    body["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned()
}

#[tokio::test]
async fn rotation_issues_a_new_refresh_token() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let old = rt(&body);
    let resp = refresh(&app, &flow.rp, &old, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let new = rt(&json(&resp));
    assert_ne!(old, new);
    assert_eq!(json(&resp)["scope"], "email openid profile");
}

#[tokio::test]
async fn reuse_revokes_the_whole_family() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let old = rt(&body);
    let resp = refresh(&app, &flow.rp, &old, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let new = rt(&json(&resp));

    assert_oauth_error(
        &refresh(&app, &flow.rp, &old, None).await,
        400,
        "invalid_grant",
    );
    // The newest token of the family is dead too.
    assert_oauth_error(
        &refresh(&app, &flow.rp, &new, None).await,
        400,
        "invalid_grant",
    );
}

#[tokio::test]
async fn another_clients_refresh_token_is_rejected_without_revocation() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let a_rt = rt(&body);
    let b = register(
        &app,
        flow.tenant,
        web_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;

    assert_oauth_error(&refresh(&app, &b, &a_rt, None).await, 400, "invalid_grant");
    // Client A's token is untouched.
    let resp = refresh(&app, &flow.rp, &a_rt, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn scope_widening_is_rejected() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let old = rt(&body);
    let resp = refresh(&app, &flow.rp, &old, Some("openid admin")).await;
    assert_oauth_error(&resp, 400, "invalid_scope");
    let resp = refresh(&app, &flow.rp, &old, Some("openid phone")).await;
    assert_oauth_error(&resp, 400, "invalid_scope");

    // Narrowing is allowed and the token was not consumed by the rejected requests.
    let resp = refresh(&app, &flow.rp, &old, Some("openid email")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(json(&resp)["scope"], "email openid");
}

#[tokio::test]
async fn idle_expired_refresh_token_is_rejected() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    app.clock().advance(Duration::from_secs(14 * 24 * 3600 + 1));
    assert_oauth_error(
        &refresh(&app, &flow.rp, &rt(&body), None).await,
        400,
        "invalid_grant",
    );
}

#[tokio::test]
async fn unknown_refresh_token_is_rejected() {
    let app = TestApp::new().await;
    let (flow, _) = tokens(&app, SCOPE).await;
    assert_oauth_error(
        &refresh(&app, &flow.rp, "not-a-refresh-token", None).await,
        400,
        "invalid_grant",
    );
}

#[tokio::test]
async fn refreshed_id_token_keeps_auth_time_and_drops_nonce() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let original = jwt_claims(body["id_token"].as_str().expect("id_token"));
    assert_eq!(original["nonce"], NONCE);

    app.clock().advance(Duration::from_secs(300));
    let resp = refresh(&app, &flow.rp, &rt(&body), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let refreshed = json(&resp);
    let id_token = refreshed["id_token"].as_str().expect("refreshed id_token");
    let c = jwt_claims(id_token);
    assert_eq!(c["auth_time"], original["auth_time"]);
    assert!(c.get("nonce").is_none(), "{c}");
    assert_eq!(c["sub"], original["sub"]);
    assert!(c["iat"].as_i64() > original["iat"].as_i64());
    let jwks = published(&app, flow.tenant).await;
    anvil_jose::jws::verify_jwt(id_token, &jwks, &[anvil_jose::keys::Alg::RS256])
        .expect("refreshed id_token verifies");
}

#[tokio::test]
async fn client_without_the_refresh_grant_cannot_refresh() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, SCOPE).await;
    let code_only = register(
        &app,
        flow.tenant,
        anvil_core::service::client::ClientInput {
            grant_types: vec![anvil_core::model::GrantType::AuthorizationCode],
            ..web_input(ClientAuthMethod::ClientSecretBasic)
        },
    )
    .await;
    let resp = refresh(&app, &code_only, &rt(&body), None).await;
    assert_oauth_error(&resp, 400, "unauthorized_client");
}
