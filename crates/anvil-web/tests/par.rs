//! Pushed authorization requests (RFC 9126, OIDC-18) end to end: push, authorize with the
//! `request_uri`, code, token, for every client authentication method and a public PKCE client.
//! The negative tests live in `security_par.rs`.

mod authz;
mod par_support;
mod support;
mod token_support;

use std::time::Duration;

use anvil_core::model::ClientAuthMethod;
use anvil_core::model::{NewPushedRequest, SecretHash};
use anvil_core::ports::Clock;
use anvil_core::ports::StorageError;
use anvil_jose::encoding::secret_hash;
use par_support::*;
use support::{TestApp, json};
use token_support::{REDIRECT, jwt_claims};

/// Push, authorize with a session, exchange the code; the ID token carries the pushed nonce.
async fn happy_path(method: ClientAuthMethod) {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, method).await;
    let cookie = signed_in(&app, "ada@example.test").await;

    let request_uri = push_default(&app, &client).await;
    let resp = authorize(&app, client.id(), &request_uri, &[], Some(&cookie)).await;
    let code = code_of(&resp, &iss);

    let resp = exchange(&app, &client, &code).await;
    assert_eq!(resp.status, 200, "{method:?}: {}", resp.text());
    let body = json(&resp);
    let id_token = body["id_token"].as_str().expect("id_token");
    let claims = jwt_claims(id_token);
    assert_eq!(claims["nonce"], token_support::NONCE);
    assert_eq!(claims["aud"], serde_json::json!([client.id()]));
    assert_eq!(claims["iss"], iss);
}

#[tokio::test]
async fn par_client_secret_basic_happy_path() {
    happy_path(ClientAuthMethod::ClientSecretBasic).await;
}

#[tokio::test]
async fn par_client_secret_post_happy_path() {
    happy_path(ClientAuthMethod::ClientSecretPost).await;
}

#[tokio::test]
async fn par_private_key_jwt_happy_path() {
    happy_path(ClientAuthMethod::PrivateKeyJwt).await;
}

#[tokio::test]
async fn par_public_pkce_client_happy_path() {
    happy_path(ClientAuthMethod::None).await;
}

#[tokio::test]
async fn par_basic_client_may_repeat_its_client_id_in_the_body() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let mut pairs = pushed_params();
    let id = client.id().to_owned();
    pairs.push(("client_id", &id));
    push_ok(&app, &client.auth(&app.issuer(None)), &pairs).await;
}

#[tokio::test]
async fn par_front_channel_parameters_are_ignored() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;
    let request_uri = push_default(&app, &client).await;

    let resp = authorize(
        &app,
        client.id(),
        &request_uri,
        &[
            ("redirect_uri", "https://evil.example/cb"),
            ("state", "front-channel-state"),
            ("scope", "openid email"),
            ("response_mode", "form_post"),
            ("prompt", "none"),
            ("code_challenge", "x"),
        ],
        Some(&cookie),
    )
    .await;
    // The pushed redirect URI, state and query mode are used; nothing from the query.
    let code = code_of(&resp, &iss);
    let resp = exchange(&app, &client, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(json(&resp)["scope"], "openid profile");
}

#[tokio::test]
async fn par_without_session_goes_through_login_and_continue() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let request_uri = push_default(&app, &client).await;

    let resp = authorize(&app, client.id(), &request_uri, &[], None).await;
    let request_id = authz::assert_login_redirect(&resp, &iss);

    // The login flow signs the user in, then continues the stored request.
    let cookie = signed_in(&app, "ada@example.test").await;
    let resp = authz::get(
        &app,
        &format!("/authorize/continue?request={request_id}"),
        Some(&cookie),
    )
    .await;
    let code = code_of(&resp, &iss);
    let resp = exchange(&app, &client, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn par_pushed_prompt_none_without_session_answers_at_the_redirect_uri() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let mut pairs = pushed_params();
    pairs.push(("prompt", "none"));
    let request_uri = push_ok(&app, &client.auth(&iss), &pairs).await;
    let resp = authorize(&app, client.id(), &request_uri, &[], None).await;
    authz::assert_error_redirect(&resp, REDIRECT, "login_required", &iss);
    assert_eq!(
        authz::param(&resp, "state").as_deref(),
        Some("pushed-state")
    );
}

#[tokio::test]
async fn par_post_authorize_accepts_a_request_uri() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;
    let request_uri = push_default(&app, &client).await;
    let resp = authz::post(
        &app,
        "/authorize",
        &[("client_id", client.id()), ("request_uri", &request_uri)],
        Some(&cookie),
    )
    .await;
    code_of(&resp, &iss);
}

#[tokio::test]
async fn par_path_tenant_endpoint_is_served() {
    let app = TestApp::new().await;
    let resp = app
        .post_form("/t/default/par", &[("response_type", "code")])
        .await;
    // Served (client authentication fails), not the 404 fallback.
    assert_eq!(resp.status, 401, "{}", resp.text());
    assert_eq!(json(&resp)["error"], "invalid_client");
    assert!(resp.header("access-control-allow-origin").is_none());
}

/// Re-inserting a pushed request under the same hash conflicts while the row exists.
async fn row_exists(app: &TestApp, request_uri: &str, client_id: &str) -> bool {
    let hash = SecretHash(secret_hash(request_uri));
    let now = app.clock().now();
    let attempt = app
        .storage()
        .grants()
        .create_pushed_request(
            authz::default_tenant(app).id,
            &NewPushedRequest {
                request_uri_hash: hash,
                client_id: client_id.to_owned(),
                params: serde_json::json!({}),
                created_at: now,
                expires_at: now,
            },
        )
        .await;
    match attempt {
        Err(StorageError::Conflict(_)) => true,
        Ok(()) => false,
        Err(e) => panic!("unexpected storage error: {e}"),
    }
}

#[tokio::test]
async fn par_expired_rows_are_purged() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let request_uri = push_default(&app, &client).await;

    app.storage()
        .purge_expired(app.clock().now())
        .await
        .expect("purge");
    assert!(
        row_exists(&app, &request_uri, client.id()).await,
        "a live pushed request is kept"
    );

    app.clock().advance(Duration::from_secs(61));
    let purged = app
        .storage()
        .purge_expired(app.clock().now())
        .await
        .expect("purge");
    assert!(purged >= 1, "{purged}");
    assert!(
        !row_exists(&app, &request_uri, client.id()).await,
        "the expired pushed request is gone"
    );
}

#[tokio::test]
async fn par_response_carries_no_redirect() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let resp = push(&app, &client.auth(&app.issuer(None)), &pushed_params()).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert!(resp.headers.get("location").is_none());
}
