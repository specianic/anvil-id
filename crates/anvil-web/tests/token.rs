//! `POST /token` happy paths: authorization_code with client_secret_basic and client_secret_post,
//! the ID token and access token contents, refresh token issuance and HTTP details.

mod support;
mod token_support;

use anvil_core::model::{ClientAuthMethod, GrantType};
use anvil_jose::encoding::at_hash;
use anvil_jose::jws::verify_jwt;
use anvil_jose::keys::Alg;
use support::{TestApp, json, start_time};
use token_support::*;

const SCOPE: &str = "openid profile email offline_access";

#[tokio::test]
async fn code_exchange_with_basic_returns_verified_tokens() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, SCOPE).await;
    let resp = exchange(&app, &flow.rp, &flow.code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.header("pragma"), Some("no-cache"));
    assert!(
        resp.header("content-type")
            .is_some_and(|c| c.starts_with("application/json"))
    );
    let body = json(&resp);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 600);
    assert_eq!(body["scope"], "email offline_access openid profile");
    assert!(
        body["refresh_token"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );

    let id_token = body["id_token"].as_str().expect("id_token");
    let access_token = body["access_token"].as_str().expect("access_token");

    // The ID token verifies against the tenant's published key set, kid set.
    let jwks = published(&app, flow.tenant).await;
    let header = jwt_header(id_token);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(
        header["kid"],
        app.default.as_ref().expect("default").kid.as_str()
    );
    let verified = verify_jwt(id_token, &jwks, &[Alg::RS256]).expect("id_token verifies");
    let c = serde_json::Value::Object(verified.claims);
    let issuer = app.issuer(None);
    assert_eq!(c["iss"], issuer.as_str());
    assert_eq!(c["sub"], flow.user.id.to_string());
    // aud is the client id (as a one-element array).
    assert!(
        c["aud"] == flow.rp.id() || c["aud"] == serde_json::json!([flow.rp.id()]),
        "aud {}",
        c["aud"]
    );
    assert_eq!(c["azp"], flow.rp.id());
    assert_eq!(c["nonce"], NONCE);
    assert_eq!(c["auth_time"], start_time().unix_timestamp());
    assert_eq!(c["iat"], start_time().unix_timestamp());
    assert!(c["exp"].as_i64().expect("exp") > start_time().unix_timestamp());
    assert_eq!(c["acr"], "urn:anvilid:acr:pwd");
    assert_eq!(c["amr"], serde_json::json!(["pwd"]));
    assert_eq!(c["at_hash"], at_hash(access_token));

    // The access token is an RFC 9068 JWT from the same key.
    let at_header = jwt_header(access_token);
    assert_eq!(at_header["typ"], "at+jwt");
    let at = verify_jwt(access_token, &jwks, &[Alg::RS256]).expect("AT verifies");
    assert_eq!(at.claims["iss"], issuer.as_str());
    assert_eq!(at.claims["client_id"], flow.rp.id());
    assert_eq!(at.claims["sub"], flow.user.id.to_string());
}

#[tokio::test]
async fn code_exchange_with_client_secret_post() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretPost, "openid").await;
    let resp = exchange(&app, &flow.rp, &flow.code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    assert!(body["id_token"].is_string());
    assert_eq!(body["scope"], "openid");
}

#[tokio::test]
async fn no_refresh_token_without_the_refresh_grant() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(
        &app,
        tenant,
        anvil_core::service::client::ClientInput {
            grant_types: vec![GrantType::AuthorizationCode],
            ..web_input(ClientAuthMethod::ClientSecretBasic)
        },
    )
    .await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let session = seed_session(&app, tenant, &user).await;
    let code = issue_code(
        &app,
        tenant,
        &rp,
        &session,
        &params("openid", Some(CHALLENGE)),
    )
    .await;
    let resp = exchange(&app, &rp, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    assert!(body.get("refresh_token").is_none(), "{body}");
    assert!(body["id_token"].is_string());
}

#[tokio::test]
async fn no_id_token_without_openid() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretBasic, "profile").await;
    let resp = exchange(&app, &flow.rp, &flow.code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(json(&resp).get("id_token").is_none());
}

#[tokio::test]
async fn public_client_exchanges_with_pkce_only() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, public_input()).await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let session = seed_session(&app, tenant, &user).await;
    let code = issue_code(
        &app,
        tenant,
        &rp,
        &session,
        &params("openid", Some(CHALLENGE)),
    )
    .await;
    let resp = exchange(&app, &rp, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn tenant_path_token_endpoint_uses_the_tenant_issuer() {
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
    let id_token = json(&resp)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();
    let jwks = published(&app, acme.id).await;
    let verified = verify_jwt(&id_token, &jwks, &[Alg::RS256]).expect("acme key verifies");
    assert_eq!(verified.claims["iss"], app.issuer(Some("acme")).as_str());
}

#[tokio::test]
async fn non_form_bodies_and_repeated_parameters_are_invalid_request() {
    let app = TestApp::new().await;
    let flow = code_flow(&app, ClientAuthMethod::ClientSecretPost, "openid").await;

    let json_req = axum::http::Request::post("/token")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            "{\"grant_type\":\"authorization_code\"}",
        ))
        .expect("request");
    assert_oauth_error(&app.send(json_req).await, 400, "invalid_request");

    let resp = token(
        &app,
        &flow.rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", &flow.code),
            ("code", "other"),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_request");
    // The rejected request did not consume the code.
    assert_eq!(exchange(&app, &flow.rp, &flow.code).await.status, 200);
}

#[tokio::test]
async fn get_is_not_allowed_and_cors_is_public() {
    let app = TestApp::new().await;
    assert_eq!(app.get("/token").await.status, 405);
    let preflight = axum::http::Request::builder()
        .method("OPTIONS")
        .uri("/token")
        .header("origin", "https://rp.test")
        .header("access-control-request-method", "POST")
        .body(axum::body::Body::empty())
        .expect("request");
    let resp = app.send(preflight).await;
    assert_eq!(resp.header("access-control-allow-origin"), Some("*"));
    assert!(resp.header("access-control-allow-credentials").is_none());
}
