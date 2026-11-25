//! `GET/POST /userinfo` happy paths: the three ways to present the token, scope-based claims with
//! OIDC Core §5.1 types, and `claims.userinfo` requests.

mod support;
mod token_support;

use anvil_core::model::{ClaimsRequest, ClientAuthMethod, RequestedClaim};
use support::{TestApp, json};
use token_support::*;

fn at(body: &serde_json::Value) -> String {
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

#[tokio::test]
async fn header_get_header_post_and_body_post_are_accepted() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid").await;
    let token = at(&body);
    let sub = jwt_claims(body["id_token"].as_str().expect("id_token"))["sub"].clone();

    for resp in [
        userinfo_get(&app, &token).await,
        userinfo_post_header(&app, &token).await,
        userinfo_post_body(&app, &token).await,
    ] {
        assert_eq!(resp.status, 200, "{}", resp.text());
        assert!(
            resp.header("content-type")
                .is_some_and(|c| c.starts_with("application/json"))
        );
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        assert_eq!(json(&resp)["sub"], sub);
    }
}

#[tokio::test]
async fn openid_only_returns_only_sub() {
    let app = TestApp::new().await;
    let (flow, body) = tokens(&app, "openid").await;
    let resp = userinfo_get(&app, &at(&body)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let claims = json(&resp);
    let obj = claims.as_object().expect("object");
    assert_eq!(obj.len(), 1, "{claims}");
    assert_eq!(claims["sub"], flow.user.id.to_string());
}

#[tokio::test]
async fn scope_claims_have_the_standard_types() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid profile email address phone").await;
    let resp = userinfo_get(&app, &at(&body)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let c = json(&resp);
    // profile
    assert_eq!(c["name"], "Ada Lovelace");
    assert_eq!(c["given_name"], "Ada");
    assert_eq!(c["family_name"], "Lovelace");
    assert_eq!(c["preferred_username"], "ada");
    assert_eq!(c["locale"], "en-GB");
    assert!(c["updated_at"].is_i64(), "updated_at is a number: {c}");
    // email
    assert_eq!(c["email"], "ada@example.test");
    assert_eq!(c["email_verified"], true);
    assert!(c["email_verified"].is_boolean());
    // address
    assert!(c["address"].is_object(), "{c}");
    assert_eq!(c["address"]["locality"], "London");
    assert_eq!(c["address"]["country"], "GB");
    // phone
    assert_eq!(c["phone_number"], "+44 20 7946 0000");
    assert!(c["phone_number_verified"].is_boolean());
    assert_eq!(c["phone_number_verified"], true);
}

#[tokio::test]
async fn profile_scope_does_not_leak_email_or_phone() {
    let app = TestApp::new().await;
    let (_, body) = tokens(&app, "openid profile").await;
    let c = json(&userinfo_get(&app, &at(&body)).await);
    assert_eq!(c["name"], "Ada Lovelace");
    for absent in ["email", "email_verified", "address", "phone_number"] {
        assert!(c.get(absent).is_none(), "{absent} leaked: {c}");
    }
}

#[tokio::test]
async fn userinfo_claims_request_is_honoured_and_not_put_in_the_id_token() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let session = seed_session(&app, tenant, &user).await;
    let request = ClaimsRequest {
        userinfo: vec![RequestedClaim {
            name: "name".into(),
            essential: true,
            values: vec![],
        }],
        id_token: vec![],
    };
    let code = issue_code(
        &app,
        tenant,
        &rp,
        &session,
        &params_with_claims("openid", request),
    )
    .await;
    let resp = exchange(&app, &rp, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    let id = jwt_claims(body["id_token"].as_str().expect("id_token"));
    assert!(id.get("name").is_none(), "{id}");

    let c = json(&userinfo_get(&app, &at(&body)).await);
    assert_eq!(c["name"], "Ada Lovelace");
    assert!(c.get("email").is_none());
}

#[tokio::test]
async fn tenant_path_userinfo_accepts_its_own_tokens() {
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
    let resp = get_with_auth(&app, "/t/acme/userinfo", &format!("Bearer {token}")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(json(&resp)["sub"], user.id.to_string());
}

#[tokio::test]
async fn cors_is_public() {
    let app = TestApp::new().await;
    let preflight = axum::http::Request::builder()
        .method("OPTIONS")
        .uri("/userinfo")
        .header("origin", "https://rp.test")
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "authorization")
        .body(axum::body::Body::empty())
        .expect("request");
    let resp = app.send(preflight).await;
    assert_eq!(resp.header("access-control-allow-origin"), Some("*"));
    assert!(resp.header("access-control-allow-credentials").is_none());
}
