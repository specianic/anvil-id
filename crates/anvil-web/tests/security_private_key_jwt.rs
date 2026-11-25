//! `private_key_jwt` client authentication at `POST /token` (RFC 7523, RFC 9700 §2.6): every
//! malformed, misdirected, replayed or wrongly signed assertion is `invalid_client`.

mod support;
mod token_support;

use anvil_core::model::ClientAuthMethod;
use anvil_core::service::client::ClientInput;
use anvil_jose::encoding::random_token;
use anvil_jose::keys::{Alg, SigningKey};
use serde_json::{Value, json};
use support::{TestApp, start_time};
use token_support::*;

const CC: &[(&str, &str)] = &[("grant_type", "client_credentials")];

struct Setup {
    app: TestApp,
    rp: Rp,
    key: ClientKey,
    issuer: String,
}

async fn setup() -> Setup {
    let app = TestApp::new().await;
    let key = client_key();
    let rp = register(
        &app,
        default_tenant(&app),
        ClientInput {
            jwks: Some(key.jwks.clone()),
            ..cc_input(ClientAuthMethod::PrivateKeyJwt)
        },
    )
    .await;
    let issuer = app.issuer(None);
    Setup {
        app,
        rp,
        key,
        issuer,
    }
}

impl Setup {
    /// Valid claims; tests then break one of them.
    fn claims(&self) -> Value {
        let now = start_time().unix_timestamp();
        json!({
            "iss": self.rp.id(),
            "sub": self.rp.id(),
            "aud": self.issuer,
            "iat": now,
            "exp": now + 60,
            "jti": random_token(),
        })
    }

    fn sign(&self, claims: &Value) -> String {
        self.key
            .signer
            .sign_jwt(Some("client-authentication+jwt"), claims)
            .expect("sign")
    }

    async fn send(&self, assertion: String) -> support::TestResponse {
        token(&self.app, &Auth::Assertion(assertion), CC).await
    }

    async fn rejects(&self, assertion: String, what: &str) {
        let resp = self.send(assertion).await;
        assert_eq!(resp.status, 401, "{what}: {}", resp.text());
        assert_oauth_error(&resp, 401, "invalid_client");
        assert!(resp.header("www-authenticate").is_none(), "{what}");
    }
}

#[tokio::test]
async fn valid_typed_assertion_is_accepted() {
    let s = setup().await;
    let resp = s.send(s.sign(&s.claims())).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn valid_untyped_assertion_is_accepted() {
    let s = setup().await;
    let a = s.key.signer.sign_jwt(None, &s.claims()).expect("sign");
    let resp = s.send(a).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn token_endpoint_audience_is_rejected() {
    let s = setup().await;
    let mut c = s.claims();
    c["aud"] = json!(format!("{}/token", s.issuer));
    s.rejects(s.sign(&c), "aud = token endpoint").await;
}

#[tokio::test]
async fn multi_valued_audience_is_rejected() {
    let s = setup().await;
    let mut c = s.claims();
    c["aud"] = json!([s.issuer, "https://other.test"]);
    s.rejects(s.sign(&c), "aud array").await;
    // A one-element array of the issuer is fine.
    let mut c = s.claims();
    c["aud"] = json!([s.issuer]);
    assert_eq!(s.send(s.sign(&c)).await.status, 200);
}

#[tokio::test]
async fn replayed_assertion_is_rejected() {
    let s = setup().await;
    let a = s.sign(&s.claims());
    assert_eq!(s.send(a.clone()).await.status, 200);
    s.rejects(a, "replay").await;
}

#[tokio::test]
async fn reused_jti_in_a_new_assertion_is_rejected() {
    let s = setup().await;
    let first = s.claims();
    assert_eq!(s.send(s.sign(&first)).await.status, 200);
    let mut again = s.claims();
    again["jti"] = first["jti"].clone();
    again["iat"] = json!(start_time().unix_timestamp() + 1);
    s.rejects(s.sign(&again), "jti reuse").await;
}

#[tokio::test]
async fn far_future_exp_is_rejected() {
    let s = setup().await;
    let mut c = s.claims();
    c["exp"] = json!(start_time().unix_timestamp() + 5 * 60 + 30);
    s.rejects(s.sign(&c), "exp > 5 min").await;
}

#[tokio::test]
async fn expired_assertion_is_rejected() {
    let s = setup().await;
    let mut c = s.claims();
    c["iat"] = json!(start_time().unix_timestamp() - 300);
    c["exp"] = json!(start_time().unix_timestamp() - 60);
    s.rejects(s.sign(&c), "expired").await;
}

#[tokio::test]
async fn missing_jti_or_exp_is_rejected() {
    let s = setup().await;
    let mut c = s.claims();
    c.as_object_mut().expect("object").remove("jti");
    s.rejects(s.sign(&c), "no jti").await;
    let mut c = s.claims();
    c.as_object_mut().expect("object").remove("exp");
    s.rejects(s.sign(&c), "no exp").await;
}

#[tokio::test]
async fn iss_different_from_sub_is_rejected() {
    let s = setup().await;
    let mut c = s.claims();
    c["iss"] = json!("someone-else");
    s.rejects(s.sign(&c), "iss != sub").await;
}

#[tokio::test]
async fn hs256_and_none_are_rejected() {
    let s = setup().await;
    let c = s.claims();
    let hs = forged(
        &json!({"alg": "HS256", "kid": s.key.kid, "typ": "JWT"}),
        &c,
        b"0123456789abcdef0123456789abcdef",
    );
    s.rejects(hs, "HS256").await;
    let mut c = s.claims();
    c["jti"] = json!(random_token());
    let none = forged(&json!({"alg": "none"}), &c, b"");
    s.rejects(none, "alg none").await;
}

#[tokio::test]
async fn unknown_kid_is_rejected() {
    let s = setup().await;
    let other = client_key();
    let a = other
        .signer
        .sign_jwt(Some("client-authentication+jwt"), &s.claims())
        .expect("sign");
    s.rejects(a, "unknown kid").await;
}

#[tokio::test]
async fn unregistered_key_under_the_registered_kid_is_rejected() {
    let s = setup().await;
    let g = anvil_jose::keys::generate_rs256().expect("key");
    let impostor = SigningKey::from_pkcs8(&s.key.kid, Alg::RS256, &g.pkcs8).expect("signer");
    let a = impostor
        .sign_jwt(Some("client-authentication+jwt"), &s.claims())
        .expect("sign");
    s.rejects(a, "unregistered key").await;
}

#[tokio::test]
async fn assertion_for_a_secret_client_is_rejected() {
    let s = setup().await;
    let secret_client = register(
        &s.app,
        default_tenant(&s.app),
        cc_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let mut c = s.claims();
    c["iss"] = json!(secret_client.id());
    c["sub"] = json!(secret_client.id());
    s.rejects(s.sign(&c), "client registered for basic").await;
}

#[tokio::test]
async fn assertion_with_a_secret_is_rejected() {
    let s = setup().await;
    let auth = Auth::Raw(
        None,
        vec![
            (
                "client_assertion_type".into(),
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ),
            ("client_assertion".into(), s.sign(&s.claims())),
            ("client_id".into(), s.rp.id().into()),
            ("client_secret".into(), "x".into()),
        ],
    );
    assert_oauth_error(&token(&s.app, &auth, CC).await, 401, "invalid_client");
}

#[tokio::test]
async fn wrong_assertion_type_is_rejected() {
    let s = setup().await;
    let auth = Auth::Raw(
        None,
        vec![
            ("client_assertion_type".into(), "urn:example:other".into()),
            ("client_assertion".into(), s.sign(&s.claims())),
        ],
    );
    assert_oauth_error(&token(&s.app, &auth, CC).await, 401, "invalid_client");
}
