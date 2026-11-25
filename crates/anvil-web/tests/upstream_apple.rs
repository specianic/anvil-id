//! Sign in with Apple against a wiremock Apple (AUTH-07, AUTH-11, SEC-03), through AnvilID's
//! real start, `form_post` and callback routes, on the selected backend (`ANVILID_TEST_DB`).
//! The connection overrides the issuer (= the client-secret audience) and the endpoints with the
//! mock's; the team's `.p8` key is generated per test and sealed like an uploaded one.
//!
//! Covered: the authorization request (`response_mode=form_post`, `name email`, no PKCE); the
//! cross-site `form_post` answered with a 303 to the `GET` callback where the sign-in happens;
//! the ES256 client secret checked by the mock's token endpoint (header kid/alg, iss = team,
//! sub = services id, aud, lifetime), minted per token request, refused for another audience or
//! another key; `email_verified` as a string; names only from the first authorization's `user`
//! JSON (never overwritten later, a forged `user` is ignored); private relay addresses; the
//! shared ID-token attacks (the JWKS signature check is never skipped) and key rotation.

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{
    AMR_FED, AppleConfig, ConnectionConfig, ConnectionId, EndpointOverrides, NewConnection,
    SocialConfig, SocialProvider,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::connection::seal_secret;
use anvil_jose::encoding::b64std;
use anvil_jose::{Jwk, generate_es256};
use secrecy::SecretString;
use serde_json::{Value, json};
use support::TestResponse;
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::{
    AppleSecretCheck, MOCK_CLIENT_ID, MOCK_EMAIL, MOCK_SUBJECT, MockKind, MockProvider, form_field,
};

const APPLE: &str = "apple";
const TEAM_ID: &str = "TEAM123456";
const KEY_ID: &str = "KEY7654321";

/// A fresh ES256 team key: its PKCS#8 PEM (`.p8` format) and its public JWK.
fn team_key() -> (String, Jwk) {
    let g = generate_es256().expect("ES256 key");
    let b64 = b64std(&g.pkcs8);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    (pem, g.public_jwk)
}

/// App + Apple mock + Apple connection whose sealed secret is a fresh team key. The mock checks
/// the client secret against that key and expects `aud` = `audience` (default: the mock issuer,
/// which the connection's issuer override makes the client-secret audience).
async fn apple_with(audience: Option<&str>, check_key: Option<Jwk>) -> Upstream {
    let app = app().await;
    let mock = MockProvider::start(MockKind::Apple).await;
    mock.set_now(app.clock().now().unix_timestamp());
    let (pem, public_jwk) = team_key();
    mock.expect_apple_client_secret(AppleSecretCheck {
        public_jwk: check_key.unwrap_or(public_jwk),
        key_id: KEY_ID.into(),
        team_id: TEAM_ID.into(),
        services_id: MOCK_CLIENT_ID.into(),
        audience: audience.map_or_else(|| mock.issuer(), str::to_owned),
    });
    let config = ConnectionConfig::Social(SocialConfig {
        provider: SocialProvider::Apple,
        client_id: MOCK_CLIENT_ID.into(),
        scopes: vec![],
        endpoints: EndpointOverrides {
            issuer: Some(mock.issuer()),
            authorization_endpoint: Some(mock.authorization_endpoint()),
            token_endpoint: Some(mock.token_endpoint()),
            userinfo_endpoint: None,
            jwks_uri: Some(mock.jwks_uri()),
            api_base_url: None,
        },
        microsoft_tenant: None,
        allowed_tenants: vec![],
        hosted_domains: vec![],
        apple: Some(AppleConfig {
            team_id: TEAM_ID.into(),
            key_id: KEY_ID.into(),
        }),
    });
    let tenant = tenant(&app).id;
    let id = ConnectionId::new_v7();
    let secret = seal_secret(app.kek(), tenant, id, &SecretString::from(pem)).expect("seal");
    let conn = app
        .storage()
        .connections()
        .create(
            tenant,
            &NewConnection {
                id,
                slug: APPLE.into(),
                display_name: "Apple".into(),
                enabled: true,
                config,
                secret_enc: Some(secret),
                trust_email_verified: true,
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create connection");
    Upstream { app, mock, conn }
}

async fn apple() -> Upstream {
    apple_with(None, None).await
}

/// Apple posts `fields` cross-site to the callback (no cookies: SameSite=Lax); the 303 is
/// followed to the `GET` callback with the browser's cookies.
async fn post_back(u: &Upstream, fields: &[(String, String)]) -> TestResponse {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish();
    let post = u
        .app
        .send(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri(format!("/ui/login/upstream/{APPLE}/callback"))
                .header("content-type", "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "cross-site")
                .header("cookie", "")
                .body(axum::body::Body::from(body))
                .expect("request"),
        )
        .await;
    assert_eq!(post.status, 303, "{}", post.text());
    assert!(session(&u.app).await.is_none(), "the POST signs nobody in");
    u.app.follow(&post).await
}

/// A full Apple sign-in: start, the token endpoint answers an ID token for the flow's nonce plus
/// `overrides`, Apple's `form_post` (with the `user` JSON on the first authorization only).
async fn apple_sign_in(u: &Upstream, overrides: Value) -> (TestResponse, Vec<(String, String)>) {
    let started = start(&u.app, APPLE).await;
    reply_for(u, &started, overrides);
    let fields = u
        .mock
        .apple_authorization_response(&started.state, "Alice", "Apple");
    (post_back(u, &fields).await, fields)
}

async fn assert_rejected(u: &Upstream, resp: &TestResponse, reason: &str, label: &str) {
    assert_eq!(resp.status, 400, "{label}: {}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "login", "{label}: {html}");
    assert!(
        message_keys(&html).contains(&"upstream.failed".to_owned()),
        "{label}: {html}"
    );
    assert!(session(&u.app).await.is_none(), "{label}: no session");
    assert_eq!(
        failure_reasons(&u.app).await.first().map(String::as_str),
        Some(reason),
        "{label}"
    );
}

fn has_user_json(fields: &[(String, String)]) -> bool {
    fields.iter().any(|(k, _)| k == "user")
}

#[tokio::test]
async fn first_sign_in_uses_form_post_no_pkce_and_a_verified_client_secret() {
    let u = apple().await;
    let started = start(&u.app, APPLE).await;
    assert!(
        started
            .location
            .as_str()
            .starts_with(&u.mock.authorization_endpoint()),
        "{}",
        started.location
    );
    assert_eq!(started.param("response_mode").as_deref(), Some("form_post"));
    assert_eq!(started.param("scope").as_deref(), Some("name email"));
    assert!(started.param("code_challenge").is_none(), "Apple: no PKCE");
    assert!(started.param("code_challenge_method").is_none());
    assert!(started.nonce.is_some());

    reply_for(&u, &started, json!({}));
    let fields = u
        .mock
        .apple_authorization_response(&started.state, "Alice", "Apple");
    assert!(has_user_json(&fields), "first authorization carries user");
    let resp = post_back(&u, &fields).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = session(&u.app).await.expect("session");
    assert_eq!(s.amr, vec![AMR_FED.to_owned()]);

    // The `"true"` string counts as verified (trusted connection); names come from `user`.
    let alice = user(&u.app, MOCK_EMAIL).await.expect("registered");
    assert_eq!(s.user_id, alice.id);
    assert!(alice.email_verified);
    assert_eq!(alice.claims.given_name.as_deref(), Some("Alice"));
    assert_eq!(alice.claims.family_name.as_deref(), Some("Apple"));
    assert_eq!(alice.claims.name.as_deref(), Some("Alice Apple"));
    assert_eq!(links(&u.app, &alice).await[0].subject, MOCK_SUBJECT);

    // client_secret_post with the minted secret, no verifier, no Basic header.
    let reqs = u.mock.received_token_requests().await;
    assert_eq!(reqs.len(), 1);
    assert!(form_field(&reqs[0], "code_verifier").is_none());
    assert!(reqs[0].headers.get("authorization").is_none());
    assert_eq!(
        form_field(&reqs[0], "client_id").as_deref(),
        Some(MOCK_CLIENT_ID)
    );
    assert_eq!(form_field(&reqs[0], "code").as_deref(), Some("apple-code"));
    let secrets = u.mock.apple_client_secrets();
    assert_eq!(secrets.len(), 1, "the mock accepted one client secret");
    let c = &secrets[0];
    let now = u.app.clock().now().unix_timestamp();
    assert_eq!(c["iss"], TEAM_ID);
    assert_eq!(c["sub"], MOCK_CLIENT_ID);
    assert_eq!(c["aud"], json!(u.mock.issuer()));
    assert_eq!(c["iat"], json!(now));
    assert_eq!(c["exp"], json!(now + 300));
}

#[tokio::test]
async fn later_sign_ins_mint_a_new_secret_and_keep_the_first_names() {
    let u = apple().await;
    let (first, fields) = apple_sign_in(&u, json!({})).await;
    assert_eq!(first.status, 200, "{}", first.text());
    assert!(has_user_json(&fields));
    let alice = user(&u.app, MOCK_EMAIL).await.expect("registered");
    u.app.clear_cookies();

    // Later: Apple sends no user JSON; the account and its names are unchanged.
    u.app.clock().advance(std::time::Duration::from_secs(30));
    u.mock.set_now(u.app.clock().now().unix_timestamp());
    let (second, fields) = apple_sign_in(&u, json!({})).await;
    assert_eq!(second.status, 200, "{}", second.text());
    assert!(!has_user_json(&fields), "user JSON only on the first time");
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    let again = user(&u.app, MOCK_EMAIL).await.expect("user");
    assert_eq!(again.claims.given_name.as_deref(), Some("Alice"));
    assert_eq!(again.claims.family_name.as_deref(), Some("Apple"));

    // A forged `user` value on a later return is ignored as well.
    u.app.clear_cookies();
    let started = start(&u.app, APPLE).await;
    reply_for(&u, &started, json!({}));
    let mut fields = u
        .mock
        .apple_authorization_response(&started.state, "x", "y");
    fields.push((
        "user".into(),
        json!({ "name": { "firstName": "Mallory", "lastName": "Forged" } }).to_string(),
    ));
    let third = post_back(&u, &fields).await;
    assert_eq!(third.status, 200, "{}", third.text());
    let still = user(&u.app, MOCK_EMAIL).await.expect("user");
    assert_eq!(still.claims.given_name.as_deref(), Some("Alice"));
    assert_eq!(still.claims.family_name.as_deref(), Some("Apple"));

    // One secret per token request, each minted at its own time.
    let secrets = u.mock.apple_client_secrets();
    assert_eq!(secrets.len(), 3);
    assert_ne!(secrets[0]["iat"], secrets[1]["iat"]);
    assert_ne!(secrets[0]["exp"], secrets[1]["exp"]);
    let sent: Vec<String> = u
        .mock
        .received_token_requests()
        .await
        .iter()
        .map(|r| form_field(r, "client_secret").expect("client_secret"))
        .collect();
    assert_ne!(sent[0], sent[1], "a fresh secret per token request");
}

#[tokio::test]
async fn string_false_email_verified_and_private_relay_addresses() {
    let u = apple().await;
    let relay = "x7k2pq9w@privaterelay.appleid.com";
    let (resp, _) = apple_sign_in(
        &u,
        json!({
            "email": relay,
            "email_verified": "false",
            "is_private_email": "true",
        }),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let relayed = user(&u.app, relay)
        .await
        .expect("relay address is the email");
    assert!(!relayed.email_verified, "\"false\" is not verified");
    let l = links(&u.app, &relayed).await;
    assert_eq!(l[0].metadata.get("is_private_email"), Some(&json!(true)));
    assert_eq!(l[0].email_at_link.as_deref(), Some(relay));
}

#[tokio::test]
async fn client_secret_for_another_audience_or_key_is_refused_by_apple() {
    // The mock expects another audience: Apple answers invalid_client, nobody signs in.
    let u = apple_with(Some("https://other-audience.example"), None).await;
    let (resp, _) = apple_sign_in(&u, json!({})).await;
    assert_rejected(&u, &resp, "exchange_failed", "other audience").await;
    assert!(u.mock.apple_client_secrets().is_empty());
    assert_eq!(u.mock.received_token_requests().await.len(), 1);
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());

    // The mock knows another team key: the signature does not verify.
    let (_, other_key) = team_key();
    let u = apple_with(None, Some(other_key)).await;
    let (resp, _) = apple_sign_in(&u, json!({})).await;
    assert_rejected(&u, &resp, "exchange_failed", "other key").await;
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}

#[tokio::test]
async fn shared_id_token_attacks_are_rejected() {
    let u = apple().await;
    let count = u.mock.attack_tokens("n").len();
    for i in 0..count {
        let started = start(&u.app, APPLE).await;
        let attack = u
            .mock
            .attack_tokens(started.nonce.as_deref().expect("nonce"))
            .swap_remove(i);
        u.mock.respond_with_raw_id_token(&attack.id_token);
        let fields = u
            .mock
            .apple_authorization_response(&started.state, "Alice", "Apple");
        let resp = post_back(&u, &fields).await;
        assert_rejected(&u, &resp, attack.reason, attack.label).await;
    }
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}

#[tokio::test]
async fn rotated_key_refreshes_the_jwks_once_and_an_unknown_kid_then_fails() {
    let u = apple().await;
    assert_eq!(apple_sign_in(&u, json!({})).await.0.status, 200);
    assert_eq!(u.mock.jwks_requests().await, 1);
    u.app.clear_cookies();
    u.mock.rotate_key();
    let (resp, _) = apple_sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(u.mock.jwks_requests().await, 2);
    u.app.clear_cookies();
    let started = start(&u.app, APPLE).await;
    let token = u
        .mock
        .id_token_with_unknown_kid(json!({ "nonce": started.nonce.clone().expect("nonce") }));
    u.mock.respond_with_raw_id_token(&token);
    let fields = u
        .mock
        .apple_authorization_response(&started.state, "Alice", "Apple");
    let resp = post_back(&u, &fields).await;
    assert_rejected(&u, &resp, "id_token_signature", "unknown kid").await;
    assert_eq!(u.mock.jwks_requests().await, 2);
}
