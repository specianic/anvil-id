//! Generic OAuth2 connection against a wiremock OAuth2 provider (AUTH-07, AUTH-11), through
//! AnvilID's real start and callback routes, on the selected backend (`ANVILID_TEST_DB`). The
//! identity comes from the profile endpoint through the connection's JSON-pointer mapping.
//!
//! Covered: the authorization and token requests (configured scopes, PKCE, client_secret_basic,
//! no nonce); subject/email/name mapping including a numeric subject; a mapped
//! `email_verified` on an untrusted connection never links automatically and registers an
//! unverified account; a trusted connection with a mapped `true` auto-links; anything but a
//! boolean `true` is not verified; a missing or empty subject is rejected; an ID token in the
//! token answer is ignored (identity only from the profile).

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{AMR_FED, AuditAction, ClaimMapping, ConnectionConfig, OAuth2Config};
use anvil_core::ports::Clock as _;
use anvil_jose::encoding::{b64url, sha256};
use serde_json::{Value, json};
use support::TestResponse;
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::{MOCK_CLIENT_ID, MOCK_EMAIL, MockKind, MockProvider, form_field};

const OAUTH2: &str = "forge";
const PASSWORD: &str = "correct horse battery";

/// A profile in the provider's own shape (nothing OIDC-like about it).
fn profile(id: Value, verified: Value) -> Value {
    json!({
        "data": {
            "id": id,
            "display_name": "Alice Forge",
            "contact": { "email": MOCK_EMAIL, "verified": verified },
        }
    })
}

async fn oauth2(trust: bool) -> Upstream {
    let app = app().await;
    let mock = MockProvider::start(MockKind::Oauth2).await;
    mock.set_now(app.clock().now().unix_timestamp());
    mock.set_userinfo(profile(json!(98765), json!(true)));
    let config = ConnectionConfig::Oauth2(OAuth2Config {
        authorization_endpoint: mock.authorization_endpoint(),
        token_endpoint: mock.token_endpoint(),
        userinfo_endpoint: mock.userinfo_endpoint(),
        client_id: MOCK_CLIENT_ID.into(),
        scopes: vec!["profile".into(), "email".into()],
        use_pkce: true,
        mapping: ClaimMapping {
            subject: "/data/id".into(),
            email: Some("/data/contact/email".into()),
            email_verified: Some("/data/contact/verified".into()),
            name: Some("/data/display_name".into()),
        },
    });
    let conn = add_connection(&app, OAUTH2, "Forge", config, trust).await;
    Upstream { app, mock, conn }
}

async fn o_sign_in(u: &Upstream) -> TestResponse {
    let started = start(&u.app, OAUTH2).await;
    u.app
        .get(&callback_path(
            OAUTH2,
            &[("code", "forge-code"), ("state", &started.state)],
        ))
        .await
}

async fn local_alice(u: &Upstream) {
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    u.app.clear_cookies();
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

#[tokio::test]
async fn mapping_registers_an_unverified_account_by_default() {
    // Untrusted (the default for a generic provider): the mapped `verified: true` is not enough.
    let u = oauth2(false).await;
    let started = start(&u.app, OAUTH2).await;
    assert_eq!(started.param("scope").as_deref(), Some("profile email"));
    assert_eq!(
        started.param("code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(started.nonce.is_none(), "OAuth2: no nonce");
    let resp = u
        .app
        .get(&callback_path(
            OAUTH2,
            &[("code", "forge-code"), ("state", &started.state)],
        ))
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = session(&u.app).await.expect("session");
    assert_eq!(s.amr, vec![AMR_FED.to_owned()]);
    let alice = user(&u.app, MOCK_EMAIL).await.expect("registered");
    assert_eq!(s.user_id, alice.id);
    assert!(!alice.email_verified, "untrusted connection");
    assert_eq!(alice.claims.name.as_deref(), Some("Alice Forge"));
    let l = links(&u.app, &alice).await;
    assert_eq!(l[0].subject, "98765", "numeric subject as a string");

    // client_secret_basic with the PKCE verifier; the profile call is a bearer call.
    let reqs = u.mock.received_token_requests().await;
    assert!(reqs[0].headers.get("authorization").is_some());
    let verifier = form_field(&reqs[0], "code_verifier").expect("verifier");
    assert_eq!(
        Some(b64url(&sha256(verifier.as_bytes()))),
        started.param("code_challenge")
    );
    assert_eq!(u.mock.request_count("/userinfo").await, 1);
}

#[tokio::test]
async fn untrusted_mapped_verified_email_needs_confirmation() {
    let u = oauth2(false).await;
    local_alice(&u).await;
    let resp = o_sign_in(&u).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    assert!(!html.contains(MOCK_EMAIL), "candidate not revealed: {html}");
    let alice = user(&u.app, MOCK_EMAIL).await.expect("alice");
    assert!(links(&u.app, &alice).await.is_empty());
    assert!(session(&u.app).await.is_none());
}

#[tokio::test]
async fn trusted_mapped_verified_email_auto_links() {
    let u = oauth2(true).await;
    local_alice(&u).await;
    let alice = user(&u.app, MOCK_EMAIL).await.expect("alice");
    let resp = o_sign_in(&u).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].details.as_map()["mode"], "auto");
}

#[tokio::test]
async fn only_a_mapped_boolean_true_counts_as_verified() {
    for (verified, label) in [
        (json!("true"), "string"),
        (json!(1), "number"),
        (json!(false), "false"),
        (Value::Null, "missing"),
    ] {
        let u = oauth2(true).await;
        local_alice(&u).await;
        u.mock.set_userinfo(profile(json!("forge-7"), verified));
        let resp = o_sign_in(&u).await;
        assert_eq!(resp.status, 200, "{label}: {}", resp.text());
        assert_eq!(form_id(&resp.html()), "upstream-link", "{label}");
        assert!(session(&u.app).await.is_none(), "{label}");
    }
}

#[tokio::test]
async fn missing_or_empty_subject_is_rejected() {
    let u = oauth2(true).await;
    for (id, label) in [
        (Value::Null, "missing"),
        (json!(""), "empty"),
        (json!({ "nested": 1 }), "object"),
        (json!(1.5), "fraction"),
    ] {
        u.mock.set_userinfo(profile(id, json!(true)));
        let resp = o_sign_in(&u).await;
        assert_rejected(&u, &resp, "claim_missing", label).await;
    }
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}

#[tokio::test]
async fn an_id_token_in_the_token_answer_is_ignored() {
    // A generic OAuth2 provider is never trusted for ID tokens: identity is the profile's.
    let u = oauth2(true).await;
    let token = u
        .mock
        .id_token(json!({ "sub": "from-id-token", "email": "mallory@example.com" }));
    u.mock.set_token_reply(
        200,
        json!({ "access_token": "at", "token_type": "Bearer", "id_token": token }),
    );
    let resp = o_sign_in(&u).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let alice = user(&u.app, MOCK_EMAIL)
        .await
        .expect("registered from profile");
    assert_eq!(links(&u.app, &alice).await[0].subject, "98765");
    assert!(user(&u.app, "mallory@example.com").await.is_none());
}
