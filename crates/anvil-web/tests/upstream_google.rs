//! Google preset against a wiremock Google (AUTH-07, AUTH-11), through AnvilID's real start and
//! callback routes, on the selected backend (`ANVILID_TEST_DB`). The connection points its
//! authorization, token and JWKS endpoints at the mock (per-connection endpoint overrides) and
//! keeps the preset issuer rule, so tokens carry Google's issuer strings while every request
//! goes to loopback.
//!
//! Covered: just-in-time sign-in with the scheme-less `accounts.google.com` issuer, the https
//! issuer, any other issuer rejected, the `hd` allow-list, auto-linking a verified account only
//! when the connection is trusted and the tenant allows it, the shared ID-token attacks and key
//! rotation (one forced JWKS refresh, then fail).

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{
    AMR_FED, AuditAction, ConnectionConfig, EndpointOverrides, SocialConfig, SocialProvider,
};
use anvil_core::ports::Clock as _;
use anvil_jose::encoding::{b64url, sha256};
use serde_json::{Value, json};
use support::TestResponse;
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::{
    GOOGLE_TOKEN_ISSUER, MOCK_CLIENT_ID, MOCK_EMAIL, MOCK_SUBJECT, MockKind, MockProvider,
    form_field,
};

const GOOGLE: &str = "google";
const PASSWORD: &str = "correct horse battery";

/// App + Google mock + Google connection (`trust_email_verified = trust`, `hd` allow-list).
async fn google(trust: bool, hosted_domains: &[&str]) -> Upstream {
    let app = app().await;
    let mock = MockProvider::start(MockKind::Google).await;
    mock.set_now(app.clock().now().unix_timestamp());
    let config = ConnectionConfig::Social(SocialConfig {
        provider: SocialProvider::Google,
        client_id: MOCK_CLIENT_ID.into(),
        scopes: vec![],
        endpoints: EndpointOverrides {
            issuer: None,
            authorization_endpoint: Some(mock.authorization_endpoint()),
            token_endpoint: Some(mock.token_endpoint()),
            userinfo_endpoint: Some(mock.userinfo_endpoint()),
            jwks_uri: Some(mock.jwks_uri()),
            api_base_url: None,
        },
        microsoft_tenant: None,
        allowed_tenants: vec![],
        hosted_domains: hosted_domains.iter().map(|d| (*d).to_owned()).collect(),
        apple: None,
    });
    let conn = add_connection(&app, GOOGLE, "Google", config, trust).await;
    Upstream { app, mock, conn }
}

/// Google returns to the callback with `code` and `state`.
async fn google_callback(u: &Upstream, started: &Started) -> TestResponse {
    u.app
        .get(&callback_path(
            GOOGLE,
            &[("code", "google-code"), ("state", &started.state)],
        ))
        .await
}

/// Start, the token endpoint answers an ID token for the flow's nonce plus `overrides`, callback.
async fn google_sign_in(u: &Upstream, overrides: Value) -> TestResponse {
    let started = start(&u.app, GOOGLE).await;
    reply_for(u, &started, overrides);
    google_callback(u, &started).await
}

/// The generic error on a fresh sign-in form, no session, audited with `reason`.
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
async fn scheme_less_issuer_signs_in_just_in_time() {
    let u = google(true, &[]).await;
    let started = start(&u.app, GOOGLE).await;
    assert!(
        started
            .location
            .as_str()
            .starts_with(&u.mock.authorization_endpoint()),
        "{}",
        started.location
    );
    assert_eq!(
        started.param("scope").as_deref(),
        Some("openid email profile")
    );
    assert_eq!(
        started.param("code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(started.param("response_mode").is_none());
    reply_for(&u, &started, json!({ "iss": GOOGLE_TOKEN_ISSUER }));
    let resp = google_callback(&u, &started).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&"login.signed_in".to_owned()),
        "{}",
        resp.text()
    );
    let s = session(&u.app).await.expect("session");
    assert_eq!(s.amr, vec![AMR_FED.to_owned()]);
    let alice = user(&u.app, MOCK_EMAIL).await.expect("registered");
    assert_eq!(s.user_id, alice.id);
    assert!(alice.email_verified, "trusted Google email is verified");
    assert_eq!(alice.claims.given_name.as_deref(), Some("Alice"));
    let l = links(&u.app, &alice).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].subject, MOCK_SUBJECT);

    // client_secret_basic and the PKCE verifier of the challenge.
    let reqs = u.mock.received_token_requests().await;
    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].headers.get("authorization").is_some());
    assert!(form_field(&reqs[0], "client_secret").is_none());
    let verifier = form_field(&reqs[0], "code_verifier").expect("verifier");
    assert_eq!(
        Some(b64url(&sha256(verifier.as_bytes()))),
        started.param("code_challenge")
    );
}

#[tokio::test]
async fn https_issuer_is_accepted_too() {
    let u = google(true, &[]).await;
    let resp = google_sign_in(&u, json!({ "iss": "https://accounts.google.com" })).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session(&u.app).await.is_some());
}

#[tokio::test]
async fn any_other_issuer_is_rejected() {
    let u = google(true, &[]).await;
    let base = u.mock.base_url();
    for iss in [
        "https://evil.example",
        "http://accounts.google.com",
        "https://accounts.google.com/",
        "accounts.google.com.evil.example",
        base.as_str(),
    ] {
        let resp = google_sign_in(&u, json!({ "iss": iss })).await;
        assert_rejected(&u, &resp, "id_token_issuer", iss).await;
    }
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}

#[tokio::test]
async fn hosted_domain_allow_list_is_enforced() {
    let u = google(true, &["example.com"]).await;
    for (hd, label) in [
        (json!("other.example"), "other domain"),
        (Value::Null, "missing hd"),
        (json!(["example.com"]), "not a string"),
    ] {
        let resp = google_sign_in(&u, json!({ "hd": hd })).await;
        assert_rejected(&u, &resp, "hosted_domain", label).await;
    }
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());

    // A listed domain (case-insensitive) signs in and the link records it.
    let resp = google_sign_in(&u, json!({ "hd": "Example.COM" })).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let alice = user(&u.app, MOCK_EMAIL).await.expect("registered");
    let l = links(&u.app, &alice).await;
    assert_eq!(l[0].metadata.get("hd"), Some(&json!("Example.COM")));
}

#[tokio::test]
async fn verified_email_auto_links_only_when_trusted_and_allowed() {
    // Trusted connection, tenant auto-link on, verified local account: linked automatically.
    let u = google(true, &[]).await;
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    let alice = user(&u.app, MOCK_EMAIL).await.expect("alice");
    let resp = google_sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].details.as_map()["mode"], "auto");
    assert_eq!(linked[0].details.as_map()["connection"], GOOGLE);

    // Untrusted connection: the same assertion only offers the confirmation page.
    let u = google(false, &[]).await;
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    let resp = google_sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(form_id(&resp.html()), "upstream-link");
    assert!(session(&u.app).await.is_none());

    // Trusted but the tenant turned auto-linking off: confirmation as well.
    let u = google(true, &[]).await;
    tenant_settings(&u.app, |s| s.auto_link = false).await;
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    let resp = google_sign_in(&u, json!({})).await;
    assert_eq!(form_id(&resp.html()), "upstream-link");
    assert!(audit(&u.app, AuditAction::IdentityLinked).await.is_empty());
}

#[tokio::test]
async fn shared_id_token_attacks_are_rejected() {
    let u = google(true, &[]).await;
    let count = u.mock.attack_tokens("n").len();
    for i in 0..count {
        let started = start(&u.app, GOOGLE).await;
        let attack = u
            .mock
            .attack_tokens(started.nonce.as_deref().expect("nonce"))
            .swap_remove(i);
        u.mock.respond_with_raw_id_token(&attack.id_token);
        let resp = google_callback(&u, &started).await;
        assert_rejected(&u, &resp, attack.reason, attack.label).await;
    }
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}

#[tokio::test]
async fn rotated_key_refreshes_the_jwks_once_and_an_unknown_kid_then_fails() {
    let u = google(true, &[]).await;
    assert_eq!(google_sign_in(&u, json!({})).await.status, 200);
    assert_eq!(u.mock.jwks_requests().await, 1);
    u.app.clear_cookies();
    // Google rotates: the cached set lacks the new kid, one forced refresh finds it.
    u.mock.rotate_key();
    let resp = google_sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(u.mock.jwks_requests().await, 2);
    u.app.clear_cookies();
    // A kid nobody publishes: rejected without another fetch (refresh throttle).
    let started = start(&u.app, GOOGLE).await;
    let token = u
        .mock
        .id_token_with_unknown_kid(json!({ "nonce": started.nonce.clone().expect("nonce") }));
    u.mock.respond_with_raw_id_token(&token);
    let resp = google_callback(&u, &started).await;
    assert_rejected(&u, &resp, "id_token_signature", "unknown kid").await;
    assert_eq!(u.mock.jwks_requests().await, 2);
}
