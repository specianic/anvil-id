//! Microsoft preset against a wiremock Microsoft identity platform (AUTH-07, AUTH-11), through
//! AnvilID's real start and callback routes, on the selected backend (`ANVILID_TEST_DB`). The
//! connection overrides the issuer with the mock's `{tenantid}` template (national-cloud style)
//! and points every endpoint at the mock.
//!
//! Covered: multi-tenant sign-in with `tid` substitution; an `iss` for another tenant than `tid`,
//! a missing `tid`, a non-canonical `tid` and a tenant outside `allowed_tenants` all rejected; a
//! single-tenant connection; a verified-looking email never auto-links (Microsoft email is
//! admin-controlled) and a just-in-time account keeps it unverified; `tid`/`oid` kept in the link
//! metadata; the shared ID-token attacks and key rotation.

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{
    AuditAction, ConnectionConfig, EndpointOverrides, SocialConfig, SocialProvider,
};
use anvil_core::ports::Clock as _;
use serde_json::{Value, json};
use support::TestResponse;
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::{
    MOCK_CLIENT_ID, MOCK_EMAIL, MOCK_SUBJECT, MOCK_TENANT_ID, MockKind, MockProvider,
};

const MS: &str = "microsoft";
const PASSWORD: &str = "correct horse battery";
/// Another (test) tenant id.
const OTHER_TENANT: &str = "3f6b0c2e-5d1a-4e8f-9b7c-2a1d0e9f8c7b";

/// How the connection is scoped.
enum Tenancy<'a> {
    /// `common` with the `{tenantid}` issuer template and an optional allow-list.
    Multi(&'a [&'a str]),
    /// One tenant id with that tenant's exact issuer.
    Single,
}

async fn microsoft(trust: bool, tenancy: Tenancy<'_>) -> Upstream {
    let app = app().await;
    let mock = MockProvider::start(MockKind::Microsoft).await;
    mock.set_now(app.clock().now().unix_timestamp());
    let (issuer, tenant, allowed) = match tenancy {
        Tenancy::Multi(allowed) => (
            mock.issuer_template(),
            None,
            allowed.iter().map(|t| (*t).to_owned()).collect(),
        ),
        Tenancy::Single => (mock.issuer(), Some(MOCK_TENANT_ID.to_owned()), vec![]),
    };
    let config = ConnectionConfig::Social(SocialConfig {
        provider: SocialProvider::Microsoft,
        client_id: MOCK_CLIENT_ID.into(),
        scopes: vec![],
        endpoints: EndpointOverrides {
            issuer: Some(issuer),
            authorization_endpoint: Some(mock.authorization_endpoint()),
            token_endpoint: Some(mock.token_endpoint()),
            userinfo_endpoint: Some(mock.userinfo_endpoint()),
            jwks_uri: Some(mock.jwks_uri()),
            api_base_url: None,
        },
        microsoft_tenant: tenant,
        allowed_tenants: allowed,
        hosted_domains: vec![],
        apple: None,
    });
    let conn = add_connection(&app, MS, "Microsoft", config, trust).await;
    Upstream { app, mock, conn }
}

/// The issuer of tenant `tid` at the mock.
fn tenant_issuer(u: &Upstream, tid: &str) -> String {
    u.mock.issuer_template().replace("{tenantid}", tid)
}

async fn ms_callback(u: &Upstream, started: &Started) -> TestResponse {
    u.app
        .get(&callback_path(
            MS,
            &[("code", "ms-code"), ("state", &started.state)],
        ))
        .await
}

async fn ms_sign_in(u: &Upstream, overrides: Value) -> TestResponse {
    let started = start(&u.app, MS).await;
    reply_for(u, &started, overrides);
    ms_callback(u, &started).await
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
async fn multi_tenant_sign_in_substitutes_tid_and_keeps_email_unverified() {
    // Trusted connection: Microsoft email still never counts as verified.
    let u = microsoft(true, Tenancy::Multi(&[])).await;
    let started = start(&u.app, MS).await;
    assert_eq!(
        started.param("code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(started.nonce.is_some());
    reply_for(&u, &started, json!({}));
    let resp = ms_callback(&u, &started).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let alice = user(&u.app, MOCK_EMAIL).await.expect("registered");
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    assert!(!alice.email_verified, "Microsoft email is never trusted");
    let l = links(&u.app, &alice).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].subject, MOCK_SUBJECT);
    assert_eq!(l[0].metadata.get("tid"), Some(&json!(MOCK_TENANT_ID)));
    assert!(l[0].metadata.get("oid").is_some_and(Value::is_string));
    // client_secret_basic.
    let reqs = u.mock.received_token_requests().await;
    assert!(reqs[0].headers.get("authorization").is_some());

    // A user of another tenant signs in through the same multi-tenant connection.
    u.app.clear_cookies();
    let resp = ms_sign_in(
        &u,
        json!({
            "iss": tenant_issuer(&u, OTHER_TENANT),
            "tid": OTHER_TENANT,
            "sub": "other-tenant-user",
            "email": "bob@example.com",
        }),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(user(&u.app, "bob@example.com").await.is_some());
}

#[tokio::test]
async fn tid_and_issuer_must_agree() {
    let u = microsoft(true, Tenancy::Multi(&[])).await;
    let mine = tenant_issuer(&u, MOCK_TENANT_ID);
    let other = tenant_issuer(&u, OTHER_TENANT);
    let upper = MOCK_TENANT_ID.to_ascii_uppercase();
    let braced = format!("{{{MOCK_TENANT_ID}}}");
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({ "iss": other, "tid": MOCK_TENANT_ID }),
            "iss of another tenant",
        ),
        (
            json!({ "iss": mine, "tid": OTHER_TENANT }),
            "tid of another tenant",
        ),
        (json!({ "tid": null }), "missing tid"),
        (
            json!({ "tid": "contoso", "iss": tenant_issuer(&u, "contoso") }),
            "non-UUID tid",
        ),
        (
            json!({ "tid": upper, "iss": tenant_issuer(&u, &upper) }),
            "uppercase tid",
        ),
        (
            json!({ "tid": braced, "iss": tenant_issuer(&u, &braced) }),
            "braced tid",
        ),
        (json!({ "tid": 42 }), "numeric tid"),
        (
            json!({ "iss": u.mock.issuer_template() }),
            "unsubstituted template",
        ),
    ];
    for (overrides, label) in cases {
        let resp = ms_sign_in(&u, overrides).await;
        assert_rejected(&u, &resp, "id_token_issuer", label).await;
    }
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}

#[tokio::test]
async fn tenant_outside_the_allow_list_is_rejected() {
    let u = microsoft(true, Tenancy::Multi(&[MOCK_TENANT_ID])).await;
    let other = tenant_issuer(&u, OTHER_TENANT);
    let resp = ms_sign_in(&u, json!({ "iss": other, "tid": OTHER_TENANT })).await;
    assert_rejected(&u, &resp, "id_token_issuer", "other tenant").await;
    let resp = ms_sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn single_tenant_connection_accepts_only_its_tenant() {
    let u = microsoft(true, Tenancy::Single).await;
    let other = tenant_issuer(&u, OTHER_TENANT);
    let resp = ms_sign_in(&u, json!({ "iss": other, "tid": OTHER_TENANT })).await;
    assert_rejected(&u, &resp, "id_token_issuer", "other tenant").await;
    // Its own issuer with a tid that disagrees is refused too.
    let resp = ms_sign_in(&u, json!({ "tid": OTHER_TENANT })).await;
    assert_rejected(&u, &resp, "id_token_issuer", "tid mismatch").await;
    let resp = ms_sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn verified_looking_email_never_auto_links() {
    let u = microsoft(true, Tenancy::Multi(&[])).await;
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    let resp = ms_sign_in(&u, json!({ "email_verified": true, "xms_edov": true })).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    // The candidate account is not revealed.
    assert!(!html.contains(MOCK_EMAIL), "{html}");
    let alice = user(&u.app, MOCK_EMAIL).await.expect("alice");
    assert!(links(&u.app, &alice).await.is_empty());
    assert!(session(&u.app).await.is_none());
    assert!(audit(&u.app, AuditAction::IdentityLinked).await.is_empty());
}

#[tokio::test]
async fn shared_id_token_attacks_are_rejected() {
    let u = microsoft(true, Tenancy::Multi(&[])).await;
    let count = u.mock.attack_tokens("n").len();
    for i in 0..count {
        let started = start(&u.app, MS).await;
        let attack = u
            .mock
            .attack_tokens(started.nonce.as_deref().expect("nonce"))
            .swap_remove(i);
        u.mock.respond_with_raw_id_token(&attack.id_token);
        let resp = ms_callback(&u, &started).await;
        assert_rejected(&u, &resp, attack.reason, attack.label).await;
    }
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}

#[tokio::test]
async fn rotated_key_refreshes_the_jwks_once_and_an_unknown_kid_then_fails() {
    let u = microsoft(true, Tenancy::Multi(&[])).await;
    assert_eq!(ms_sign_in(&u, json!({})).await.status, 200);
    assert_eq!(u.mock.jwks_requests().await, 1);
    u.app.clear_cookies();
    u.mock.rotate_key();
    let resp = ms_sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(u.mock.jwks_requests().await, 2);
    u.app.clear_cookies();
    let started = start(&u.app, MS).await;
    let token = u
        .mock
        .id_token_with_unknown_kid(json!({ "nonce": started.nonce.clone().expect("nonce") }));
    u.mock.respond_with_raw_id_token(&token);
    let resp = ms_callback(&u, &started).await;
    assert_rejected(&u, &resp, "id_token_signature", "unknown kid").await;
    assert_eq!(u.mock.jwks_requests().await, 2);
}
