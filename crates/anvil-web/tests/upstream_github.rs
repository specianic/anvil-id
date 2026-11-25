//! GitHub preset against a wiremock GitHub (AUTH-07, AUTH-11), through AnvilID's real start and
//! callback routes, on the selected backend (`ANVILID_TEST_DB`). GitHub is plain OAuth2: the
//! identity comes from `GET {api}/user` and the email only from `GET {api}/user/emails`. The
//! connection points the authorization and token endpoints and the API base at the mock (the
//! GitHub Enterprise Server override).
//!
//! Covered: the authorization request (`read:user user:email`, PKCE S256, no nonce) and the token
//! request (`client_secret_post`, the verifier); subject = the numeric `id`, so a renamed login
//! keeps the link; only the primary *and* verified address is used (a verified secondary or an
//! unverified primary never links or registers an account); the GitHub REST headers on every API
//! call (the mock answers 401 without them); a `200 {"error":...}` token answer is a generic
//! failure; a GitHub Enterprise API base with a path prefix; a profile without a numeric id.

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{
    AMR_FED, AuditAction, ConnectionConfig, EndpointOverrides, SocialConfig, SocialProvider,
};
use anvil_core::ports::Clock as _;
use anvil_jose::encoding::{b64url, sha256};
use serde_json::json;
use support::TestResponse;
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::{
    GHES_API_PREFIX, MOCK_CLIENT_ID, MOCK_EMAIL, MOCK_GITHUB_ID, MockKind, MockProvider, form_field,
};

const GITHUB: &str = "github";
const PASSWORD: &str = "correct horse battery";

/// App + GitHub mock + GitHub connection with API base `api_base` (default: the mock root).
async fn github_with(trust: bool, api_base: Option<String>) -> Upstream {
    let app = app().await;
    let mock = MockProvider::start(MockKind::Github).await;
    mock.set_now(app.clock().now().unix_timestamp());
    let config = ConnectionConfig::Social(SocialConfig {
        provider: SocialProvider::Github,
        client_id: MOCK_CLIENT_ID.into(),
        scopes: vec![],
        endpoints: EndpointOverrides {
            issuer: None,
            authorization_endpoint: Some(mock.authorization_endpoint()),
            token_endpoint: Some(mock.token_endpoint()),
            userinfo_endpoint: None,
            jwks_uri: None,
            api_base_url: Some(api_base.unwrap_or_else(|| mock.api_base_url())),
        },
        microsoft_tenant: None,
        allowed_tenants: vec![],
        hosted_domains: vec![],
        apple: None,
    });
    let conn = add_connection(&app, GITHUB, "GitHub", config, trust).await;
    Upstream { app, mock, conn }
}

async fn github() -> Upstream {
    github_with(true, None).await
}

async fn gh_callback(u: &Upstream, started: &Started) -> TestResponse {
    u.app
        .get(&callback_path(
            GITHUB,
            &[("code", "gh-code"), ("state", &started.state)],
        ))
        .await
}

/// Start + callback (the mock's token endpoint answers an access token, no ID token).
async fn gh_sign_in(u: &Upstream) -> TestResponse {
    let started = start(&u.app, GITHUB).await;
    gh_callback(u, &started).await
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
async fn sign_in_uses_the_numeric_id_pkce_and_client_secret_post() {
    let u = github().await;
    let started = start(&u.app, GITHUB).await;
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
        Some("read:user user:email")
    );
    assert_eq!(
        started.param("code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(started.nonce.is_none(), "OAuth2: no nonce");
    let resp = gh_callback(&u, &started).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = session(&u.app).await.expect("session");
    assert_eq!(s.amr, vec![AMR_FED.to_owned()]);

    // The primary verified address registered the account, not the verified secondary.
    let octo = user(&u.app, MOCK_EMAIL).await.expect("registered");
    assert_eq!(s.user_id, octo.id);
    assert!(octo.email_verified);
    assert!(user(&u.app, "octo-secondary@example.com").await.is_none());
    assert_eq!(octo.claims.name.as_deref(), Some("Octo Cat"));
    let l = links(&u.app, &octo).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].subject, MOCK_GITHUB_ID.to_string());
    assert_eq!(l[0].metadata.get("login"), Some(&json!("octo")));

    // client_secret_post + the PKCE verifier; no Basic header.
    let reqs = u.mock.received_token_requests().await;
    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].headers.get("authorization").is_none());
    assert_eq!(
        form_field(&reqs[0], "client_secret").as_deref(),
        Some(SECRET)
    );
    assert_eq!(
        form_field(&reqs[0], "client_id").as_deref(),
        Some(MOCK_CLIENT_ID)
    );
    let verifier = form_field(&reqs[0], "code_verifier").expect("verifier");
    assert_eq!(
        Some(b64url(&sha256(verifier.as_bytes()))),
        started.param("code_challenge")
    );
    assert_eq!(
        reqs[0].headers.get("accept").and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "GitHub answers form-encoded without it"
    );
}

#[tokio::test]
async fn api_calls_carry_the_github_rest_headers() {
    let u = github().await;
    assert_eq!(gh_sign_in(&u).await.status, 200);
    let requests = u.mock.server.received_requests().await.expect("recorded");
    let api: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().starts_with("/user"))
        .collect();
    assert_eq!(api.len(), 2, "/user and /user/emails");
    for r in api {
        let h = |n: &str| r.headers.get(n).and_then(|v| v.to_str().ok());
        assert_eq!(h("accept"), Some("application/vnd.github+json"));
        assert_eq!(h("x-github-api-version"), Some("2022-11-28"));
        assert!(h("user-agent").is_some_and(|ua| !ua.is_empty()));
        assert_eq!(
            h("authorization").map(str::to_owned),
            Some(format!("Bearer {}", upstream_support::MOCK_ACCESS_TOKEN))
        );
    }
}

#[tokio::test]
async fn renamed_login_keeps_the_link() {
    let u = github().await;
    assert_eq!(gh_sign_in(&u).await.status, 200);
    let octo = user(&u.app, MOCK_EMAIL).await.expect("registered");
    u.app.clear_cookies();
    // The login and the primary email change at GitHub; the numeric id does not.
    u.mock
        .set_github_user(json!({ "id": MOCK_GITHUB_ID, "login": "octo-renamed", "name": null }));
    u.mock.set_github_emails(json!([
        { "email": "new-primary@example.com", "primary": true, "verified": true },
    ]));
    let resp = gh_sign_in(&u).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, octo.id);
    assert_eq!(links(&u.app, &octo).await.len(), 1);
    assert!(user(&u.app, "new-primary@example.com").await.is_none());

    // Another account with the same login string but another id is another identity.
    u.app.clear_cookies();
    u.mock
        .set_github_user(json!({ "id": MOCK_GITHUB_ID + 1, "login": "octo" }));
    u.mock.set_github_emails(json!([
        { "email": "impostor@example.com", "primary": true, "verified": true },
    ]));
    assert_eq!(gh_sign_in(&u).await.status, 200);
    let other = user(&u.app, "impostor@example.com").await.expect("other");
    assert_ne!(other.id, octo.id);
}

#[tokio::test]
async fn only_a_primary_and_verified_email_is_used() {
    let u = github().await;
    // A verified local account for each address GitHub lists.
    for e in ["primary-unverified@example.com", "secondary@example.com"] {
        register(&u.app, "", e, PASSWORD).await;
        mark_verified(&u.app, e).await;
    }
    u.app.clear_cookies();
    u.mock.set_github_emails(json!([
        { "email": "primary-unverified@example.com", "primary": true, "verified": false },
        { "email": "secondary@example.com", "primary": false, "verified": true },
        { "email": "string-flags@example.com", "primary": "true", "verified": "true" },
    ]));
    let resp = gh_sign_in(&u).await;
    // No usable address: neither linked to an existing account nor registered.
    assert_rejected(&u, &resp, "email_missing", "no verified primary").await;
    for e in ["primary-unverified@example.com", "secondary@example.com"] {
        let local = user(&u.app, e).await.expect("local");
        assert!(links(&u.app, &local).await.is_empty(), "{e}");
    }
    assert!(user(&u.app, "string-flags@example.com").await.is_none());
    assert!(audit(&u.app, AuditAction::IdentityLinked).await.is_empty());

    // No emails at all (e.g. the list is empty): the same.
    u.mock.set_github_emails(json!([]));
    let resp = gh_sign_in(&u).await;
    assert_rejected(&u, &resp, "email_missing", "empty list").await;
}

#[tokio::test]
async fn verified_primary_auto_links_a_verified_local_account() {
    let u = github().await;
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    let local = user(&u.app, MOCK_EMAIL).await.expect("local");
    u.app.clear_cookies();
    let resp = gh_sign_in(&u).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, local.id);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked[0].details.as_map()["mode"], "auto");
}

#[tokio::test]
async fn token_endpoint_error_with_200_is_a_generic_failure() {
    let u = github().await;
    u.mock.set_token_reply(
        200,
        json!({
            "error": "bad_verification_code",
            "error_description": "The code passed is incorrect or expired.",
        }),
    );
    let resp = gh_sign_in(&u).await;
    assert_rejected(&u, &resp, "exchange_failed", "200 with error").await;
    assert!(!resp.text().contains("bad_verification_code"));
    assert_eq!(u.mock.request_count("/user").await, 0, "no API call");
}

#[tokio::test]
async fn profile_without_a_numeric_id_is_rejected() {
    let u = github().await;
    for (profile, label) in [
        (json!({ "login": "octo" }), "missing id"),
        (json!({ "id": "4242", "login": "octo" }), "string id"),
        (json!({ "id": -1, "login": "octo" }), "negative id"),
    ] {
        u.mock.set_github_user(profile);
        let resp = gh_sign_in(&u).await;
        assert_rejected(&u, &resp, "claim_missing", label).await;
    }
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}

#[tokio::test]
async fn github_enterprise_api_base_override() {
    let u = github_with(true, None).await;
    // Rebuild the connection with an Enterprise-style base (path prefix, trailing slash).
    let base = format!("{}{GHES_API_PREFIX}/", u.mock.base_url());
    let u = {
        let mut config = u.conn.config.clone();
        if let ConnectionConfig::Social(s) = &mut config {
            s.endpoints.api_base_url = Some(base);
        }
        let conn = add_connection(&u.app, "ghes", "GitHub Enterprise", config, true).await;
        Upstream {
            app: u.app,
            mock: u.mock,
            conn,
        }
    };
    let started = start(&u.app, "ghes").await;
    let resp = u
        .app
        .get(&callback_path(
            "ghes",
            &[("code", "gh-code"), ("state", &started.state)],
        ))
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(user(&u.app, MOCK_EMAIL).await.is_some());
    assert_eq!(
        u.mock
            .request_count(&format!("{GHES_API_PREFIX}/user"))
            .await,
        1
    );
    assert_eq!(
        u.mock
            .request_count(&format!("{GHES_API_PREFIX}/user/emails"))
            .await,
        1
    );
    assert_eq!(u.mock.request_count("/user").await, 0);
}
