//! Upstream IdP transport adapter (AUTH-07, SEC-03): discovery, JWKS cache, code exchange and
//! bearer API calls against a wiremock [`MockProvider`], including the negative cases.

mod upstream_support;

use std::time::Duration;

use anvil_core::ports::{
    ApiProfile, CodeExchange, TokenEndpointAuth, UpstreamClient, UpstreamError,
};
use anvil_jose::encoding::b64std;
use anvil_jose::{Alg, verify_jwt};
use anvil_web::adapters::outbound::OutboundPolicy;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use upstream_support::{
    MOCK_ACCESS_TOKEN, MOCK_GITHUB_ID, MOCK_SUBJECT, MockKind, MockProvider, dev_upstream,
    form_field, upstream_with,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn exchange(mock: &MockProvider, auth: TokenEndpointAuth) -> CodeExchange {
    CodeExchange {
        token_endpoint: mock.token_endpoint(),
        client_id: "my client:1".into(),
        client_secret: Some(secret("s&cret+/")),
        auth,
        code: secret("the-code"),
        redirect_uri: "https://anvil.example/upstream/callback".into(),
        code_verifier: Some(secret(&"v".repeat(43))),
    }
}

/// A server answering discovery with `doc`.
async fn discovery_server(doc: impl Fn(&str) -> serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    let body = doc(&server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

fn doc(issuer: &str, base: &str) -> serde_json::Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "id_token_signing_alg_values_supported": ["RS256"],
    })
}

/// Edits a discovery document in place.
type Mutate = fn(&mut serde_json::Value);

// ----- Discovery ---------------------------------------------------------------------------------

#[tokio::test]
async fn discovery_happy_path_is_parsed_and_cached() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    let up = dev_upstream();
    let md = up.metadata(&mock.issuer()).await.expect("metadata");
    assert_eq!(md.issuer, mock.issuer());
    assert_eq!(md.authorization_endpoint, mock.authorization_endpoint());
    assert_eq!(md.token_endpoint, mock.token_endpoint());
    assert_eq!(md.userinfo_endpoint, Some(mock.userinfo_endpoint()));
    assert_eq!(md.jwks_uri, mock.jwks_uri());
    assert_eq!(md.id_token_signing_alg_values_supported, ["RS256", "ES256"]);
    assert_eq!(md.code_challenge_methods_supported, ["S256"]);
    assert!(md.authorization_response_iss_parameter_supported);

    let again = up.metadata(&mock.issuer()).await.expect("cached metadata");
    assert_eq!(again, md);
    assert_eq!(
        mock.request_count("/.well-known/openid-configuration")
            .await,
        1,
        "second call served from cache"
    );
}

#[tokio::test]
async fn discovery_issuer_mismatch_is_rejected() {
    let server = discovery_server(|base| doc("https://evil.example", base)).await;
    let err = dev_upstream().metadata(&server.uri()).await.unwrap_err();
    assert_eq!(err, UpstreamError::InvalidResponse("issuer mismatch"));

    // Exact comparison: a trailing slash is a different issuer.
    let server = discovery_server(|base| doc(base, base)).await;
    let err = dev_upstream()
        .metadata(&format!("{}/", server.uri()))
        .await
        .unwrap_err();
    assert_eq!(err, UpstreamError::InvalidResponse("issuer mismatch"));

    // Microsoft's multi-tenant document carries the {tenantid} template, never the request URL.
    let ms = MockProvider::start(MockKind::Microsoft).await;
    let err = dev_upstream()
        .metadata(&ms.discovery_issuer())
        .await
        .unwrap_err();
    assert_eq!(err, UpstreamError::InvalidResponse("issuer mismatch"));
    let md = dev_upstream()
        .metadata(&ms.issuer())
        .await
        .expect("tenant-specific discovery");
    assert_eq!(md.issuer, ms.issuer());
}

#[tokio::test]
async fn discovery_failures_are_not_cached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let base = server.uri();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc(&base, &base)))
        .with_priority(10)
        .mount(&server)
        .await;
    let up = dev_upstream();
    assert_eq!(
        up.metadata(&base).await.unwrap_err(),
        UpstreamError::Status(503)
    );
    up.metadata(&base).await.expect("retry after a failure");
}

#[tokio::test]
async fn discovery_rejects_endpoints_the_outbound_policy_refuses() {
    // http is allowed only to allow-listed destinations: 127.0.0.1 is, 10.0.0.5 is not.
    let policy = OutboundPolicy {
        allow_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
        extra_ca_pem: None,
        allow_http: true,
    };
    let cases: [(&str, Mutate); 5] = [
        ("http token endpoint to a non-allow-listed address", |d| {
            d["token_endpoint"] = json!("http://10.0.0.5/token");
        }),
        ("https jwks_uri to cloud metadata", |d| {
            d["jwks_uri"] = json!("https://169.254.169.254/jwks");
        }),
        ("non-http scheme", |d| {
            d["authorization_endpoint"] = json!("javascript:alert(1)");
        }),
        ("userinfo in URL", |d| {
            d["userinfo_endpoint"] = json!("https://user:pw@idp.example/userinfo");
        }),
        ("not a URL", |d| {
            d["token_endpoint"] = json!("/token");
        }),
    ];
    for (what, mutate) in cases {
        let server = discovery_server(|base| {
            let mut d = doc(base, base);
            mutate(&mut d);
            d
        })
        .await;
        let err = upstream_with(&policy)
            .metadata(&server.uri())
            .await
            .unwrap_err();
        assert!(
            matches!(err, UpstreamError::InvalidResponse(_)),
            "{what}: {err:?}"
        );
    }

    // Without allow_http (production policy shape) plain http is never accepted.
    let prod_like = OutboundPolicy {
        allow_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
        extra_ca_pem: None,
        allow_http: false,
    };
    let server = discovery_server(|base| doc(base, base)).await;
    assert_eq!(
        upstream_with(&prod_like)
            .metadata(&server.uri())
            .await
            .unwrap_err(),
        UpstreamError::Blocked
    );
}

#[tokio::test]
async fn malformed_discovery_document_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
        .mount(&server)
        .await;
    assert_eq!(
        dev_upstream().metadata(&server.uri()).await.unwrap_err(),
        UpstreamError::InvalidResponse("malformed discovery document")
    );
}

// ----- JWKS --------------------------------------------------------------------------------------

#[tokio::test]
async fn jwks_is_cached_and_mock_tokens_verify_against_it() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    let up = dev_upstream();
    let set = up.jwks(&mock.jwks_uri(), false).await.expect("jwks");
    assert_eq!(set.keys.len(), 2);
    let set2 = up.jwks(&mock.jwks_uri(), false).await.expect("cached jwks");
    assert_eq!(set, set2);
    assert_eq!(
        mock.jwks_requests().await,
        1,
        "second call served from cache"
    );

    // MockProvider sanity: its tokens verify against the published set; attack tokens do not.
    let rs = verify_jwt(&mock.id_token(json!({})), &set, &[Alg::RS256]).expect("RS256 verifies");
    assert_eq!(rs.claims["sub"], MOCK_SUBJECT);
    assert_eq!(rs.header.kid.as_deref(), Some(mock.rs256_kid().as_str()));
    verify_jwt(&mock.id_token_es256(json!({})), &set, &[Alg::ES256]).expect("ES256 verifies");
    let removed = verify_jwt(&mock.id_token(json!({"email": null})), &set, &[Alg::RS256])
        .expect("override token verifies");
    assert!(!removed.claims.contains_key("email"));
    assert!(verify_jwt(&mock.id_token_with_alg_none(), &set, &[Alg::RS256]).is_err());
    assert!(verify_jwt(&mock.id_token_hs256_with_public_key(), &set, &[Alg::RS256]).is_err());
}

#[tokio::test]
async fn jwks_low_max_age_is_clamped_to_five_minutes() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    mock.set_jwks_cache_control(Some("public, max-age=1"));
    let up = dev_upstream();
    up.jwks(&mock.jwks_uri(), false).await.expect("jwks");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    up.jwks(&mock.jwks_uri(), false).await.expect("jwks");
    assert_eq!(
        mock.jwks_requests().await,
        1,
        "max-age=1 is clamped to 5 min, so the entry is still fresh"
    );
    // The clamp itself (both bounds) is pinned by the unit table in adapters::upstream::jwks.
    assert_eq!(
        anvil_web::adapters::upstream::jwks::ttl_from_cache_control(Some("max-age=1")),
        Duration::from_secs(300)
    );
    assert_eq!(
        anvil_web::adapters::upstream::jwks::ttl_from_cache_control(Some("max-age=604800")),
        Duration::from_secs(86_400)
    );
}

#[tokio::test]
async fn forced_refresh_is_throttled_to_once_per_minute() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    let up = dev_upstream();
    let uri = mock.jwks_uri();
    let before = up.jwks(&uri, false).await.expect("jwks");
    assert_eq!(mock.jwks_requests().await, 1);

    // The upstream rotates; an unknown kid forces one refresh, which sees the new key.
    let new_kid = mock.rotate_key();
    let after = up.jwks(&uri, true).await.expect("forced refresh");
    assert_eq!(mock.jwks_requests().await, 2);
    assert!(
        !before
            .keys
            .iter()
            .any(|k| k.kid.as_deref() == Some(&new_kid))
    );
    assert!(
        after
            .keys
            .iter()
            .any(|k| k.kid.as_deref() == Some(&new_kid))
    );

    // Further forced refreshes within the minute are served from the cache.
    for _ in 0..5 {
        let again = up.jwks(&uri, true).await.expect("throttled refresh");
        assert_eq!(again, after);
    }
    mock.rotate_key();
    up.jwks(&uri, true).await.expect("throttled refresh");
    assert_eq!(
        mock.jwks_requests().await,
        2,
        "random-kid floods cannot cause upstream request floods"
    );
}

#[tokio::test]
async fn jwks_fetch_failures_fail_closed() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    let up = dev_upstream();

    mock.set_jwks_reply(500, json!({}));
    assert_eq!(
        up.jwks(&mock.jwks_uri(), false).await.unwrap_err(),
        UpstreamError::Status(500)
    );
    mock.set_jwks_reply(200, json!({"not": "a jwks"}));
    assert_eq!(
        up.jwks(&mock.jwks_uri(), false).await.unwrap_err(),
        UpstreamError::InvalidResponse("malformed JWKS")
    );

    // A cached set does not hide a failed forced refresh.
    mock.reset_jwks_reply();
    up.jwks(&mock.jwks_uri(), false).await.expect("jwks");
    mock.set_jwks_reply(503, json!({}));
    assert_eq!(
        up.jwks(&mock.jwks_uri(), true).await.unwrap_err(),
        UpstreamError::Status(503)
    );
}

#[tokio::test]
async fn jwks_with_private_members_is_rejected() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
        let mut key = json!({"kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB"});
        key[private] = json!("c2VjcmV0");
        mock.set_jwks_reply(200, json!({ "keys": [key] }));
        let err = dev_upstream()
            .jwks(&mock.jwks_uri(), false)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            UpstreamError::InvalidResponse("malformed JWKS"),
            "member {private}"
        );
    }
}

// ----- Token exchange ----------------------------------------------------------------------------

#[tokio::test]
async fn token_exchange_client_secret_basic() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    let tokens = dev_upstream()
        .exchange_code(&exchange(&mock, TokenEndpointAuth::Basic))
        .await
        .expect("exchange");
    assert_eq!(tokens.access_token.expose_secret(), MOCK_ACCESS_TOKEN);
    assert!(tokens.id_token.is_some());
    assert_eq!(tokens.token_type, "Bearer");

    let reqs = mock.received_token_requests().await;
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    // RFC 6749 §2.3.1: id and secret are form-urlencoded before base64.
    let expected = format!("Basic {}", b64std(b"my+client%3A1:s%26cret%2B%2F"));
    assert_eq!(r.headers.get("authorization").unwrap(), expected.as_str());
    assert_eq!(r.headers.get("accept").unwrap(), "application/json");
    assert_eq!(
        r.headers.get("content-type").unwrap(),
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        form_field(r, "grant_type").as_deref(),
        Some("authorization_code")
    );
    assert_eq!(form_field(r, "code").as_deref(), Some("the-code"));
    assert_eq!(
        form_field(r, "redirect_uri").as_deref(),
        Some("https://anvil.example/upstream/callback")
    );
    assert_eq!(
        form_field(r, "code_verifier"),
        Some("v".repeat(43)),
        "PKCE verifier sent"
    );
    assert_eq!(
        form_field(r, "client_secret"),
        None,
        "secret only in the header"
    );
    assert_eq!(form_field(r, "client_id"), None);
}

#[tokio::test]
async fn token_exchange_client_secret_post_and_no_pkce() {
    let mock = MockProvider::start(MockKind::Github).await;
    let mut ex = exchange(&mock, TokenEndpointAuth::Post);
    ex.code_verifier = None;
    let tokens = dev_upstream().exchange_code(&ex).await.expect("exchange");
    assert!(tokens.id_token.is_none(), "GitHub returns no ID token");
    assert_eq!(tokens.token_type, "bearer");

    let reqs = mock.received_token_requests().await;
    let r = &reqs[0];
    assert!(r.headers.get("authorization").is_none());
    assert_eq!(r.headers.get("accept").unwrap(), "application/json");
    assert_eq!(form_field(r, "client_id").as_deref(), Some("my client:1"));
    assert_eq!(form_field(r, "client_secret").as_deref(), Some("s&cret+/"));
    assert_eq!(form_field(r, "code_verifier"), None);
}

#[tokio::test]
async fn token_exchange_negative_responses() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    let up = dev_upstream();
    let ex = exchange(&mock, TokenEndpointAuth::Basic);

    mock.set_token_reply_raw(200, vec![b'a'; 70 * 1024], "application/json");
    assert_eq!(
        up.exchange_code(&ex).await.unwrap_err(),
        UpstreamError::TooLarge
    );

    mock.set_token_reply(
        500,
        json!({"error": "server_error", "error_description": "boom"}),
    );
    assert_eq!(
        up.exchange_code(&ex).await.unwrap_err(),
        UpstreamError::Status(500)
    );

    mock.set_token_reply(400, json!({"error": "invalid_grant"}));
    assert_eq!(
        up.exchange_code(&ex).await.unwrap_err(),
        UpstreamError::Status(400)
    );

    // GitHub reports errors with 200.
    mock.set_token_reply(
        200,
        json!({"error": "bad_verification_code", "error_description": "The code passed is incorrect or expired."}),
    );
    assert_eq!(
        up.exchange_code(&ex).await.unwrap_err(),
        UpstreamError::InvalidResponse("error response")
    );

    mock.set_token_reply_raw(
        200,
        b"access_token=x&token_type=bearer".to_vec(),
        "application/x-www-form-urlencoded",
    );
    assert_eq!(
        up.exchange_code(&ex).await.unwrap_err(),
        UpstreamError::InvalidResponse("malformed token response")
    );

    mock.set_token_reply(200, json!({"token_type": "Bearer"}));
    assert_eq!(
        up.exchange_code(&ex).await.unwrap_err(),
        UpstreamError::InvalidResponse("missing access_token")
    );

    // A redirect is never followed.
    mock.set_token_reply(302, json!({}));
    assert_eq!(
        up.exchange_code(&ex).await.unwrap_err(),
        UpstreamError::Status(302)
    );
}

#[tokio::test]
async fn upstream_errors_never_echo_bodies_or_urls() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    mock.set_token_reply(500, json!({"error_description": "SECRET-UPSTREAM-DETAIL"}));
    let err = dev_upstream()
        .exchange_code(&exchange(&mock, TokenEndpointAuth::Basic))
        .await
        .unwrap_err();
    let text = format!("{err} {err:?}");
    assert!(!text.contains("SECRET-UPSTREAM-DETAIL"));
    assert!(!text.contains("127.0.0.1"));
    assert!(!text.contains("the-code"));
}

// ----- API calls ---------------------------------------------------------------------------------

#[tokio::test]
async fn get_json_sends_bearer_and_standard_accept() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    let info = dev_upstream()
        .get_json(
            &mock.userinfo_endpoint(),
            &secret(MOCK_ACCESS_TOKEN),
            ApiProfile::Standard,
        )
        .await
        .expect("userinfo");
    assert_eq!(info["sub"], MOCK_SUBJECT);
    let reqs = mock.server.received_requests().await.unwrap();
    let r = reqs.iter().find(|r| r.url.path() == "/userinfo").unwrap();
    assert_eq!(
        r.headers.get("authorization").unwrap(),
        format!("Bearer {MOCK_ACCESS_TOKEN}").as_str()
    );
    assert_eq!(r.headers.get("accept").unwrap(), "application/json");
}

#[tokio::test]
async fn get_json_github_profile_sends_required_headers() {
    let mock = MockProvider::start(MockKind::Github).await;
    let up = dev_upstream();
    let bearer = secret(MOCK_ACCESS_TOKEN);
    let user = up
        .get_json(
            &format!("{}/user", mock.api_base_url()),
            &bearer,
            ApiProfile::Github,
        )
        .await
        .expect("github user (mock requires the GitHub headers)");
    assert_eq!(user["id"], MOCK_GITHUB_ID);
    let emails = up
        .get_json(
            &format!("{}/user/emails", mock.api_base_url()),
            &bearer,
            ApiProfile::Github,
        )
        .await
        .expect("github emails");
    assert!(emails.as_array().is_some_and(|a| a.len() == 2));

    // Without the GitHub headers the mock (like GitHub) refuses.
    assert_eq!(
        up.get_json(
            &format!("{}/user", mock.api_base_url()),
            &bearer,
            ApiProfile::Standard
        )
        .await
        .unwrap_err(),
        UpstreamError::Status(401)
    );
    let reqs = mock.server.received_requests().await.unwrap();
    let r = &reqs[0];
    assert_eq!(r.headers.get("x-github-api-version").unwrap(), "2022-11-28");
    assert_eq!(
        r.headers.get("accept").unwrap(),
        "application/vnd.github+json"
    );
    assert!(r.headers.get("user-agent").is_some());
}

#[tokio::test]
async fn get_json_rejects_non_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("eyJhbGciOi.signed.jwt"))
        .mount(&server)
        .await;
    assert_eq!(
        dev_upstream()
            .get_json(&server.uri(), &secret("t"), ApiProfile::Standard)
            .await
            .unwrap_err(),
        UpstreamError::InvalidResponse("malformed JSON")
    );
}

// ----- SSRF guard --------------------------------------------------------------------------------

#[tokio::test]
async fn production_policy_blocks_loopback_upstreams() {
    let mock = MockProvider::start(MockKind::Oidc).await;
    let up = upstream_with(&OutboundPolicy::default());
    let https_loopback = mock.base_url().replace("http://", "https://");

    assert_eq!(
        up.metadata(&mock.issuer()).await.unwrap_err(),
        UpstreamError::Blocked
    );
    assert_eq!(
        up.metadata(&https_loopback).await.unwrap_err(),
        UpstreamError::Blocked
    );
    assert_eq!(
        up.jwks(&format!("{https_loopback}/jwks"), false)
            .await
            .unwrap_err(),
        UpstreamError::Blocked
    );
    let mut ex = exchange(&mock, TokenEndpointAuth::Basic);
    ex.token_endpoint = format!("{https_loopback}/token");
    assert_eq!(
        up.exchange_code(&ex).await.unwrap_err(),
        UpstreamError::Blocked
    );
    assert_eq!(
        up.get_json(
            "https://169.254.169.254/latest/meta-data/",
            &secret("t"),
            ApiProfile::Standard
        )
        .await
        .unwrap_err(),
        UpstreamError::Blocked
    );
    assert!(
        mock.server.received_requests().await.unwrap().is_empty(),
        "nothing reached the mock"
    );
}
