//! Pushed authorization requests (RFC 9126, RFC 10070): every control has a named negative test.
//! A `request_uri` is single-use, short-lived and bound to its client; pushing requires client
//! authentication exactly like `/token`; errors are JSON at `/par` and error pages (never
//! redirects) for unusable `request_uri`s at `/authorize`; clients and tenants can require PAR.

mod authz;
mod par_support;
mod support;
mod token_support;

use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::ClientAuthMethod;
use anvil_core::ports::Clock;
use par_support::*;
use support::{TestApp, json};
use token_support::{Auth, REDIRECT, assert_oauth_error, basic, token_at};

/// The themed error page for `invalid_request`, with no redirect.
fn assert_no_redirect_page(resp: &support::TestResponse) {
    authz::assert_error_page(resp, "invalid_request");
}

#[tokio::test]
async fn par_request_uri_single_use() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;
    let request_uri = push_default(&app, &client).await;

    let first = authorize(&app, client.id(), &request_uri, &[], Some(&cookie)).await;
    code_of(&first, &iss);
    // A reload (or a replay) gets the error page, never a second code.
    let again = authorize(&app, client.id(), &request_uri, &[], Some(&cookie)).await;
    assert_no_redirect_page(&again);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn par_request_uri_concurrent_single_winner() {
    let app = Arc::new(TestApp::new().await);
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = Arc::new(signed_in(&app, "ada@example.test").await);
    let request_uri = Arc::new(push_default(&app, &client).await);
    let client_id = Arc::new(client.id().to_owned());

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (app, cookie, uri, id) = (
            Arc::clone(&app),
            Arc::clone(&cookie),
            Arc::clone(&request_uri),
            Arc::clone(&client_id),
        );
        set.spawn(async move { authorize(&app, &id, &uri, &[], Some(&cookie)).await });
    }
    let mut winners = 0;
    let mut losers = 0;
    while let Some(resp) = set.join_next().await {
        let resp = resp.expect("task");
        match resp.status.as_u16() {
            303 => {
                code_of(&resp, &iss);
                winners += 1;
            }
            400 => {
                assert_no_redirect_page(&resp);
                losers += 1;
            }
            other => panic!("unexpected status {other}: {}", resp.text()),
        }
    }
    assert_eq!((winners, losers), (1, 7));
}

#[tokio::test]
async fn par_request_uri_expires() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;

    // Just inside the lifetime it works.
    let live = push_default(&app, &client).await;
    app.clock().advance(Duration::from_secs(59));
    code_of(
        &authorize(&app, client.id(), &live, &[], Some(&cookie)).await,
        &iss,
    );

    // At expires_in it is gone.
    let request_uri = push_default(&app, &client).await;
    app.clock().advance(Duration::from_secs(60));
    let resp = authorize(&app, client.id(), &request_uri, &[], Some(&cookie)).await;
    assert_no_redirect_page(&resp);
}

#[tokio::test]
async fn par_request_uri_bound_to_client() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let owner = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let other = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;
    let request_uri = push_default(&app, &owner).await;

    let resp = authorize(&app, other.id(), &request_uri, &[], Some(&cookie)).await;
    assert_no_redirect_page(&resp);
    assert!(
        resp.html().contains("data-error-key=\"invalid_request\""),
        "{}",
        resp.html()
    );

    // The mismatched attempt used the request up: a leaked request_uri cannot be retried.
    let resp = authorize(&app, owner.id(), &request_uri, &[], Some(&cookie)).await;
    assert_no_redirect_page(&resp);

    // Without client_id there is no binding to check against.
    let fresh = push_default(&app, &owner).await;
    let resp = authz::get(
        &app,
        &authz::authorize_path("", &[("request_uri", &fresh)]),
        Some(&cookie),
    )
    .await;
    assert_no_redirect_page(&resp);
    let _ = iss;
}

#[tokio::test]
async fn par_non_urn_request_uri_refused() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;

    // Request objects by reference are never fetched: unchanged request_uri_not_supported.
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", client.id()),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "s"),
        ("code_challenge", token_support::CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    pairs.push(("request_uri", "https://rp.test/request.jwt"));
    let resp = authz::get(&app, &authz::authorize_path("", &pairs), Some(&cookie)).await;
    authz::assert_error_redirect(&resp, REDIRECT, "request_uri_not_supported", &iss);

    // A PAR URN that is not well formed (42 or 44 characters, not base64url) is unusable.
    for bad in [
        format!("{PREFIX}{}", "a".repeat(42)),
        format!("{PREFIX}{}", "a".repeat(44)),
        format!("{PREFIX}{}+", "a".repeat(42)),
    ] {
        let resp = authorize(&app, client.id(), &bad, &[], Some(&cookie)).await;
        assert_no_redirect_page(&resp);
    }
}

#[tokio::test]
async fn par_unknown_request_uri_no_redirect() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;
    let unknown = format!("{PREFIX}{}", "A".repeat(43));
    let resp = authorize(
        &app,
        client.id(),
        &unknown,
        &[("redirect_uri", REDIRECT), ("state", "x")],
        Some(&cookie),
    )
    .await;
    assert_no_redirect_page(&resp);
}

#[tokio::test]
async fn par_confidential_client_requires_auth() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    // client_id alone (the public-client form) is not authentication for a confidential client.
    let resp = push(&app, &Auth::None(client.id().to_owned()), &pushed_params()).await;
    assert_oauth_error(&resp, 401, "invalid_client");
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    // No credentials at all.
    let resp = push_raw(&app, None, &pushed_params()).await;
    assert_oauth_error(&resp, 401, "invalid_client");
}

#[tokio::test]
async fn par_wrong_secret_refused() {
    let app = TestApp::new().await;
    let basic_client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let resp = push_raw(
        &app,
        Some(&basic(basic_client.id(), "not-the-secret")),
        &pushed_params(),
    )
    .await;
    assert_oauth_error(&resp, 401, "invalid_client");
    assert!(
        resp.header("www-authenticate")
            .is_some_and(|h| h.starts_with("Basic")),
        "Basic challenge"
    );

    let post_client = par_client(&app, ClientAuthMethod::ClientSecretPost).await;
    let resp = push(
        &app,
        &Auth::Post(post_client.id().to_owned(), "not-the-secret".to_owned()),
        &pushed_params(),
    )
    .await;
    assert_oauth_error(&resp, 401, "invalid_client");
}

#[tokio::test]
async fn par_request_uri_in_body_refused() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let earlier = push_default(&app, &client).await;
    let mut pairs = pushed_params();
    pairs.push(("request_uri", &earlier));
    let resp = push(&app, &client.auth(&app.issuer(None)), &pairs).await;
    assert_oauth_error(&resp, 400, "invalid_request");
    assert!(resp.header("location").is_none());
}

#[tokio::test]
async fn par_request_object_not_supported() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let mut pairs = pushed_params();
    pairs.push(("request", "eyJhbGciOiJub25lIn0.e30."));
    let resp = push(&app, &client.auth(&app.issuer(None)), &pairs).await;
    assert_oauth_error(&resp, 400, "request_not_supported");
    assert!(resp.header("location").is_none());
}

#[tokio::test]
async fn par_client_assertion_aud_par_endpoint_refused() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::PrivateKeyJwt).await;
    let key = client.key.as_ref().expect("key");
    // RFC 10070: the issuer is the only accepted audience, not the PAR or token endpoint URL.
    for aud in [format!("{iss}/par"), format!("{iss}/token")] {
        let resp = push(
            &app,
            &Auth::Assertion(assertion(key, client.id(), &aud)),
            &pushed_params(),
        )
        .await;
        assert_oauth_error(&resp, 401, "invalid_client");
    }
    // The issuer works.
    push_ok(
        &app,
        &Auth::Assertion(assertion(key, client.id(), &iss)),
        &pushed_params(),
    )
    .await;
}

#[tokio::test]
async fn par_jti_replay_shared_with_token() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::PrivateKeyJwt).await;
    let key = client.key.as_ref().expect("key");

    // Used at /par, replayed at /par and at /token.
    let used = assertion(key, client.id(), &iss);
    push_ok(&app, &Auth::Assertion(used.clone()), &pushed_params()).await;
    let resp = push(&app, &Auth::Assertion(used.clone()), &pushed_params()).await;
    assert_oauth_error(&resp, 401, "invalid_client");
    let token_pairs = [
        ("grant_type", "authorization_code"),
        ("code", "unknown-code"),
        ("redirect_uri", REDIRECT),
        ("code_verifier", token_support::VERIFIER),
    ];
    let resp = token_at(&app, "/token", &Auth::Assertion(used), &token_pairs).await;
    assert_oauth_error(&resp, 401, "invalid_client");

    // Used at /token first (the grant fails, the assertion is recorded), then refused at /par.
    let at_token = assertion(key, client.id(), &iss);
    let resp = token_at(
        &app,
        "/token",
        &Auth::Assertion(at_token.clone()),
        &token_pairs,
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_grant");
    let resp = push(&app, &Auth::Assertion(at_token), &pushed_params()).await;
    assert_oauth_error(&resp, 401, "invalid_client");
}

#[tokio::test]
async fn par_redirect_uri_must_match_registered() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let auth = client.auth(&app.issuer(None));
    // RFC 9126 §2.4 would allow relaxing this for authenticated clients; we do not.
    for uri in [
        "https://rp.test/cb/other",
        "https://rp.test/cb?x=1",
        "https://evil.example/cb",
    ] {
        let pairs: Vec<(&str, &str)> = pushed_params()
            .into_iter()
            .map(|(k, v)| {
                if k == "redirect_uri" {
                    (k, uri)
                } else {
                    (k, v)
                }
            })
            .collect();
        let resp = push(&app, &auth, &pairs).await;
        assert_oauth_error(&resp, 400, "invalid_request");
        assert!(resp.header("location").is_none());
    }
    // Missing redirect_uri is refused too (OIDC requests require it).
    let pairs: Vec<(&str, &str)> = pushed_params()
        .into_iter()
        .filter(|(k, _)| *k != "redirect_uri")
        .collect();
    let resp = push(&app, &auth, &pairs).await;
    assert_oauth_error(&resp, 400, "invalid_request");
}

#[tokio::test]
async fn par_required_client_plain_authorize_refused() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client_with(&app, ClientAuthMethod::ClientSecretBasic, |c| {
        c.require_pushed_authorization_requests = true;
    })
    .await;
    let cookie = signed_in(&app, "ada@example.test").await;

    let mut plain = pushed_params();
    plain.push(("client_id", client.id()));
    let resp = authz::get(&app, &authz::authorize_path("", &plain), Some(&cookie)).await;
    authz::assert_error_redirect(&resp, REDIRECT, "invalid_request", &iss);
    assert!(authz::param(&resp, "code").is_none());

    // An untrusted redirect URI still gets the error page, never a redirect.
    let bad: Vec<(&str, &str)> = plain
        .iter()
        .map(|&(k, v)| {
            if k == "redirect_uri" {
                (k, "https://evil.example/cb")
            } else {
                (k, v)
            }
        })
        .collect();
    let resp = authz::get(&app, &authz::authorize_path("", &bad), Some(&cookie)).await;
    authz::assert_error_page(&resp, "redirect_uri_mismatch");

    // The pushed request works.
    let request_uri = push_default(&app, &client).await;
    code_of(
        &authorize(&app, client.id(), &request_uri, &[], Some(&cookie)).await,
        &iss,
    );
}

#[tokio::test]
async fn par_tenant_required_plain_authorize_refused() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;
    require_par_for_tenant(&app, true).await;

    let mut plain = pushed_params();
    plain.push(("client_id", client.id()));
    let resp = authz::get(&app, &authz::authorize_path("", &plain), Some(&cookie)).await;
    authz::assert_error_redirect(&resp, REDIRECT, "invalid_request", &iss);

    let request_uri = push_default(&app, &client).await;
    code_of(
        &authorize(&app, client.id(), &request_uri, &[], Some(&cookie)).await,
        &iss,
    );

    // Switched off again, the plain request works.
    require_par_for_tenant(&app, false).await;
    let resp = authz::get(&app, &authz::authorize_path("", &plain), Some(&cookie)).await;
    code_of(&resp, &iss);
}

#[tokio::test]
async fn par_no_interaction_errors() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let auth = || client.auth(&app.issuer(None));
    // No session is looked at when pushing: prompt=none, prompt=login and prompt=consent are
    // accepted (they are decided at /authorize), never login_required / consent_required.
    for prompt in ["none", "login", "consent", "select_account"] {
        let mut pairs = pushed_params();
        pairs.push(("prompt", prompt));
        let resp = push(&app, &auth(), &pairs).await;
        assert_eq!(resp.status, 201, "prompt={prompt}: {}", resp.text());
    }
    // Validation errors are JSON errors, not interaction errors or redirects.
    let mut pairs = pushed_params();
    pairs.push(("prompt", "none login"));
    let resp = push(&app, &auth(), &pairs).await;
    assert_oauth_error(&resp, 400, "invalid_request");
    let body = json(&resp);
    for interaction in [
        "login_required",
        "consent_required",
        "interaction_required",
        "account_selection_required",
    ] {
        assert_ne!(body["error"], interaction);
    }
}

#[tokio::test]
async fn par_policy_rechecked_at_use() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let cookie = signed_in(&app, "ada@example.test").await;
    let tenant = authz::default_tenant(&app).id;

    // The client switches to PAR-only scopes without openid between push and use.
    let request_uri = push_default(&app, &client).await;
    app.storage()
        .clients()
        .update(
            tenant,
            client.id(),
            &anvil_core::model::ClientUpdate {
                scopes: Some(vec!["profile".into()]),
                ..Default::default()
            },
            app.clock().now(),
        )
        .await
        .expect("update")
        .expect("client exists");
    let resp = authorize(&app, client.id(), &request_uri, &[], Some(&cookie)).await;
    authz::assert_error_redirect(&resp, REDIRECT, "invalid_scope", &iss);

    // The client is deleted between push and use.
    let other = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let request_uri = push_default(&app, &other).await;
    app.storage()
        .clients()
        .delete(tenant, other.id())
        .await
        .expect("delete");
    let resp = authorize(&app, other.id(), &request_uri, &[], Some(&cookie)).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(resp.headers.get("location").is_none());
}

#[tokio::test]
async fn par_id_token_hint_refused() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let mut pairs = pushed_params();
    pairs.push(("id_token_hint", "eyJhbGciOiJSUzI1NiJ9.e30.sig"));
    let resp = push(&app, &client.auth(&app.issuer(None)), &pairs).await;
    assert_oauth_error(&resp, 400, "invalid_request");
}

#[tokio::test]
async fn par_body_client_id_must_match_credentials() {
    let app = TestApp::new().await;
    let client = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let other = par_client(&app, ClientAuthMethod::ClientSecretBasic).await;
    let mut pairs = pushed_params();
    pairs.push(("client_id", other.id()));
    let resp = push(&app, &client.auth(&app.issuer(None)), &pairs).await;
    assert_oauth_error(&resp, 401, "invalid_client");
}

#[tokio::test]
async fn par_requires_form_body() {
    let app = TestApp::new().await;
    let resp = app
        .send(
            axum::http::Request::post(PAR)
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .expect("request"),
        )
        .await;
    assert_oauth_error(&resp, 400, "invalid_request");
}
