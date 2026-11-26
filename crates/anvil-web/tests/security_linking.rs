//! Account-linking and upstream-callback threat model (AUTH-07, AUTH-11), on the selected backend
//! (`ANVILID_TEST_DB`). Every control has a negative test:
//!
//! - linking: an unverified upstream email, an untrusted connection, a Microsoft connection
//!   (admin-controlled addresses) or an unverified local account never auto-link; the
//!   confirmation page for an unexposed candidate reveals nothing about the account;
//! - the callback: missing or wrong binding cookie, tampered `state`, a replayed callback, an ID
//!   token with another nonce and an RFC 9207 `iss` mismatch are all rejected, and each leaves
//!   no session;
//! - the start is a CSRF-protected form POST; the callback is the only UI route that accepts a
//!   cross-site POST;
//! - an upstream identity linked to one user cannot be linked to another from the account page;
//! - a forged or mismatched callback never clears the binding cookie, so it cannot cancel the
//!   browser's pending sign-in; only a callback whose `state` and binding cookie match does;
//! - under `require_verified_email`, an upstream sign-in to an account whose email is not
//!   verified (just created from an untrusted upstream, or through an existing link) creates no
//!   session;
//! - the UserInfo fallback refuses a UserInfo `sub` that differs from the ID token's.

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{
    AuditAction, ConnectionConfig, EndpointOverrides, SocialConfig, SocialProvider,
};
use anvil_core::ports::Clock as _;
use serde_json::json;
use support::{TestResponse, csrf_from};
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::{MOCK_CLIENT_ID, MOCK_EMAIL, MockKind, MockProvider};

const PASSWORD: &str = "correct horse battery";

/// Alice has a local password account whose email equals the upstream one.
async fn local_alice(u: &Upstream, verified: bool) {
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    if verified {
        mark_verified(&u.app, MOCK_EMAIL).await;
    }
}

async fn alice_links(u: &Upstream) -> usize {
    let alice = user(&u.app, MOCK_EMAIL).await.expect("alice");
    links(&u.app, &alice).await.len()
}

/// The answer is the link confirmation page, nothing is linked and nobody is signed in.
async fn assert_confirmation_only(u: &Upstream, resp: &TestResponse) -> String {
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    assert_eq!(alice_links(u).await, 0);
    assert!(session(&u.app).await.is_none());
    assert!(audit(&u.app, AuditAction::IdentityLinked).await.is_empty());
    html
}

/// The answer is the generic error on a fresh sign-in form and nobody is signed in.
async fn assert_rejected(u: &Upstream, resp: &TestResponse, reason: &str) {
    assert_eq!(resp.status, 400, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "login", "{html}");
    assert!(
        message_keys(&html).contains(&"upstream.failed".to_owned()),
        "{html}"
    );
    assert!(session(&u.app).await.is_none(), "no session");
    assert_eq!(
        failure_reasons(&u.app).await.first().map(String::as_str),
        Some(reason)
    );
}

#[tokio::test]
async fn unverified_upstream_email_never_auto_links_and_hides_the_account() {
    let u = setup(true).await;
    local_alice(&u, true).await;
    let resp = sign_in(&u, json!({ "email_verified": false })).await;
    let html = assert_confirmation_only(&u, &resp).await;
    // The candidate is not revealed: no prefilled address, the email appears nowhere.
    assert!(!html.contains(MOCK_EMAIL), "{html}");
    assert!(!html.contains("value=\"alice"), "{html}");
}

#[tokio::test]
async fn untrusted_connection_with_a_verified_email_needs_confirmation() {
    let u = setup(false).await;
    local_alice(&u, true).await;
    let resp = sign_in(&u, json!({})).await;
    let html = assert_confirmation_only(&u, &resp).await;
    assert!(!html.contains(MOCK_EMAIL), "{html}");
}

#[tokio::test]
async fn unverified_local_account_is_never_auto_linked() {
    let u = setup(true).await;
    local_alice(&u, false).await;
    let resp = sign_in(&u, json!({})).await;
    assert_confirmation_only(&u, &resp).await;
}

#[tokio::test]
async fn confirmation_page_does_not_tell_whether_an_untrusted_email_has_an_account() {
    // An untrusted connection asserting the address of an existing account: the page shows the
    // generic explanation without the address, the same text whatever the address.
    let u = setup(false).await;
    local_alice(&u, true).await;
    let resp = sign_in(&u, json!({})).await;
    let html = assert_confirmation_only(&u, &resp).await;
    let identifier_value = html
        .split("id=\"identifier\"")
        .nth(1)
        .and_then(|rest| rest.split('>').next())
        .unwrap_or_default()
        .to_owned();
    assert!(!identifier_value.contains("value="), "{identifier_value}");
    assert!(html.contains("Sign in to it to connect Acme ID"), "{html}");
}

#[tokio::test]
async fn microsoft_email_never_auto_links_even_when_trusted() {
    let app = app().await;
    let ms = MockProvider::start(MockKind::Microsoft).await;
    ms.set_now(app.clock().now().unix_timestamp());
    let config = ConnectionConfig::Social(SocialConfig {
        provider: SocialProvider::Microsoft,
        client_id: MOCK_CLIENT_ID.into(),
        scopes: vec![],
        endpoints: EndpointOverrides {
            issuer: Some(ms.issuer_template()),
            authorization_endpoint: Some(ms.authorization_endpoint()),
            token_endpoint: Some(ms.token_endpoint()),
            userinfo_endpoint: Some(ms.userinfo_endpoint()),
            jwks_uri: Some(ms.jwks_uri()),
            api_base_url: None,
        },
        microsoft_tenant: None,
        allowed_tenants: vec![],
        hosted_domains: vec![],
        apple: None,
    });
    let conn = add_connection(&app, "ms", "Microsoft", config, true).await;
    let u = Upstream {
        app,
        mock: ms,
        conn,
    };
    local_alice(&u, true).await;
    let started = start(&u.app, "ms").await;
    reply_for(&u, &started, json!({}));
    let resp = u
        .app
        .get(&callback_path(
            "ms",
            &[("code", "code-1"), ("state", &started.state)],
        ))
        .await;
    assert_confirmation_only(&u, &resp).await;
}

#[tokio::test]
async fn callback_without_the_binding_cookie_is_rejected_and_keeps_the_flow() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    reply_for(&u, &started, json!({}));
    let binding = binding_cookie_name(&u.app);
    let value = u.app.cookies()[&binding].clone();
    let iss = u.mock.issuer();
    let path = callback_path(
        SLUG,
        &[("code", "code-1"), ("state", &started.state), ("iss", &iss)],
    );
    // Login CSRF: the callback arrives in a browser that did not start the sign-in.
    let resp = get_with_cookies(&u.app, &path, |k| k != binding, None).await;
    assert_rejected(&u, &resp, "binding_invalid").await;
    assert!(
        u.mock.received_token_requests().await.is_empty(),
        "no code exchange"
    );
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
    // The forged callback did not consume the pending sign-in: the browser holding the binding
    // cookie completes it.
    let ok = get_with_cookies(&u.app, &path, |_| true, Some((&binding, &value))).await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert!(session(&u.app).await.is_some());
}

#[tokio::test]
async fn callback_with_another_binding_cookie_is_rejected() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    reply_for(&u, &started, json!({}));
    let binding = binding_cookie_name(&u.app);
    let iss = u.mock.issuer();
    let path = callback_path(
        SLUG,
        &[("code", "code-1"), ("state", &started.state), ("iss", &iss)],
    );
    let resp = get_with_cookies(
        &u.app,
        &path,
        |k| k != binding,
        Some((&binding, "attacker-binding-value")),
    )
    .await;
    assert_rejected(&u, &resp, "binding_invalid").await;
    assert!(u.mock.received_token_requests().await.is_empty());
}

#[tokio::test]
async fn tampered_or_foreign_state_is_rejected() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    reply_for(&u, &started, json!({}));
    let iss = u.mock.issuer();
    let (flow, _) = started.state.split_once('.').expect("state");
    for state in [
        format!("{flow}.tampered-random-part-0123456789abcdef"),
        format!("{}.whatever", uuid::Uuid::now_v7()),
        "no-flow-id".to_owned(),
    ] {
        let resp = u
            .app
            .get(&callback_path(
                SLUG,
                &[("code", "code-1"), ("state", &state), ("iss", &iss)],
            ))
            .await;
        assert_eq!(resp.status, 400, "{state}: {}", resp.text());
        assert!(session(&u.app).await.is_none());
    }
    assert!(u.mock.received_token_requests().await.is_empty());
    let reasons = failure_reasons(&u.app).await;
    assert_eq!(
        reasons,
        vec!["state_invalid", "flow_expired", "state_invalid"]
    );
    // A callback for another connection's slug with this state is refused too.
    let other = add_connection(&u.app, "other", "Other", u.conn.config.clone(), true).await;
    let resp = u
        .app
        .get(&callback_path(
            &other.slug,
            &[("code", "code-1"), ("state", &started.state), ("iss", &iss)],
        ))
        .await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        failure_reasons(&u.app).await.first().map(String::as_str),
        Some("connection_mismatch")
    );
}

#[tokio::test]
async fn a_replayed_callback_is_rejected() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    reply_for(&u, &started, json!({}));
    let name = binding_cookie_name(&u.app);
    let binding = u.app.cookies()[&name].clone();
    let first = callback(&u, &started).await;
    assert_eq!(first.status, 200, "{}", first.text());
    // Same state again (with the binding cookie restored and without the new session).
    u.app.clear_cookies();
    let iss = u.mock.issuer();
    let path = callback_path(
        SLUG,
        &[("code", "code-1"), ("state", &started.state), ("iss", &iss)],
    );
    let again = get_with_cookies(&u.app, &path, |_| false, Some((&name, &binding))).await;
    assert_eq!(again.status, 400, "{}", again.text());
    assert!(session(&u.app).await.is_none());
    assert_eq!(
        u.mock.received_token_requests().await.len(),
        1,
        "one exchange"
    );
    assert_eq!(audit(&u.app, AuditAction::LoginSucceeded).await.len(), 1);
}

#[tokio::test]
async fn an_id_token_for_another_nonce_is_rejected() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    u.mock
        .respond_with_id_token(json!({ "nonce": "nonce-of-another-sign-in" }));
    let resp = callback(&u, &started).await;
    assert_rejected(&u, &resp, "nonce_mismatch").await;
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
    // An ID token without a nonce is rejected too.
    let started = start(&u.app, SLUG).await;
    u.mock.respond_with_id_token(json!({}));
    let resp = callback(&u, &started).await;
    assert_rejected(&u, &resp, "nonce_mismatch").await;
}

#[tokio::test]
async fn rfc9207_iss_must_match_when_the_provider_advertises_it() {
    let u = setup(true).await;
    for (iss, label) in [(Some("https://evil.example"), "wrong"), (None, "missing")] {
        let started = start(&u.app, SLUG).await;
        reply_for(&u, &started, json!({}));
        let mut pairs = vec![("code", "code-1"), ("state", started.state.as_str())];
        if let Some(i) = iss {
            pairs.push(("iss", i));
        }
        let resp = u.app.get(&callback_path(SLUG, &pairs)).await;
        assert_eq!(resp.status, 400, "{label}: {}", resp.text());
        assert!(session(&u.app).await.is_none(), "{label}");
        assert_eq!(
            failure_reasons(&u.app).await.first().map(String::as_str),
            Some("iss_mismatch"),
            "{label}"
        );
    }
    assert!(u.mock.received_token_requests().await.is_empty());
}

#[tokio::test]
async fn provider_error_is_a_generic_error_without_echoing_it() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    let resp = u
        .app
        .get(&callback_path(
            SLUG,
            &[
                ("error", "access_denied"),
                ("error_description", "<script>alert(1)</script>"),
                ("state", &started.state),
                ("iss", &u.mock.issuer()),
            ],
        ))
        .await;
    assert_rejected(&u, &resp, "provider_error").await;
    assert!(!resp.text().contains("alert(1)"));
    assert!(!resp.text().contains("access_denied"));
}

#[tokio::test]
async fn start_requires_the_csrf_token_and_the_flow_cookie() {
    let u = setup(true).await;
    let html = u.app.get("/ui/login").await.html();
    let action = button_action(&u.app, &html, SLUG);
    let missing = u.app.post_form(&action, &[]).await;
    assert_eq!(missing.status, 403, "{}", missing.text());
    let wrong = u
        .app
        .post_form(&action, &[("csrf_token", "not-the-token")])
        .await;
    assert_eq!(wrong.status, 403, "{}", wrong.text());
    // The right token without the flow cookie is refused as well.
    let csrf = csrf_from(&html);
    let flow = flow_cookie(&u.app).expect("flow cookie").0;
    let body = format!("csrf_token={csrf}");
    let resp = u
        .app
        .send(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri(&action)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin")
                .header(
                    "cookie",
                    u.app
                        .cookies()
                        .into_iter()
                        .filter(|(k, _)| *k != flow)
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("; "),
                )
                .body(axum::body::Body::from(body))
                .expect("request"),
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert!(
        !u.app
            .cookies()
            .keys()
            .any(|k| k.contains("anvil_upstream_"))
    );
    // An unknown connection is a 404.
    let unknown = u
        .app
        .post_form(
            &action.replace(SLUG, "nope"),
            &[("csrf_token", &csrf_from(&html))],
        )
        .await;
    assert_eq!(unknown.status, 404, "{}", unknown.text());
}

#[tokio::test]
async fn only_the_callback_accepts_a_cross_site_post() {
    let u = setup(true).await;
    let cross_site = |path: String| {
        axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "cross-site")
            .body(axum::body::Body::from("state=x&code=y"))
            .expect("request")
    };
    let callback = u
        .app
        .send(cross_site(format!("/ui/login/upstream/{SLUG}/callback")))
        .await;
    assert_eq!(callback.status, 303, "{}", callback.text());
    for path in [
        "/ui/login".to_owned(),
        format!("/ui/login/upstream/{SLUG}?flow=00000000-0000-0000-0000-000000000000"),
        "/ui/registration".to_owned(),
    ] {
        let resp = u.app.send(cross_site(path.clone())).await;
        assert_eq!(resp.status, 403, "{path}: {}", resp.text());
    }
    // The posted values change nothing without a matching pending sign-in.
    assert!(session(&u.app).await.is_none());
}

#[tokio::test]
async fn an_identity_linked_to_one_user_cannot_be_linked_to_another() {
    let u = setup(true).await;
    // The upstream identity registers its own account.
    sign_in(&u, json!({})).await;
    let first = user(&u.app, MOCK_EMAIL).await.expect("registered");
    u.app.clear_cookies();
    // Bob tries to link the same identity from his account page.
    register(&u.app, "", "bob@example.com", PASSWORD).await;
    let bob = user(&u.app, "bob@example.com").await.expect("bob");
    let resp = login(&u.app, "", "bob@example.com", PASSWORD).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.text());
    let page = u.app.get("/ui/account/security").await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let i = html.find("flow=").expect("settings flow") + 5;
    let path = format!("/ui/login/upstream/{SLUG}?flow={}", &html[i..i + 36]);
    let started = post_start(&u.app, &path, &csrf_from(&html)).await;
    reply_for(&u, &started, json!({}));
    let resp = callback(&u, &started).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&"upstream.already_linked".to_owned()),
        "{}",
        resp.text()
    );
    assert!(links(&u.app, &bob).await.is_empty());
    assert_eq!(links(&u.app, &first).await.len(), 1);
    assert_eq!(
        failure_reasons(&u.app).await.first().map(String::as_str),
        Some("already_linked")
    );
}

#[tokio::test]
async fn link_from_the_account_page_needs_the_owner_signed_in() {
    let u = setup(true).await;
    register(&u.app, "", "bob@example.com", PASSWORD).await;
    let bob = user(&u.app, "bob@example.com").await.expect("bob");
    login(&u.app, "", "bob@example.com", PASSWORD).await;
    let page = u.app.get("/ui/account/security").await;
    let html = page.html();
    let i = html.find("flow=").expect("settings flow") + 5;
    let path = format!("/ui/login/upstream/{SLUG}?flow={}", &html[i..i + 36]);
    let started = post_start(&u.app, &path, &csrf_from(&html)).await;
    reply_for(&u, &started, json!({}));
    // The callback arrives without Bob's session (signed out meanwhile).
    let session_name = session_cookie(&u.app).expect("session").0;
    let iss = u.mock.issuer();
    let cb = callback_path(
        SLUG,
        &[("code", "code-1"), ("state", &started.state), ("iss", &iss)],
    );
    let resp = get_with_cookies(&u.app, &cb, |k| k != session_name, None).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(links(&u.app, &bob).await.is_empty());
    assert_eq!(
        failure_reasons(&u.app).await.first().map(String::as_str),
        Some("reauth_required")
    );
}

// ---------------------------------------------------------------------------------------------
// The binding cookie is cleared only when the callback proved the binding
// ---------------------------------------------------------------------------------------------

/// Whether a response clears (expires) the cookie `name`.
fn clears_cookie(resp: &TestResponse, name: &str) -> bool {
    resp.headers
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with(&format!("{name}=")) && v.contains("Max-Age=0"))
}

#[tokio::test]
async fn forged_callback_does_not_cancel_pending_sign_in() {
    let u = setup(true).await;
    let iss = u.mock.issuer();
    // An earlier sign-in of this browser that it abandoned: its state is "another flow's state".
    let other = start(&u.app, SLUG).await;
    let started = start(&u.app, SLUG).await;
    reply_for(&u, &started, json!({}));
    let binding = binding_cookie_name(&u.app);
    let value = u.app.cookies()[&binding].clone();
    let (flow, _) = started.state.split_once('.').expect("state");
    let forged_states = [
        "no-flow-id".to_owned(),
        format!("{}.whatever", uuid::Uuid::now_v7()),
        format!("{flow}.tampered-random-part-0123456789abcdef"),
        other.state.clone(),
    ];
    for state in &forged_states {
        let path = callback_path(SLUG, &[("code", "code-x"), ("state", state), ("iss", &iss)]);
        let resp = u.app.get(&path).await;
        assert_eq!(resp.status, 400, "{state}: {}", resp.text());
        assert!(
            !clears_cookie(&resp, &binding),
            "{state}: {:?}",
            resp.headers
        );
        assert_eq!(u.app.cookies().get(&binding), Some(&value), "{state}");
    }
    let path = callback_path(
        SLUG,
        &[("code", "code-1"), ("state", &started.state), ("iss", &iss)],
    );
    // The right state without the binding cookie, and with another binding cookie.
    let without = get_with_cookies(&u.app, &path, |k| k != binding, None).await;
    assert_eq!(without.status, 400, "{}", without.text());
    assert!(!clears_cookie(&without, &binding));
    let wrong = get_with_cookies(
        &u.app,
        &path,
        |k| k != binding,
        Some((&binding, "attacker-binding-value")),
    )
    .await;
    assert_eq!(wrong.status, 400, "{}", wrong.text());
    assert!(!clears_cookie(&wrong, &binding));
    assert!(session(&u.app).await.is_none());
    assert!(u.mock.received_token_requests().await.is_empty());
    assert_eq!(
        failure_reasons(&u.app).await[..2],
        ["binding_invalid".to_owned(), "binding_invalid".to_owned()]
    );

    // The genuine callback still signs in, and clears the cookie.
    assert_eq!(u.app.cookies().get(&binding), Some(&value));
    let ok = u.app.get(&path).await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert!(clears_cookie(&ok, &binding));
    assert!(session(&u.app).await.is_some());
    assert!(!u.app.cookies().contains_key(&binding));
}

#[tokio::test]
async fn matching_callback_clears_the_binding_cookie_even_when_it_fails_later() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    let binding = binding_cookie_name(&u.app);
    let resp = u
        .app
        .get(&callback_path(
            SLUG,
            &[
                ("error", "access_denied"),
                ("state", &started.state),
                ("iss", &u.mock.issuer()),
            ],
        ))
        .await;
    assert_rejected(&u, &resp, "provider_error").await;
    assert!(clears_cookie(&resp, &binding), "{:?}", resp.headers);
    assert!(!u.app.cookies().contains_key(&binding));
}

// ---------------------------------------------------------------------------------------------
// require_verified_email applies to upstream accounts
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn untrusted_jit_account_must_verify_before_sign_in() {
    let u = setup(false).await;
    tenant_settings(&u.app, |s| s.require_verified_email = true).await;
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "login", "{html}");
    assert!(
        message_keys(&html).contains(&"registration.check_email".to_owned()),
        "{html}"
    );
    assert!(session(&u.app).await.is_none(), "no session");
    assert!(
        crate::ui_helpers::session_cookie(&u.app).is_none(),
        "no session cookie"
    );
    let alice = user(&u.app, MOCK_EMAIL).await.expect("account created");
    assert!(!alice.email_verified);
    assert_eq!(links(&u.app, &alice).await.len(), 1);
    assert_eq!(audit(&u.app, AuditAction::UserRegistered).await.len(), 1);
    assert_eq!(
        failure_reasons(&u.app).await.first().map(String::as_str),
        Some("email_not_verified")
    );
    assert!(audit(&u.app, AuditAction::LoginSucceeded).await.is_empty());
    let emails = take_emails(&u.app).await;
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert_eq!(emails[0].to, MOCK_EMAIL);
    let link = link_of(&u.app, &emails, "verification");

    // A second upstream sign-in before verifying is refused with the sign-in error, and sends
    // nothing new.
    u.app.clear_cookies();
    let again = sign_in(&u, json!({})).await;
    assert_eq!(again.status, 400, "{}", again.text());
    assert!(
        message_keys(&again.html()).contains(&"login.email_not_verified".to_owned()),
        "{}",
        again.text()
    );
    assert!(session(&u.app).await.is_none());
    assert!(take_emails(&u.app).await.is_empty());

    // After the verification link, the upstream sign-in signs in.
    let done = submit_form(&u.app, &link, &[]).await;
    assert_eq!(done.status, 200, "{}", done.text());
    assert!(
        user(&u.app, MOCK_EMAIL)
            .await
            .expect("alice")
            .email_verified
    );
    u.app.clear_cookies();
    let ok = sign_in(&u, json!({})).await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
}

#[tokio::test]
async fn linked_unverified_account_is_refused_under_require_verified_email() {
    // Created while verification was not required; the tenant turns it on afterwards.
    let u = setup(false).await;
    let first = sign_in(&u, json!({})).await;
    assert_eq!(first.status, 200, "{}", first.text());
    assert!(session(&u.app).await.is_some());
    take_emails(&u.app).await;
    tenant_settings(&u.app, |s| s.require_verified_email = true).await;
    u.app.clear_cookies();
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "login", "{html}");
    assert!(
        message_keys(&html).contains(&"login.email_not_verified".to_owned()),
        "{html}"
    );
    assert!(session(&u.app).await.is_none(), "no session");
    assert_eq!(
        failure_reasons(&u.app).await.first().map(String::as_str),
        Some("email_not_verified")
    );
    assert!(take_emails(&u.app).await.is_empty(), "no new email");
    assert_eq!(audit(&u.app, AuditAction::LoginSucceeded).await.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// UserInfo fallback (generic OIDC, email only in UserInfo)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn userinfo_fallback_rejects_another_subject() {
    let u = setup(true).await;
    u.mock.set_userinfo(json!({
        "sub": "someone-else",
        "email": "mallory@example.com",
        "email_verified": true,
    }));
    let started = start(&u.app, SLUG).await;
    reply_for(
        &u,
        &started,
        json!({ "email": null, "email_verified": null }),
    );
    let resp = callback(&u, &started).await;
    assert_rejected(&u, &resp, "userinfo_subject").await;
    assert!(user(&u.app, "mallory@example.com").await.is_none());
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
}
