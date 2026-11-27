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
//! - the UserInfo fallback refuses a UserInfo `sub` that differs from the ID token's;
//! - an organization's IdP is trusted only for its own org's verified domains: org A's IdP
//!   asserting an address on a domain verified by org B never auto-links to the org B user and
//!   never makes that account a member of org A;
//! - link confirmation without a password: only an identity already linked to the revealed
//!   candidate account (or an emailed code to its verified address) confirms; an identity of
//!   another user, an unlinked identity, a crafted start for an unrevealed candidate or a code to
//!   another address links nothing, the providers are not shown when the candidate may not be
//!   revealed, and a required second factor still comes first.

mod email_code_support;
mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{
    AuditAction, Connection, ConnectionConfig, CredentialId, EndpointOverrides, MfaPolicy, NewTotp,
    NewUser, SocialConfig, SocialProvider, StandardClaims, TOTP_SEED_PURPOSE, User, UserId,
    UserStatus, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::otp::TotpSecret;
use aws_lc_rs::hmac;
use serde_json::json;
use support::{TestResponse, csrf_from};
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::{MOCK_CLIENT_ID, MOCK_EMAIL, MOCK_SUBJECT, MockKind, MockProvider};

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

#[tokio::test]
async fn foreign_domain_email_never_auto_links() {
    const VICTIM: &str = "victim@orgb.example";
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.auto_link = true).await;
    let org_a = create_org(&u.app, "org-a", &[]).await;
    let org_b = create_org(&u.app, "org-b", &[]).await;
    verify_domain(&u.app, &org_a, "orga.example").await;
    verify_domain(&u.app, &org_b, "orgb.example").await;
    // Org A's IdP, trusted for email_verified (the strongest setting an org admin can pick).
    add_org_connection(&u.app, &u.mock, &org_a, "org-a-sso", true).await;
    // The victim: a verified local account on org B's domain, member of org B.
    register(&u.app, "", VICTIM, PASSWORD).await;
    mark_verified(&u.app, VICTIM).await;
    let victim = user(&u.app, VICTIM).await.expect("victim");
    u.app
        .storage()
        .organizations()
        .add_member(
            tenant(&u.app).id,
            &anvil_core::model::NewMembership {
                org_id: org_b.id,
                user_id: victim.id,
                role_ids: vec![],
                created_at: u.app.clock().now(),
            },
        )
        .await
        .expect("add member");

    let resp = sign_in_at(
        &u,
        "org-a-sso",
        json!({ "email": VICTIM, "email_verified": true }),
    )
    .await;
    // The Phase 4 confirmation, without revealing the account.
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    assert!(!html.contains(VICTIM), "{html}");
    assert!(links(&u.app, &victim).await.is_empty(), "never auto-linked");
    assert!(session(&u.app).await.is_none(), "no session");
    assert!(audit(&u.app, AuditAction::IdentityLinked).await.is_empty());
    assert!(
        !is_member(&u.app, &org_a, &victim).await,
        "no org A membership for the victim"
    );
    assert!(audit(&u.app, AuditAction::OrgMemberAdded).await.is_empty());

    // The same address from org B's own IdP is trusted (control).
    add_org_connection(&u.app, &u.mock, &org_b, "org-b-sso", true).await;
    let resp = sign_in_at(
        &u,
        "org-b-sso",
        json!({ "sub": "b-subject", "email": VICTIM, "email_verified": true }),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(links(&u.app, &victim).await.len(), 1, "org B's IdP links");
    assert!(!is_member(&u.app, &org_a, &victim).await);
}

#[tokio::test]
async fn foreign_domain_jit_account_is_unverified_and_cannot_claim_the_address() {
    // Org A's IdP asserting a not-yet-registered address on org B's domain: the JIT account gets
    // an unverified email (verification email sent), so it can never be auto-linked to later.
    let u = setup(true).await;
    let org_a = create_org(&u.app, "org-a", &[]).await;
    let org_b = create_org(&u.app, "org-b", &[]).await;
    verify_domain(&u.app, &org_a, "orga.example").await;
    verify_domain(&u.app, &org_b, "orgb.example").await;
    add_org_connection(&u.app, &u.mock, &org_a, "org-a-sso", true).await;
    let resp = sign_in_at(
        &u,
        "org-a-sso",
        json!({ "email": "ceo@orgb.example", "email_verified": true }),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let jit = user(&u.app, "ceo@orgb.example").await.expect("jit user");
    assert!(!jit.email_verified, "foreign domain is never verified");
    assert!(!is_member(&u.app, &org_b, &jit).await);
    let emails = take_emails(&u.app).await;
    assert_eq!(emails.len(), 1, "verification email: {emails:?}");
}

#[tokio::test]
async fn tenant_connection_trust_is_unchanged_by_org_domains() {
    // A tenant (non-org) connection keeps the Phase 4 trust: an org's verified domain neither
    // grants nor removes trust there.
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.auto_link = true).await;
    let org = create_org(&u.app, "org-b", &[]).await;
    verify_domain(&u.app, &org, "orgb.example").await;
    register(&u.app, "", "pat@orgb.example", PASSWORD).await;
    mark_verified(&u.app, "pat@orgb.example").await;
    let pat = user(&u.app, "pat@orgb.example").await.expect("pat");
    let resp = sign_in(
        &u,
        json!({ "email": "pat@orgb.example", "email_verified": true }),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(links(&u.app, &pat).await.len(), 1, "Phase 4 auto-link");
    assert!(
        !is_member(&u.app, &org, &pat).await,
        "tenant connections add no membership"
    );
}

// ---------------------------------------------------------------------------------------------
// Link confirmation without a password: an already-linked provider or an emailed code proves the
// candidate account; nothing else links (AUTH-11, 1.0.0-rc.1 fix)
// ---------------------------------------------------------------------------------------------

/// Slug and name of a second connection (to the same mock) the candidate may already be linked to.
const SECOND: &str = "second-id";
const SECOND_NAME: &str = "Second ID";

async fn second_connection(u: &Upstream, slug: &str, name: &str) -> Connection {
    add_connection(&u.app, slug, name, mock_oidc_config(&u.mock), true).await
}

/// Alice's account was created through social login: no password, no passkey, a verified email.
async fn social_only_alice(u: &Upstream) -> User {
    let now = u.app.clock().now();
    u.app
        .storage()
        .users()
        .create(
            tenant(&u.app).id,
            &NewUser {
                id: UserId::new_v7(),
                email: MOCK_EMAIL.into(),
                email_verified: true,
                username: None,
                claims: StandardClaims::default(),
                status: UserStatus::Active,
                created_at: now,
            },
            None,
            None,
            None,
        )
        .await
        .expect("create alice")
}

/// The upstream sign-in through [`SLUG`] lands on the link confirmation page (auto-link off).
async fn link_page(u: &Upstream) -> String {
    tenant_settings(&u.app, |s| s.auto_link = false).await;
    let resp = sign_in(u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    html
}

/// Presses the confirmation button of `slug` on the link page and returns from the provider as
/// `subject` (with an unrelated email, so no email match can play a part).
async fn confirm_with(u: &Upstream, page: &str, slug: &str, subject: &str) -> TestResponse {
    let action = button_action(&u.app, page, slug);
    let started = post_start(&u.app, &action, &csrf_from(page)).await;
    reply_for(
        u,
        &started,
        json!({ "sub": subject, "email": "mallory@example.net" }),
    );
    callback_at(u, slug, &started).await
}

/// Nothing new is linked to Alice and no `identity_linked` was recorded.
async fn assert_nothing_linked(u: &Upstream, alice: &User, before: usize) {
    assert_eq!(links(&u.app, alice).await.len(), before);
    assert!(audit(&u.app, AuditAction::IdentityLinked).await.is_empty());
    assert!(user(&u.app, "mallory@example.net").await.is_none());
}

#[tokio::test]
async fn linked_provider_confirms_the_link_of_a_social_only_account() {
    let u = setup(true).await;
    let second = second_connection(&u, SECOND, SECOND_NAME).await;
    // A third connection Alice is not linked to is never offered.
    second_connection(&u, "third-id", "Third ID").await;
    let alice = social_only_alice(&u).await;
    link_identity(&u.app, &alice, &second, "alice-second").await;

    let page = link_page(&u).await;
    assert!(page.contains("id=\"upstream-second-id-form\""), "{page}");
    assert!(!page.contains("upstream-third-id"), "{page}");
    assert!(!page.contains("upstream-acme-id-form"), "{page}");
    assert!(session(&u.app).await.is_none());

    let resp = confirm_with(&u, &page, SECOND, "alice-second").await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    let l = links(&u.app, &alice).await;
    assert_eq!(l.len(), 2, "{l:?}");
    assert!(
        l.iter()
            .any(|l| l.connection_id == u.conn.id && l.subject == MOCK_SUBJECT)
    );
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].details.as_map()["mode"], "confirmed");

    // From now on the first provider alone signs Alice in.
    u.app.clear_cookies();
    let again = sign_in(&u, json!({})).await;
    assert_eq!(again.status, 200, "{}", again.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
}

#[tokio::test]
async fn confirming_with_an_identity_of_another_user_links_nothing() {
    let u = setup(true).await;
    let second = second_connection(&u, SECOND, SECOND_NAME).await;
    let alice = social_only_alice(&u).await;
    link_identity(&u.app, &alice, &second, "alice-second").await;
    register(&u.app, "", "bob@example.com", PASSWORD).await;
    let bob = user(&u.app, "bob@example.com").await.expect("bob");
    link_identity(&u.app, &bob, &second, "bob-second").await;
    u.app.clear_cookies();

    let page = link_page(&u).await;
    let resp = confirm_with(&u, &page, SECOND, "bob-second").await;
    assert_rejected(&u, &resp, "link_confirm_mismatch").await;
    assert_nothing_linked(&u, &alice, 1).await;
    assert_eq!(links(&u.app, &bob).await.len(), 1);
}

#[tokio::test]
async fn confirming_with_an_unlinked_identity_links_nothing() {
    let u = setup(true).await;
    let second = second_connection(&u, SECOND, SECOND_NAME).await;
    let alice = social_only_alice(&u).await;
    link_identity(&u.app, &alice, &second, "alice-second").await;

    let page = link_page(&u).await;
    let resp = confirm_with(&u, &page, SECOND, "nobody-second").await;
    assert_rejected(&u, &resp, "link_confirm_mismatch").await;
    assert_nothing_linked(&u, &alice, 1).await;
}

#[tokio::test]
async fn confirmation_buttons_are_hidden_when_the_account_may_not_be_revealed() {
    // Untrusted connection: the candidate is not revealed, so neither are its providers.
    let u = setup(false).await;
    let second = second_connection(&u, SECOND, SECOND_NAME).await;
    let alice = social_only_alice(&u).await;
    link_identity(&u.app, &alice, &second, "alice-second").await;

    let page = link_page(&u).await;
    assert!(!page.contains("upstream-second-id"), "{page}");
    assert!(!page.contains(SECOND_NAME), "{page}");
    assert!(!page.contains(MOCK_EMAIL), "{page}");
    // Not the "no method" verdict either (that would reveal the account), but the way out.
    let keys = message_keys(&page);
    assert!(
        !keys.contains(&"upstream.link_no_method".to_owned()),
        "{page}"
    );
    assert!(page.contains("id=\"link-account-linked\""), "{page}");

    // A crafted start of the linked provider from this flow cannot link either.
    let action = url::Url::parse(&format!("https://op.test{}", form_action(&u.app, &page)))
        .expect("form action");
    let flow = action
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .map(|(_, v)| v.into_owned())
        .expect("flow");
    let started = post_start(
        &u.app,
        &format!("/ui/login/upstream/{SECOND}?flow={flow}"),
        &csrf_from(&page),
    )
    .await;
    reply_for(&u, &started, json!({ "sub": "alice-second" }));
    let resp = callback_at(&u, SECOND, &started).await;
    assert_rejected(&u, &resp, "link_confirm_mismatch").await;
    assert_eq!(links(&u.app, &alice).await.len(), 1);
    assert!(audit(&u.app, AuditAction::IdentityLinked).await.is_empty());
}

/// RFC 6238 code (SHA-1, 6 digits, 30 s) of `seed` at `unix` (test implementation).
fn totp_code(seed: &[u8], unix: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let counter = u64::try_from(unix / 30).expect("positive time");
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[off]) & 0x7f) << 24
        | u32::from(h[off + 1]) << 16
        | u32::from(h[off + 2]) << 8
        | u32::from(h[off + 3]);
    format!("{:06}", bin % 1_000_000)
}

#[tokio::test]
async fn confirmation_through_a_linked_provider_still_needs_the_second_factor() {
    let u = setup(true).await;
    let second = second_connection(&u, SECOND, SECOND_NAME).await;
    let alice = social_only_alice(&u).await;
    link_identity(&u.app, &alice, &second, "alice-second").await;
    let id = CredentialId::new_v7();
    let seed = TotpSecret::generate();
    let secret_enc = u
        .app
        .kek()
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), seed.as_bytes())
        .expect("seal");
    let (_, hashes) = new_recovery_codes(u.app.kek()).expect("codes");
    let now = u.app.clock().now();
    u.app
        .storage()
        .users()
        .create_totp(
            tenant(&u.app).id,
            alice.id,
            &NewTotp {
                id,
                secret_enc,
                created_at: now,
            },
            &hashes,
            now,
        )
        .await
        .expect("totp");
    tenant_settings(&u.app, |s| s.mfa_policy = MfaPolicy::Required).await;

    let page = link_page(&u).await;
    let resp = confirm_with(&u, &page, SECOND, "alice-second").await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "second-factor", "{html}");
    assert!(
        session(&u.app).await.is_none(),
        "no session before the factor"
    );
    assert_eq!(
        links(&u.app, &alice).await.len(),
        1,
        "no link before the factor"
    );

    let action = form_action(&u.app, &html);
    let csrf = csrf_from(&html);
    let factor = hidden_inputs(&html)
        .into_iter()
        .find(|(n, _)| n == "factor_token")
        .expect("factor token")
        .1;
    // A wrong code links nothing.
    let wrong = u
        .app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("factor_token", &factor),
                ("code", "000000"),
            ],
        )
        .await;
    assert_eq!(wrong.status, 400, "{}", wrong.text());
    assert_eq!(links(&u.app, &alice).await.len(), 1);
    assert!(session(&u.app).await.is_none());

    let code = totp_code(seed.as_bytes(), now.unix_timestamp());
    let ok = u
        .app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("factor_token", &factor),
                ("code", &code),
            ],
        )
        .await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    assert_eq!(links(&u.app, &alice).await.len(), 2);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].details.as_map()["mode"], "confirmed");
}

#[tokio::test]
async fn link_page_without_any_confirmation_method_says_how_to_continue() {
    // Alice has no password, no passkey, no other linked provider and email sign-in is off.
    let u = setup(true).await;
    let alice = social_only_alice(&u).await;
    let page = link_page(&u).await;
    let keys = message_keys(&page);
    assert!(
        keys.contains(&"upstream.link_no_method".to_owned()),
        "{page}"
    );
    assert!(!page.contains("name=\"password\""), "{page}");
    assert!(page.contains("id=\"link-account-linked\""), "{page}");
    assert!(page.contains("/ui/account/linked"), "{page}");
    // The cancel link leads back to a working sign-in page; nothing was linked.
    let marker = "id=\"link-cancel\" href=\"";
    let i = page.find(marker).expect("cancel link") + marker.len();
    let href = &page[i..i + page[i..].find('"').expect("quoted")];
    let back = u
        .app
        .get(&to_path(&u.app, &href.replace("&amp;", "&")))
        .await;
    assert_eq!(back.status, 200, "{}", back.text());
    assert_eq!(form_id(&back.html()), "login");
    assert!(links(&u.app, &alice).await.is_empty());
    assert!(session(&u.app).await.is_none());
}

#[tokio::test]
async fn emailed_code_confirms_the_link_of_a_social_only_account() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| {
        s.email_otp = true;
        s.magic_link = true;
    })
    .await;
    let alice = social_only_alice(&u).await;
    let page = link_page(&u).await;
    assert!(page.contains("id=\"email-code-request\""), "{page}");
    assert!(!message_keys(&page).contains(&"upstream.link_no_method".to_owned()));
    let action = email_code_support::action_of(&u.app, &page, "email-code-request");
    let sent = u
        .app
        .post_form(
            &action,
            &[("csrf_token", &csrf_from(&page)), ("email", MOCK_EMAIL)],
        )
        .await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    let mail = email_code_support::one_code(&u.app).await;
    assert_eq!(mail.to, MOCK_EMAIL);
    // Only the code: the magic link cannot carry the pending link to another browser.
    assert!(mail.link.is_empty(), "{mail:?}");
    let ok = email_code_support::submit_code(&u.app, &sent, &mail.code).await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    let l = links(&u.app, &alice).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].subject, MOCK_SUBJECT);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked[0].details.as_map()["mode"], "confirmed");
}

#[tokio::test]
async fn emailed_code_for_another_address_cannot_confirm_the_link() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.email_otp = true).await;
    let alice = social_only_alice(&u).await;
    register(&u.app, "", "bob@example.com", PASSWORD).await;
    mark_verified(&u.app, "bob@example.com").await;
    take_emails(&u.app).await;
    u.app.clear_cookies();
    let page = link_page(&u).await;
    let action = email_code_support::action_of(&u.app, &page, "email-code-request");
    let resp = u
        .app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf_from(&page)),
                ("email", "bob@example.com"),
            ],
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(email_code_support::login_codes(&u.app).await.is_empty());
    assert!(links(&u.app, &alice).await.is_empty());
    assert!(session(&u.app).await.is_none());

    // An unverified candidate address is not offered a code at all.
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.email_otp = true).await;
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    let page = link_page(&u).await;
    assert!(!page.contains("id=\"email-code-request\""), "{page}");
}

#[tokio::test]
async fn callback_of_a_finished_sign_in_says_it_was_already_completed() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    reply_for(&u, &started, json!({}));
    let first = callback(&u, &started).await;
    assert_eq!(first.status, 200, "{}", first.text());
    // The browser goes back and the provider's return is loaded again: the flow is gone.
    u.app.clear_cookies();
    let again = callback(&u, &started).await;
    assert_eq!(again.status, 400, "{}", again.text());
    let html = again.html();
    assert_eq!(form_id(&html), "login", "{html}");
    let keys = message_keys(&html);
    assert!(keys.contains(&"upstream.flow_expired".to_owned()), "{html}");
    assert!(!keys.contains(&"upstream.failed".to_owned()), "{html}");
    assert_eq!(
        failure_reasons(&u.app).await.first().map(String::as_str),
        Some("flow_expired")
    );
}
