//! Upstream sign-in and account linking through the built-in pages (AUTH-07, AUTH-11), against
//! a generic OIDC [`MockProvider`], on the selected backend (`ANVILID_TEST_DB`): sign-in buttons,
//! the start redirect (state, nonce, PKCE, binding cookie), just-in-time registration, sign-in
//! through an existing link, auto-linking, link confirmation by signing in, refused
//! registration, the MFA policy after an upstream sign-in, the `form_post` hop and linking from
//! the account page. Per-provider suites live in their own files (04-26).

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{
    ACR_MFA, ACR_PWD, AMR_FED, AMR_MFA, AMR_OTP, AuditAction, CredentialId, MfaPolicy, NewTotp,
    RegistrationMode, TOTP_SEED_PURPOSE, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::encoding::{b64url, sha256};
use anvil_jose::otp::TotpSecret;
use aws_lc_rs::hmac;
use serde_json::json;
use support::csrf_from;
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::{MOCK_CLIENT_ID, MOCK_EMAIL, MOCK_SUBJECT, form_field};

const PASSWORD: &str = "correct horse battery";

fn amr(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| (*x).to_owned()).collect()
}

#[tokio::test]
async fn sign_in_page_shows_a_button_per_enabled_connection() {
    let u = setup(true).await;
    let html = u.app.get("/ui/login").await.html();
    assert!(
        html.contains(&format!("data-connection=\"{SLUG}\"")),
        "{html}"
    );
    assert!(html.contains("Continue with Acme ID"), "{html}");
    let action = button_action(&u.app, &html, SLUG);
    assert!(
        action.starts_with(&format!("/ui/login/upstream/{SLUG}?flow=")),
        "{action}"
    );
    // A disabled connection has no button.
    u.app
        .storage()
        .connections()
        .update(
            tenant(&u.app).id,
            u.conn.id,
            &anvil_core::model::ConnectionUpdate {
                enabled: Some(false),
                ..Default::default()
            },
            u.app.clock().now(),
        )
        .await
        .expect("update")
        .expect("connection");
    let html = u.app.get("/ui/login").await.html();
    assert!(!html.contains("data-connection"), "{html}");
}

#[tokio::test]
async fn start_sends_state_nonce_pkce_and_sets_the_binding_cookie() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    assert!(
        started
            .location
            .as_str()
            .starts_with(&u.mock.authorization_endpoint()),
        "{}",
        started.location
    );
    assert_eq!(started.param("client_id").as_deref(), Some(MOCK_CLIENT_ID));
    assert_eq!(started.param("response_type").as_deref(), Some("code"));
    assert_eq!(
        started.param("redirect_uri"),
        Some(format!(
            "{}/ui/login/upstream/{SLUG}/callback",
            u.app.issuer(None)
        ))
    );
    assert_eq!(
        started.param("code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(started.nonce.as_deref().is_some_and(|n| n.len() >= 32));
    let (flow, random) = started.state.split_once('.').expect("{flow}.{random}");
    assert!(uuid::Uuid::parse_str(flow).is_ok());
    assert!(random.len() >= 32);
    let name = binding_cookie_name(&u.app);
    assert!(name.starts_with("__Host-anvil_upstream_"), "{name}");

    // The token request carries the code, the redirect URI and the PKCE verifier of the
    // challenge, with client_secret_basic.
    reply_for(&u, &started, json!({}));
    let resp = callback(&u, &started).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let reqs = u.mock.received_token_requests().await;
    assert_eq!(reqs.len(), 1);
    let verifier = form_field(&reqs[0], "code_verifier").expect("verifier");
    assert_eq!(
        Some(b64url(&sha256(verifier.as_bytes()))),
        started.param("code_challenge")
    );
    assert_eq!(form_field(&reqs[0], "code").as_deref(), Some("code-1"));
    assert!(reqs[0].headers.get("authorization").is_some());
    // The answer clears the binding cookie.
    assert!(
        !u.app
            .cookies()
            .keys()
            .any(|k| k.contains("anvil_upstream_")),
        "{:?}",
        u.app.cookies()
    );
}

#[tokio::test]
async fn first_sign_in_registers_the_user_with_fed_and_trusted_email() {
    let u = setup(true).await;
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&"login.signed_in".to_owned()),
        "{}",
        resp.text()
    );
    let s = session(&u.app).await.expect("session");
    assert_eq!(s.amr, amr(&[AMR_FED]));
    assert_eq!(s.acr, ACR_PWD);
    let user = user(&u.app, MOCK_EMAIL).await.expect("user registered");
    assert_eq!(s.user_id, user.id);
    assert!(user.email_verified);
    assert_eq!(user.claims.given_name.as_deref(), Some("Alice"));
    let l = links(&u.app, &user).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].subject, MOCK_SUBJECT);
    assert_eq!(l[0].connection_id, u.conn.id);
    assert_eq!(audit(&u.app, AuditAction::UserRegistered).await.len(), 1);
    let ok = audit(&u.app, AuditAction::LoginSucceeded).await;
    assert_eq!(ok[0].details.as_map()["method"], "upstream");
}

#[tokio::test]
async fn untrusted_connection_registers_with_an_unverified_email() {
    let u = setup(false).await;
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let user = user(&u.app, MOCK_EMAIL).await.expect("user registered");
    assert!(!user.email_verified);
}

#[tokio::test]
async fn trusted_verified_jit_signs_in_at_once() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.require_verified_email = true).await;
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&"login.signed_in".to_owned()),
        "{}",
        resp.text()
    );
    let alice = user(&u.app, MOCK_EMAIL).await.expect("user registered");
    assert!(alice.email_verified);
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    assert!(
        take_emails(&u.app).await.is_empty(),
        "no verification email"
    );
}

#[tokio::test]
async fn untrusted_jit_without_requirement_signs_in_and_gets_verification_email() {
    let u = setup(false).await;
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let alice = user(&u.app, MOCK_EMAIL).await.expect("user registered");
    assert!(!alice.email_verified);
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    let emails = take_emails(&u.app).await;
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert_eq!(emails[0].to, MOCK_EMAIL);
    let link = link_of(&u.app, &emails, "verification");
    assert!(link.starts_with("/ui/verification?token="), "{link}");
}

#[tokio::test]
async fn email_only_in_userinfo_is_used_when_the_id_token_has_none() {
    // OIDC Core 5.4: a provider may return `email` only from UserInfo. `fetch_userinfo` is off.
    let u = setup(true).await;
    u.mock.set_userinfo(json!({
        "sub": MOCK_SUBJECT,
        "email": "info@example.com",
        "email_verified": true,
        "name": "Not Taken",
    }));
    let started = start(&u.app, SLUG).await;
    reply_for(
        &u,
        &started,
        json!({ "email": null, "email_verified": null }),
    );
    let resp = callback(&u, &started).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let created = user(&u.app, "info@example.com")
        .await
        .expect("user from UserInfo email");
    assert!(created.email_verified);
    // Without fetch_userinfo only the email is taken from UserInfo; names stay the ID token's.
    assert_eq!(created.claims.name.as_deref(), Some("Alice Example"));
    assert_eq!(session(&u.app).await.expect("session").user_id, created.id);
    assert_eq!(u.mock.request_count("/userinfo").await, 1);

    // An ID token with an email does not call UserInfo.
    u.app.clear_cookies();
    sign_in(&u, json!({})).await;
    assert_eq!(u.mock.request_count("/userinfo").await, 1);
}

#[tokio::test]
async fn later_sign_ins_use_the_link_even_after_the_upstream_email_changed() {
    let u = setup(true).await;
    sign_in(&u, json!({})).await;
    let first = session(&u.app).await.expect("session").user_id;
    u.app.clear_cookies();
    let resp = sign_in(&u, json!({ "email": "renamed@example.com" })).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, first);
    assert!(user(&u.app, "renamed@example.com").await.is_none());
}

#[tokio::test]
async fn verified_trusted_email_auto_links_a_verified_local_account() {
    let u = setup(true).await;
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    let alice = user(&u.app, MOCK_EMAIL).await.expect("alice");
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    assert_eq!(links(&u.app, &alice).await.len(), 1);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].details.as_map()["mode"], "auto");
    assert_eq!(linked[0].details.as_map()["connection"], SLUG);
}

#[tokio::test]
async fn without_auto_link_the_user_confirms_by_signing_in() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.auto_link = false).await;
    register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    mark_verified(&u.app, MOCK_EMAIL).await;
    let alice = user(&u.app, MOCK_EMAIL).await.expect("alice");

    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    assert!(html.contains("Sign in to it to connect Acme ID"), "{html}");
    // The verified and trusted email may be revealed: it is prefilled.
    assert!(html.contains(&format!("value=\"{MOCK_EMAIL}\"")), "{html}");
    assert!(
        session(&u.app).await.is_none(),
        "no session before the link"
    );
    assert!(links(&u.app, &alice).await.is_empty());

    // A wrong password keeps the confirmation page and links nothing.
    let action = form_action(&u.app, &html);
    let csrf = csrf_from(&html);
    let wrong = u
        .app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("identifier", MOCK_EMAIL),
                ("password", "wrong password!"),
            ],
        )
        .await;
    // Post/Redirect/Get (07.1-13): 303 to the confirmation page of the same flow, which shows
    // the error, the same copy and the prefilled address.
    assert!(support::is_prg(&wrong), "{} {}", wrong.status, wrong.text());
    let wrong = follow_prg(&u.app, wrong).await;
    assert_eq!(wrong.status, 400);
    assert_eq!(form_id(&wrong.html()), "upstream-link");
    assert!(wrong.html().contains("Sign in to it to connect Acme ID"));
    assert!(wrong.html().contains(&format!("value=\"{MOCK_EMAIL}\"")));
    assert!(wrong.html().contains("id=\"link-cancel\""));
    assert!(links(&u.app, &alice).await.is_empty());

    let ok = u
        .app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("identifier", MOCK_EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
    let l = links(&u.app, &alice).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].subject, MOCK_SUBJECT);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked[0].details.as_map()["mode"], "confirmed");

    // From now on the upstream sign-in alone signs Alice in.
    u.app.clear_cookies();
    let again = sign_in(&u, json!({})).await;
    assert_eq!(again.status, 200, "{}", again.text());
    assert_eq!(session(&u.app).await.expect("session").user_id, alice.id);
}

#[tokio::test]
async fn closed_registration_without_a_match_is_a_generic_error() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.registration = RegistrationMode::Disabled).await;
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "login");
    assert!(
        message_keys(&html).contains(&"upstream.failed".to_owned()),
        "{html}"
    );
    assert!(user(&u.app, MOCK_EMAIL).await.is_none());
    assert!(session(&u.app).await.is_none());
    assert_eq!(failure_reasons(&u.app).await, vec!["no_account"]);

    // upstream_registration overrides the general registration mode.
    tenant_settings(&u.app, |s| s.upstream_registration = Some(true)).await;
    u.app.clear_cookies();
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(user(&u.app, MOCK_EMAIL).await.is_some());
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
async fn required_mfa_policy_asks_for_the_second_factor_after_an_upstream_sign_in() {
    let u = setup(true).await;
    sign_in(&u, json!({})).await;
    let alice = user(&u.app, MOCK_EMAIL).await.expect("registered");
    // Alice adds an authenticator app; the tenant then requires MFA.
    let t = tenant(&u.app).id;
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
            t,
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
    u.app.clear_cookies();

    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "second-factor", "{html}");
    assert!(
        session(&u.app).await.is_none(),
        "no session before the factor"
    );
    let action = form_action(&u.app, &html);
    let csrf = csrf_from(&html);
    let factor = hidden_inputs(&html)
        .into_iter()
        .find(|(n, _)| n == "factor_token")
        .expect("factor token")
        .1;
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
    let s = session(&u.app).await.expect("session");
    assert_eq!(s.user_id, alice.id);
    assert_eq!(s.amr, amr(&[AMR_FED, AMR_OTP, AMR_MFA]));
    assert_eq!(s.acr, ACR_MFA);
}

#[tokio::test]
async fn required_mfa_policy_without_a_factor_enrols_one_after_an_upstream_sign_in() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.mfa_policy = MfaPolicy::Required).await;
    let resp = sign_in(&u, json!({})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(form_id(&resp.html()), "mfa-enroll", "{}", resp.text());
    assert!(session(&u.app).await.is_none());
}

#[tokio::test]
async fn form_post_return_is_answered_with_a_303_to_the_get_callback() {
    let u = setup(true).await;
    let started = start(&u.app, SLUG).await;
    reply_for(&u, &started, json!({}));
    let iss = u.mock.issuer();
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("code", "code-1"),
            ("state", started.state.as_str()),
            ("iss", iss.as_str()),
            ("user", r#"{"name":{"firstName":"A","lastName":"B"}}"#),
        ])
        .finish();
    // Cross-site, without cookies (SameSite=Lax cookies are not sent on a cross-site POST).
    let post = u
        .app
        .send(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri(format!("/ui/login/upstream/{SLUG}/callback"))
                .header("content-type", "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "cross-site")
                .header("cookie", "")
                .body(axum::body::Body::from(body))
                .expect("request"),
        )
        .await;
    assert_eq!(post.status, 303, "{}", post.text());
    let to = support::location(&post);
    let encoded: String = url::form_urlencoded::byte_serialize(started.state.as_bytes()).collect();
    assert_eq!(
        to,
        format!(
            "{}/ui/login/upstream/{SLUG}/callback?state={encoded}",
            u.app.issuer(None)
        )
    );
    assert!(session(&u.app).await.is_none(), "the POST signs nobody in");
    // The browser follows with its binding cookie.
    let resp = u.app.follow(&post).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session(&u.app).await.is_some());
    assert_eq!(u.mock.received_token_requests().await.len(), 1);
}

/// Signs `email` in with the password and opens the account security page; returns the
/// settings flow's start path for `slug` and its CSRF token.
async fn settings_start(app: &support::TestApp, email: &str, slug: &str) -> (String, String) {
    let resp = login(app, "", email, PASSWORD).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.text());
    let page = app.get("/ui/account/security").await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let i = html.find("flow=").expect("settings flow id") + 5;
    let flow = &html[i..i + 36];
    (
        format!("/ui/login/upstream/{slug}?flow={flow}"),
        csrf_from(&html),
    )
}

#[tokio::test]
async fn account_page_link_connects_the_signed_in_user() {
    let u = setup(true).await;
    register(&u.app, "", "bob@example.com", PASSWORD).await;
    let bob = user(&u.app, "bob@example.com").await.expect("bob");
    let (path, csrf) = settings_start(&u.app, "bob@example.com", SLUG).await;
    let started = post_start(&u.app, &path, &csrf).await;
    // The upstream email is not Bob's: linking from the account page does not depend on it.
    reply_for(&u, &started, json!({}));
    let resp = callback(&u, &started).await;
    // Back to the linked accounts page, which lists the new identity.
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        support::location(&resp),
        format!("{}/ui/account/linked", u.app.issuer(None))
    );
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let page = u.app.follow(&resp).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let l = links(&u.app, &bob).await;
    assert_eq!(l.len(), 1);
    let html = page.html();
    assert!(
        html.contains(&format!("id=\"linked-{}\"", l[0].id)),
        "{html}"
    );
    assert!(!html.contains("id=\"linked-none\""), "{html}");
    assert_eq!(l[0].subject, MOCK_SUBJECT);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked[0].details.as_map()["mode"], "account");
    assert!(
        user(&u.app, MOCK_EMAIL).await.is_none(),
        "no account created"
    );

    // The upstream identity now signs Bob in.
    u.app.clear_cookies();
    sign_in(&u, json!({})).await;
    assert_eq!(session(&u.app).await.expect("session").user_id, bob.id);
}
