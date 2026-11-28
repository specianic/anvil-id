//! Password plus second factor through the built-in pages (AUTH-05, UI-02) on the selected
//! backend (`ANVILID_TEST_DB`): the second-factor page after a correct password (no session
//! before it succeeds), TOTP and recovery codes, replay rejection over HTTP, the preserved
//! authorization request and the binding token of the second-factor form.
//!
//! The route-class limit for auth POSTs is raised in these tests so that several sign-ins from
//! the one test peer are not cut off by it (it is tested in `security_ratelimit.rs`; the
//! brute-force limits stay on and are tested in `security_bruteforce.rs`).

mod support;
mod token_support;
mod ui_helpers;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AMR_MFA, AMR_OTP, AMR_PWD, BrowserSession, CredentialId, NewTotp, SecretHash,
    TOTP_SEED_PURPOSE, UserId, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::otp::{TotpSecret, check_code};
use aws_lc_rs::hmac;
use secrecy::ExposeSecret as _;
use support::{TestApp, TestResponse, csrf_from, location};
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

/// A live authorization request of the default tenant for a new test client (stored through the
/// port): the sign-in pages only continue a request that exists (07.1-01; a stale id answers the
/// `flow_expired` page).
async fn live_request(app: &TestApp) -> String {
    use anvil_core::ports::Clock as _;
    let tenant = app.default.as_ref().expect("installed").tenant.id;
    let rp = token_support::register(
        app,
        tenant,
        token_support::web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let id = anvil_core::model::AuthRequestId(uuid::Uuid::now_v7());
    let now = app.clock().now();
    app.storage()
        .grants()
        .create_authorization_request(
            tenant,
            &anvil_core::model::NewAuthorizationRequest {
                id,
                client_id: rp.id().to_owned(),
                params: token_support::params("openid", Some(token_support::CHALLENGE)),
                created_at: now,
                expires_at: now + time::Duration::minutes(15),
            },
        )
        .await
        .expect("request stored");
    id.0.to_string()
}

async fn app() -> TestApp {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
}

async fn user_id(app: &TestApp) -> UserId {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, EMAIL)
        .await
        .expect("lookup")
        .expect("user")
        .id
}

/// Enrols an authenticator app (random seed, sealed like production) and a recovery-code set.
/// Returns the plaintext recovery codes.
async fn enrol_totp(app: &TestApp) -> Vec<String> {
    let tenant = default_tenant(app).id;
    let user = user_id(app).await;
    let id = CredentialId::new_v7();
    let seed = TotpSecret::generate();
    let secret_enc = app
        .kek()
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), seed.as_bytes())
        .expect("seal");
    let (codes, hashes) = new_recovery_codes(app.kek()).expect("codes");
    let now = app.clock().now();
    app.storage()
        .users()
        .create_totp(
            tenant,
            user,
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
    codes.iter().map(|c| c.expose_secret().to_owned()).collect()
}

/// RFC 6238 code (SHA-1, 6 digits, 30 s) of `seed` at `unix` (test code; the server checks it
/// with its own implementation).
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

/// The current TOTP code, computed from the stored seed opened with the test KEK.
async fn current_code(app: &TestApp) -> String {
    let tenant = default_tenant(app).id;
    let totp = app
        .storage()
        .users()
        .totp(tenant, user_id(app).await)
        .await
        .expect("totp lookup")
        .expect("enrolled");
    let seed = app
        .kek()
        .open(
            TOTP_SEED_PURPOSE,
            &credential_aad(totp.id),
            &totp.secret_enc,
        )
        .expect("seed opens");
    let now = app.clock().now().unix_timestamp();
    let code = totp_code(&seed, now);
    let secret = TotpSecret::from_bytes(&seed).expect("seed");
    assert!(
        check_code(&secret, &code, u64::try_from(now).expect("time")).is_some(),
        "the test generator agrees with the server's check"
    );
    code
}

/// The hidden `factor_token` of a second-factor page.
fn factor_token(html: &str) -> String {
    hidden_inputs(html)
        .into_iter()
        .find(|(n, _)| n == "factor_token")
        .map(|(_, v)| v)
        .expect("second-factor page carries a factor_token")
}

/// Submits the second-factor form of `page` with `pairs`.
async fn second_factor(app: &TestApp, page: &TestResponse, pairs: &[(&str, &str)]) -> TestResponse {
    let html = page.html();
    let action = form_action(app, &html);
    let csrf = csrf_from(&html);
    let token = factor_token(&html);
    let mut all = vec![
        ("csrf_token", csrf.as_str()),
        ("factor_token", token.as_str()),
    ];
    all.extend_from_slice(pairs);
    app.post_form(&action, &all).await
}

/// Signs in with the password and expects the second-factor page (no session yet).
async fn password_step(app: &TestApp, path: &str) -> TestResponse {
    let resp = submit_form(app, path, &[("identifier", EMAIL), ("password", PASSWORD)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(html.contains("id=\"second-factor\""), "{html}");
    assert!(
        session_cookie(app).is_none(),
        "no session before the second factor"
    );
    resp
}

async fn session(app: &TestApp) -> BrowserSession {
    let (_, value) = session_cookie(app).expect("session cookie");
    app.storage()
        .sessions()
        .get_active(
            default_tenant(app).id,
            &SecretHash(anvil_jose::encoding::secret_hash(&value)),
            app.clock().now(),
        )
        .await
        .expect("session lookup")
        .expect("active session")
}

fn amr(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| (*x).to_owned()).collect()
}

#[tokio::test]
async fn second_factor_page_has_the_stable_selectors_and_no_session() {
    let app = app().await;
    enrol_totp(&app).await;
    let resp = password_step(&app, "/ui/login").await;
    let html = resp.html();
    for needle in [
        "id=\"second-factor\"",
        "id=\"code\"",
        "autocomplete=\"one-time-code\"",
        "inputmode=\"numeric\"",
        "id=\"recovery-code-toggle\"",
        "id=\"recovery_code\"",
        "id=\"second-factor-submit\"",
        "id=\"page-heading\"",
        "Two-step verification",
    ] {
        assert!(html.contains(needle), "{needle} in {html}");
    }
    assert!(
        form_action(&app, &html).starts_with("/ui/login/second-factor?flow="),
        "the form posts to the second-factor route"
    );
    assert!(flow_cookie(&app).is_some(), "still in the login flow");
    // A direct visit has no form to show: back to the sign-in page.
    let resp = app.get("/ui/login/second-factor").await;
    assert_eq!(resp.status, 303);
    assert_eq!(location(&resp), format!("{}/ui/login", app.issuer(None)));
}

#[tokio::test]
async fn totp_signs_in_with_mfa_amr_and_the_same_code_is_rejected_later() {
    let app = app().await;
    enrol_totp(&app).await;
    let page = password_step(&app, "/ui/login").await;
    let code = current_code(&app).await;

    // A wrong code first: the page again with the error, still no session.
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let resp = second_factor(&app, &page, &[("code", wrong)]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.second_factor_invalid".to_owned()]
    );
    assert!(resp.html().contains("aria-invalid=\"true\""));
    assert!(session_cookie(&app).is_none());

    let resp = second_factor(&app, &resp, &[("code", &code)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.signed_in".to_owned()]
    );
    let s = session(&app).await;
    assert_eq!(s.amr, amr(&[AMR_PWD, AMR_OTP, AMR_MFA]));
    assert!(flow_cookie(&app).is_none(), "flow cookie cleared");

    // A new sign-in with the same code (same time step): rejected.
    app.clear_cookies();
    let page = password_step(&app, "/ui/login").await;
    let resp = second_factor(&app, &page, &[("code", &code)]).await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.second_factor_invalid".to_owned()]
    );
    assert!(
        session_cookie(&app).is_none(),
        "a replayed code signs nobody in"
    );
}

#[tokio::test]
async fn recovery_code_signs_in_once_and_queues_the_notice() {
    let app = app().await;
    let codes = enrol_totp(&app).await;
    take_emails(&app).await;

    let page = password_step(&app, "/ui/login").await;
    let resp = second_factor(&app, &page, &[("code", ""), ("recovery_code", &codes[0])]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = session(&app).await;
    assert_eq!(s.amr, amr(&[AMR_PWD, AMR_OTP, AMR_MFA]));
    let emails = take_emails(&app).await;
    assert_eq!(
        emails
            .iter()
            .filter(|e| e.template == "recovery_code_used" && e.to == EMAIL)
            .count(),
        1,
        "{emails:?}"
    );

    // The same recovery code again: rejected.
    app.clear_cookies();
    let page = password_step(&app, "/ui/login").await;
    let resp = second_factor(&app, &page, &[("code", ""), ("recovery_code", &codes[0])]).await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.second_factor_invalid".to_owned()]
    );
    assert!(session_cookie(&app).is_none());

    // Another unused code works.
    let resp = second_factor(&app, &resp, &[("code", ""), ("recovery_code", &codes[1])]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
}

#[tokio::test]
async fn the_authorization_request_is_preserved_through_the_second_factor() {
    let app = app().await;
    enrol_totp(&app).await;
    let request = live_request(&app).await;
    let page = password_step(&app, &format!("/ui/login?request={request}")).await;
    let code = current_code(&app).await;
    let resp = second_factor(&app, &page, &[("code", &code)]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        location(&resp),
        format!("{}/authorize/continue?request={request}", app.issuer(None))
    );
    assert!(session_cookie(&app).is_some());
}

#[tokio::test]
async fn a_second_factor_post_without_a_valid_binding_token_restarts_the_sign_in() {
    let app = app().await;
    enrol_totp(&app).await;
    let page = password_step(&app, "/ui/login").await;
    let html = page.html();
    let action = form_action(&app, &html);
    let csrf = csrf_from(&html);
    let code = current_code(&app).await;
    let token = factor_token(&html);
    let mut tampered = token.clone();
    tampered.replace_range(0..1, if token.starts_with('A') { "B" } else { "A" });

    for token in [None, Some("garbage"), Some(tampered.as_str())] {
        let mut pairs = vec![("csrf_token", csrf.as_str()), ("code", code.as_str())];
        if let Some(t) = token {
            pairs.push(("factor_token", t));
        }
        let resp = app.post_form(&action, &pairs).await;
        assert_eq!(resp.status, 400, "{token:?}: {}", resp.text());
        let html = resp.html();
        assert!(html.contains("id=\"login\""), "a fresh sign-in form");
        assert!(message_keys(&html).contains(&"flow.expired".to_owned()));
        assert!(session_cookie(&app).is_none(), "{token:?}");
    }

    // A token of another flow does not open either.
    let other = password_step(&app, "/ui/login").await;
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", csrf.as_str()),
                ("code", code.as_str()),
                ("factor_token", factor_token(&other.html()).as_str()),
            ],
        )
        .await;
    assert_eq!(resp.status, 400);
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn a_code_posted_to_the_password_route_is_not_a_second_factor() {
    let app = app().await;
    enrol_totp(&app).await;
    let page = password_step(&app, "/ui/login").await;
    let html = page.html();
    let flow = form_action(&app, &html)
        .split_once("?flow=")
        .map(|(_, f)| f.to_owned())
        .expect("flow id");
    let code = current_code(&app).await;
    let resp = app
        .post_form(
            &format!("/ui/login?flow={flow}"),
            &[("csrf_token", csrf_from(&html).as_str()), ("code", &code)],
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["flow.invalid_input".to_owned()]
    );
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn second_factor_form_without_csrf_or_flow_is_rejected() {
    let app = app().await;
    enrol_totp(&app).await;
    let page = password_step(&app, "/ui/login").await;
    let html = page.html();
    let action = form_action(&app, &html);
    let token = factor_token(&html);
    let code = current_code(&app).await;

    let resp = app
        .post_form(
            &action,
            &[("factor_token", token.as_str()), ("code", &code)],
        )
        .await;
    assert_eq!(resp.status, 403);
    assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));

    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", "wrong"),
                ("factor_token", token.as_str()),
                ("code", &code),
            ],
        )
        .await;
    assert_eq!(resp.status, 403);
    assert!(session_cookie(&app).is_none());
}
