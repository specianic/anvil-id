//! MFA policy enforcement in the login flow (AUTH-08) through the built-in pages, on the selected
//! backend (`ANVILID_TEST_DB`): the effective policy (strictest of tenant and client) against users
//! with and without a second factor, in-flow enrolment of an authenticator app when the policy is
//! `required` (QR code and key, wrong code, recovery codes shown once, `[pwd, otp, mfa]`), its
//! binding (CSRF) and single use of the confirming code.
//!
//! The route-class limit for auth POSTs is raised so several sign-ins from the one test peer are
//! not cut off by it (tested in `security_ratelimit.rs`); the brute-force limits stay on.

mod authz;
mod support;
mod ui_helpers;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    ACR_MFA, ACR_PWD, AMR_MFA, AMR_OTP, AMR_PWD, BrowserSession, ClientUpdate, CredentialId,
    MfaPolicy, NewTotp, SecretHash, TOTP_SEED_PURPOSE, TenantSettings, UserId, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::otp::TotpSecret;
use aws_lc_rs::hmac;
use support::{TestApp, TestResponse, csrf_from, location};
use ui_helpers::*;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const PASSWORD: &str = "correct horse battery";

async fn app() -> TestApp {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    register(&app, "", ALICE, PASSWORD).await;
    register(&app, "", BOB, PASSWORD).await;
    app
}

async fn set_policy(app: &TestApp, policy: MfaPolicy) {
    let t = default_tenant(app);
    set_settings(
        app,
        t.id,
        TenantSettings {
            mfa_policy: policy,
            ..t.settings.clone()
        },
    )
    .await;
}

async fn user_id(app: &TestApp, email: &str) -> UserId {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, email)
        .await
        .expect("lookup")
        .expect("user")
        .id
}

/// Enrols an authenticator app for `email` directly through storage (sealed like production).
async fn enrol_totp(app: &TestApp, email: &str) {
    let tenant = default_tenant(app).id;
    let user = user_id(app, email).await;
    let id = CredentialId::new_v7();
    let seed = TotpSecret::generate();
    let secret_enc = app
        .kek()
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), seed.as_bytes())
        .expect("seal");
    let (_, hashes) = new_recovery_codes(app.kek()).expect("codes");
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

/// RFC 4648 base32 (no padding, spaces ignored) decoder for the key shown on the page.
fn base32_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = ALPHABET
            .iter()
            .position(|a| *a == c.to_ascii_uppercase())
            .expect("base32 character");
        bits = (bits << 5) | u32::try_from(v).expect("small");
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push(u8::try_from((bits >> n) & 0xff).expect("byte"));
        }
    }
    out
}

/// The current code for the key shown on an enrolment page.
fn code_for_page(app: &TestApp, html: &str) -> String {
    let seed = base32_decode(&element_text(html, "totp-secret"));
    totp_code(&seed, app.clock().now().unix_timestamp())
}

fn hidden(html: &str, name: &str) -> String {
    hidden_inputs(html)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("hidden input {name}"))
}

/// Posts the code form (second factor or enrolment) of `page`.
async fn post_code(app: &TestApp, page: &TestResponse, code: &str) -> TestResponse {
    let html = page.html();
    let action = form_action(app, &html);
    let csrf = csrf_from(&html);
    let token = hidden(&html, "factor_token");
    app.post_form(
        &action,
        &[
            ("csrf_token", csrf.as_str()),
            ("factor_token", token.as_str()),
            ("code", code),
        ],
    )
    .await
}

async fn password(app: &TestApp, path: &str, email: &str) -> TestResponse {
    submit_form(app, path, &[("identifier", email), ("password", PASSWORD)]).await
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

fn is_second_factor(resp: &TestResponse) -> bool {
    resp.status == 200 && resp.html().contains("id=\"second-factor\"")
}

fn is_enrolment(resp: &TestResponse) -> bool {
    resp.status == 200 && resp.html().contains("id=\"mfa-enroll\"")
}

async fn assert_signed_in_single_factor(app: &TestApp, resp: &TestResponse) {
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.signed_in".to_owned()]
    );
    let s = session(app).await;
    assert_eq!(s.amr, amr(&[AMR_PWD]));
    assert_eq!(s.acr, ACR_PWD);
}

/// A client of the default tenant with `policy` and an authorization request for it: returns
/// the login path of the stored request.
async fn login_path_for_client(app: &TestApp, policy: Option<MfaPolicy>) -> String {
    let t = authz::default_tenant(app);
    let c = authz::web_client(app, &t).await;
    app.storage()
        .clients()
        .update(
            t.id,
            &c.client_id,
            &ClientUpdate {
                mfa_policy: Some(policy),
                ..ClientUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    let resp = app
        .get(&authz::authorize_path(
            "",
            &authz::pkce_params(&c.client_id),
        ))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    to_path(app, &location(&resp))
}

#[tokio::test]
async fn off_never_prompts_even_a_user_with_totp() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Off).await;
    enrol_totp(&app, ALICE).await;
    let resp = password(&app, "/ui/login", ALICE).await;
    assert_signed_in_single_factor(&app, &resp).await;
}

#[tokio::test]
async fn optional_prompts_users_with_a_factor_only() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Optional).await;
    enrol_totp(&app, ALICE).await;
    let resp = password(&app, "/ui/login", ALICE).await;
    assert!(is_second_factor(&resp), "{}", resp.text());
    assert!(session_cookie(&app).is_none());

    app.clear_cookies();
    let resp = password(&app, "/ui/login", BOB).await;
    assert_signed_in_single_factor(&app, &resp).await;
}

#[tokio::test]
async fn required_with_a_factor_prompts_for_it() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    enrol_totp(&app, ALICE).await;
    let resp = password(&app, "/ui/login", ALICE).await;
    assert!(is_second_factor(&resp), "{}", resp.text());
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn required_without_a_factor_enrols_then_signs_in_with_mfa() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let page = password(&app, "/ui/login", BOB).await;
    assert!(is_enrolment(&page), "{}", page.text());
    let html = page.html();
    for needle in [
        "id=\"mfa-enroll-required\"",
        "id=\"totp-qr\"",
        "<svg",
        "id=\"totp-secret\"",
        "id=\"code\"",
        "id=\"mfa-enroll-submit\"",
        "Your organisation requires two-step verification",
    ] {
        assert!(html.contains(needle), "{needle} in {html}");
    }
    assert!(form_action(&app, &html).starts_with("/ui/login/second-factor?flow="));
    assert!(
        session_cookie(&app).is_none(),
        "no session before enrolment"
    );
    let csp = page.header("content-security-policy").unwrap_or_default();
    assert!(!csp.contains("unsafe"), "{csp}");

    // A wrong code: the enrolment page again (same key), still no session, nothing stored.
    let code = code_for_page(&app, &html);
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let resp = post_code(&app, &page, wrong).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["mfa_enroll.code_invalid".to_owned()]
    );
    assert_eq!(
        element_text(&resp.html(), "totp-secret"),
        element_text(&html, "totp-secret")
    );
    assert!(session_cookie(&app).is_none());
    let tenant = default_tenant(&app).id;
    let bob = user_id(&app, BOB).await;
    assert!(
        app.storage()
            .users()
            .totp(tenant, bob)
            .await
            .expect("totp")
            .is_none()
    );

    // The right code: recovery codes shown once, signed in with MFA.
    let done = post_code(&app, &resp, &code).await;
    assert_eq!(done.status, 200, "{}", done.text());
    let done_html = done.html();
    assert!(done_html.contains("id=\"recovery-codes\""), "{done_html}");
    assert_eq!(done_html.matches("<li><code>").count(), 10);
    assert_eq!(done.header("cache-control"), Some("no-store"));
    let s = session(&app).await;
    assert_eq!(s.amr, amr(&[AMR_PWD, AMR_OTP, AMR_MFA]));
    assert_eq!(s.acr, ACR_MFA);
    assert!(flow_cookie(&app).is_none(), "flow finished");
    assert!(
        app.storage()
            .users()
            .totp(tenant, bob)
            .await
            .expect("totp")
            .is_some()
    );

    // Replaying the confirming POST: the flow is gone; a fresh sign-in, nobody signed in again.
    app.clear_cookies();
    let replay = app
        .post_form(
            &form_action(&app, &resp.html()),
            &[
                ("csrf_token", csrf_from(&resp.html()).as_str()),
                (
                    "factor_token",
                    hidden(&resp.html(), "factor_token").as_str(),
                ),
                ("code", code.as_str()),
            ],
        )
        .await;
    assert!(
        replay.status == 403 || replay.status == 400,
        "{}",
        replay.status
    );
    assert!(session_cookie(&app).is_none());

    // The confirming code cannot sign in again (its time step was recorded).
    let page = password(&app, "/ui/login", BOB).await;
    assert!(is_second_factor(&page), "{}", page.text());
    let resp = post_code(&app, &page, &code).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.second_factor_invalid".to_owned()]
    );
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn enrolment_continues_the_authorization_request_after_the_codes() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let path = login_path_for_client(&app, None).await;
    let page = password(&app, &path, BOB).await;
    assert!(is_enrolment(&page), "{}", page.text());
    let code = code_for_page(&app, &page.html());
    let done = post_code(&app, &page, &code).await;
    assert_eq!(done.status, 200, "{}", done.text());
    let html = done.html();
    let href = attribute_of(&html, "link-continue", "href");
    assert!(href.contains("/authorize/continue?request="), "{href}");
    let resp = app.get(&to_path(&app, &href)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).starts_with(authz::RP),
        "{}",
        location(&resp)
    );
    assert!(location(&resp).contains("code="));
}

#[tokio::test]
async fn client_required_overrides_tenant_off() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Off).await;
    enrol_totp(&app, ALICE).await;
    let path = login_path_for_client(&app, Some(MfaPolicy::Required)).await;
    let resp = password(&app, &path, ALICE).await;
    assert!(is_second_factor(&resp), "{}", resp.text());
    app.clear_cookies();
    let path = login_path_for_client(&app, Some(MfaPolicy::Required)).await;
    let resp = password(&app, &path, BOB).await;
    assert!(is_enrolment(&resp), "{}", resp.text());
}

#[tokio::test]
async fn client_off_cannot_relax_tenant_required() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let path = login_path_for_client(&app, Some(MfaPolicy::Off)).await;
    let resp = password(&app, &path, BOB).await;
    assert!(is_enrolment(&resp), "{}", resp.text());
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn client_policy_of_an_off_tenant_without_request_does_not_apply() {
    // Without an authorization request only the tenant policy counts.
    let app = app().await;
    set_policy(&app, MfaPolicy::Off).await;
    let resp = password(&app, "/ui/login", BOB).await;
    assert_signed_in_single_factor(&app, &resp).await;
}

#[tokio::test]
async fn enrolment_post_without_csrf_or_with_a_wrong_one_is_forbidden() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let page = password(&app, "/ui/login", BOB).await;
    assert!(is_enrolment(&page));
    let html = page.html();
    let action = form_action(&app, &html);
    let token = hidden(&html, "factor_token");
    let code = code_for_page(&app, &html);
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
    let bob = user_id(&app, BOB).await;
    assert!(
        app.storage()
            .users()
            .totp(default_tenant(&app).id, bob)
            .await
            .expect("totp")
            .is_none(),
        "nothing enrolled"
    );
}

/// The value of `attr` on the element with `id`.
fn attribute_of(html: &str, id: &str, attr: &str) -> String {
    let start = html
        .find(&format!("id=\"{id}\""))
        .unwrap_or_else(|| panic!("element #{id}"));
    let tag_start = html[..start].rfind('<').expect("tag");
    let tag_end = html[start..].find('>').expect("tag end") + start;
    let tag = &html[tag_start..tag_end];
    let marker = format!("{attr}=\"");
    let i = tag.find(&marker).expect("attribute") + marker.len();
    let end = tag[i..].find('"').expect("quoted") + i;
    tag[i..end].replace("&amp;", "&")
}
