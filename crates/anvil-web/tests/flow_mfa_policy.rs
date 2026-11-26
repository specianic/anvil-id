//! MFA policy enforcement in the login flow (AUTH-08) through the built-in pages, on the selected
//! backend (`ANVILID_TEST_DB`): the effective policy (strictest of tenant and client) against users
//! with and without a second factor, in-flow enrolment of an authenticator app when the policy is
//! `required` (QR code and key, wrong code, recovery codes shown once, `[pwd, otp, mfa]`), its
//! binding (CSRF) and single use of the confirming code; the passkey choice of the enrolment page
//! (a software authenticator, test code only): `[hwk, user, mfa]` and MFA `acr`, the stored
//! passkey, step-up into a passkey enrolment, and refusal of abandoned, replayed, cross-flow and
//! never-requested registrations, and of unbound requests.
//!
//! The route-class limit for auth POSTs is raised so several sign-ins from the one test peer are
//! not cut off by it (tested in `security_ratelimit.rs`); the brute-force limits stay on.

mod authz;
mod passkey_support;
mod support;
mod ui_helpers;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    ACR_MFA, ACR_PWD, AMR_HWK, AMR_MFA, AMR_OTP, AMR_PWD, AMR_USER, AuditAction, AuditEvent,
    AuditQuery, BrowserSession, ClientUpdate, CredentialId, MfaPolicy, NewTotp, SecretHash,
    TOTP_SEED_PURPOSE, TenantSettings, UserId, credential_aad,
};
use anvil_core::ports::{Clock as _, PasskeyCeremonies as _, PasskeyUser};
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::otp::TotpSecret;
use anvil_web::adapters::{WebauthnPasskeys, relying_party};
use aws_lc_rs::hmac;
use passkey_support::{FLAG_AT, FLAG_UP, FLAG_UV, SoftAuthenticator};
use support::{TestApp, TestResponse, csrf_from, json, location};
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

// ---------------------------------------------------------------------------------------------
// Passkey enrolment (the passkey choice of the enrolment page)
// ---------------------------------------------------------------------------------------------

const PASSKEY_FAILED: &str = "mfa_enroll.passkey_failed";

fn rp_id() -> &'static str {
    "op.test"
}

fn origin() -> &'static str {
    "https://op.test"
}

/// The passkey form of an enrolment page: (options path, finish path, csrf token, factor token).
fn passkey_enrol_form(app: &TestApp, page: &TestResponse) -> (String, String, String, String) {
    let html = page.html();
    (
        to_path(
            app,
            &attribute_of(&html, "mfa-enroll-passkey-form", "data-options-url"),
        ),
        to_path(
            app,
            &attribute_of(&html, "mfa-enroll-passkey-form", "action"),
        ),
        csrf_from(&html),
        hidden(&html, "factor_token"),
    )
}

/// POSTs the options request like webauthn.js and returns the creation options.
async fn creation_options(app: &TestApp, options: &str, csrf: &str) -> serde_json::Value {
    let resp = app.post_form(options, &[("csrf_token", csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    json(&resp)
}

fn challenge_of(options: &serde_json::Value) -> String {
    options["publicKey"]["challenge"]
        .as_str()
        .expect("challenge")
        .to_owned()
}

fn authenticator(user: UserId) -> SoftAuthenticator {
    SoftAuthenticator::new(&PasskeyUser {
        id: user,
        name: BOB.to_owned(),
        display_name: BOB.to_owned(),
    })
}

/// A registration response of `auth` for `challenge`.
fn registration(auth: &SoftAuthenticator, challenge: &str) -> String {
    auth.register(challenge, rp_id(), origin(), FLAG_UP | FLAG_UV | FLAG_AT)
}

/// Posts a registration response to the finish route, like webauthn.js.
async fn finish(
    app: &TestApp,
    action: &str,
    csrf: &str,
    factor: &str,
    response: &str,
) -> TestResponse {
    app.post_form(
        action,
        &[
            ("csrf_token", csrf),
            ("factor_token", factor),
            ("response", response),
        ],
    )
    .await
}

async fn passkey_count(app: &TestApp, email: &str) -> usize {
    let user = user_id(app, email).await;
    app.storage()
        .users()
        .passkeys(default_tenant(app).id, user)
        .await
        .expect("passkeys")
        .len()
}

async fn audit(app: &TestApp, action: AuditAction) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                action: Some(action),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

/// A refused passkey enrolment: the enrolment page again (400) with `mfa_enroll.passkey_failed`
/// in the passkey section, both choices still offered, nobody signed in.
fn assert_refused(app: &TestApp, resp: &TestResponse) {
    assert_eq!(resp.status, 400, "{}", resp.text());
    let html = resp.html();
    assert_eq!(message_keys(&html), vec![PASSKEY_FAILED.to_owned()]);
    assert!(html.contains("id=\"mfa-enroll-passkey-msg-1\""), "{html}");
    assert!(html.contains("id=\"mfa-enroll-passkey-form\""), "{html}");
    assert!(html.contains("id=\"mfa-enroll\""), "{html}");
    assert!(html.contains("id=\"totp-secret\""), "{html}");
    assert!(session_cookie(app).is_none(), "nobody signed in");
}

#[tokio::test]
async fn required_enrolment_offers_a_passkey_and_an_authenticator_app() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let page = password(&app, "/ui/login", BOB).await;
    assert!(is_enrolment(&page), "{}", page.text());
    let html = page.html();
    for needle in [
        "id=\"mfa-enroll-passkey\"",
        "id=\"mfa-enroll-passkey-form\"",
        "data-webauthn=\"register\"",
        "id=\"mfa-enroll-passkey-submit\" data-webauthn-trigger hidden",
        "data-webauthn-status aria-live=\"polite\"",
        "id=\"mfa-enroll-passkey-nojs\"",
        "<input type=\"hidden\" name=\"response\" value=\"\">",
        "<script src=\"/assets/webauthn.js\" defer></script>",
        "id=\"mfa-enroll-totp\"",
        "id=\"totp-secret\"",
        "Add a passkey or an authenticator app",
    ] {
        assert!(html.contains(needle), "{needle} in {html}");
    }
    // The authenticator-app form (no JavaScript needed) is the page's first form; the passkey
    // choice follows it.
    assert!(
        html.find("id=\"mfa-enroll\"").unwrap()
            < html.find("id=\"mfa-enroll-passkey-form\"").unwrap()
    );
    let (options, action, _, factor) = passkey_enrol_form(&app, &page);
    assert!(
        options.starts_with("/ui/login/enroll/passkey/start?flow="),
        "{options}"
    );
    assert!(
        action.starts_with("/ui/login/enroll/passkey/finish?flow="),
        "{action}"
    );
    assert!(!factor.is_empty());
    let csp = page.header("content-security-policy").expect("csp");
    assert!(csp.contains("script-src 'self'"), "{csp}");
    assert!(csp.contains("connect-src 'self'"), "{csp}");
    assert!(!csp.contains("unsafe"), "{csp}");
}

#[tokio::test]
async fn passkey_enrolment_signs_in_with_passkey_amr_and_stores_the_passkey() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let bob = user_id(&app, BOB).await;
    let page = password(&app, "/ui/login", BOB).await;
    assert!(is_enrolment(&page), "{}", page.text());
    let (options, action, csrf, factor) = passkey_enrol_form(&app, &page);

    let opts = creation_options(&app, &options, &csrf).await;
    assert_eq!(opts["publicKey"]["rp"]["id"], rp_id());
    assert_eq!(opts["publicKey"]["user"]["name"], BOB);
    let auth = authenticator(bob);
    let resp = finish(
        &app,
        &action,
        &csrf,
        &factor,
        &registration(&auth, &challenge_of(&opts)),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.signed_in".to_owned()]
    );
    let s = session(&app).await;
    assert_eq!(s.user_id, bob);
    assert_eq!(s.amr, amr(&[AMR_HWK, AMR_USER, AMR_MFA]));
    assert_eq!(s.acr, ACR_MFA);
    assert!(flow_cookie(&app).is_none(), "flow finished");
    assert_eq!(passkey_count(&app, BOB).await, 1);
    assert!(
        app.storage()
            .users()
            .totp(default_tenant(&app).id, bob)
            .await
            .expect("totp")
            .is_none(),
        "the authenticator app was not enrolled"
    );
    let registered = audit(&app, AuditAction::PasskeyRegistered).await;
    assert_eq!(registered.len(), 1);
    let signed_in = audit(&app, AuditAction::LoginSucceeded).await;
    assert!(
        signed_in
            .iter()
            .any(|e| e.target.as_deref() == Some(bob.to_string().as_str())),
        "login_succeeded for bob"
    );

    // The new passkey signs bob in on the next visit (a passkey sign-in satisfies `required`).
    app.clear_cookies();
    let login = app.get("/ui/login").await;
    let html = login.html();
    let options = to_path(
        &app,
        &attribute_of(&html, "login-passkey", "data-options-url"),
    );
    let action = to_path(&app, &attribute_of(&html, "login-passkey", "action"));
    let csrf = csrf_from(&html);
    let resp = app.post_form(&options, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let challenge = challenge_of(&json(&resp));
    let assertion = auth.assert(&challenge, rp_id(), origin(), FLAG_UP | FLAG_UV, 1);
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("response", &assertion)])
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = session(&app).await;
    assert_eq!(s.user_id, bob);
    assert_eq!(s.amr, amr(&[AMR_HWK, AMR_USER, AMR_MFA]));
}

#[tokio::test]
async fn passkey_enrolment_continues_the_authorization_request() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let path = login_path_for_client(&app, None).await;
    let page = password(&app, &path, BOB).await;
    assert!(is_enrolment(&page), "{}", page.text());
    let (options, action, csrf, factor) = passkey_enrol_form(&app, &page);
    let opts = creation_options(&app, &options, &csrf).await;
    let auth = authenticator(user_id(&app, BOB).await);
    let resp = finish(
        &app,
        &action,
        &csrf,
        &factor,
        &registration(&auth, &challenge_of(&opts)),
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let continue_to = location(&resp);
    assert!(
        continue_to.contains("/authorize/continue?request="),
        "{continue_to}"
    );
    let resp = app.get(&to_path(&app, &continue_to)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).starts_with(authz::RP),
        "{}",
        location(&resp)
    );
    assert!(location(&resp).contains("code="));
}

#[tokio::test]
async fn step_up_into_enrolment_can_be_satisfied_with_a_passkey_in_place() {
    // Tenant off: bob signs in with the password alone; a client that requires MFA then steps
    // the same session up through the enrolment page, here with a passkey.
    let app = app().await;
    set_policy(&app, MfaPolicy::Off).await;
    let resp = password(&app, "/ui/login", BOB).await;
    assert_signed_in_single_factor(&app, &resp).await;
    let before = session(&app).await;

    let path = login_path_for_client(&app, Some(MfaPolicy::Required)).await;
    let page = app.get(&path).await;
    assert!(is_enrolment(&page), "{}", page.text());
    assert!(
        !page.html().contains("id=\"password\""),
        "no password again"
    );
    let (options, action, csrf, factor) = passkey_enrol_form(&app, &page);
    let opts = creation_options(&app, &options, &csrf).await;
    let auth = authenticator(before.user_id);
    let resp = finish(
        &app,
        &action,
        &csrf,
        &factor,
        &registration(&auth, &challenge_of(&opts)),
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).contains("/authorize/continue?request="));
    let after = session(&app).await;
    assert_eq!(after.id, before.id, "upgraded in place");
    assert_eq!(after.amr, amr(&[AMR_PWD, AMR_HWK, AMR_USER, AMR_MFA]));
    assert_eq!(after.acr, ACR_MFA);
    assert_eq!(audit(&app, AuditAction::StepUpCompleted).await.len(), 1);
}

#[tokio::test]
async fn a_replayed_passkey_enrolment_challenge_is_refused() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let page = password(&app, "/ui/login", BOB).await;
    let (options, action, csrf, factor) = passkey_enrol_form(&app, &page);
    let opts = creation_options(&app, &options, &csrf).await;
    let auth = authenticator(user_id(&app, BOB).await);
    let valid = registration(&auth, &challenge_of(&opts));

    // A failed finish consumes the challenge: the valid response for it is now a replay.
    let resp = finish(&app, &action, &csrf, &factor, "garbage").await;
    assert_refused(&app, &resp);
    let resp = finish(&app, &action, &csrf, &factor, &valid).await;
    assert_refused(&app, &resp);
    assert_eq!(passkey_count(&app, BOB).await, 0);

    // The user stays at the enrolment step: the authenticator app still works.
    let code = code_for_page(&app, &resp.html());
    let done = post_code(&app, &resp, &code).await;
    assert_eq!(done.status, 200, "{}", done.text());
    assert!(done.html().contains("id=\"recovery-codes\""));
    assert_eq!(session(&app).await.amr, amr(&[AMR_PWD, AMR_OTP, AMR_MFA]));

    // After the sign-in the flow is gone: replaying the response signs nobody in again.
    app.clear_cookies();
    let resp = finish(&app, &action, &csrf, &factor, &valid).await;
    assert!(resp.status == 403 || resp.status == 400, "{}", resp.status);
    assert!(session_cookie(&app).is_none());
    assert_eq!(passkey_count(&app, BOB).await, 0);
}

#[tokio::test]
async fn a_successful_passkey_enrolment_cannot_be_replayed() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let page = password(&app, "/ui/login", BOB).await;
    let (options, action, csrf, factor) = passkey_enrol_form(&app, &page);
    let opts = creation_options(&app, &options, &csrf).await;
    let auth = authenticator(user_id(&app, BOB).await);
    let valid = registration(&auth, &challenge_of(&opts));
    let resp = finish(&app, &action, &csrf, &factor, &valid).await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    // The same POST again, with or without the session: the flow is finished.
    let resp = finish(&app, &action, &csrf, &factor, &valid).await;
    assert!(resp.status == 403 || resp.status == 400, "{}", resp.status);
    app.clear_cookies();
    let resp = finish(&app, &action, &csrf, &factor, &valid).await;
    assert!(resp.status == 403 || resp.status == 400, "{}", resp.status);
    assert!(session_cookie(&app).is_none());
    assert_eq!(passkey_count(&app, BOB).await, 1);
    assert_eq!(audit(&app, AuditAction::PasskeyRegistered).await.len(), 1);
}

#[tokio::test]
async fn an_abandoned_passkey_enrolment_challenge_is_refused() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let page = password(&app, "/ui/login", BOB).await;
    let (options, action, csrf, factor) = passkey_enrol_form(&app, &page);
    let auth = authenticator(user_id(&app, BOB).await);
    // The first ceremony is abandoned and a second one started: the first challenge is gone.
    let first = creation_options(&app, &options, &csrf).await;
    let second = creation_options(&app, &options, &csrf).await;
    assert_ne!(challenge_of(&first), challenge_of(&second));
    let resp = finish(
        &app,
        &action,
        &csrf,
        &factor,
        &registration(&auth, &challenge_of(&first)),
    )
    .await;
    assert_refused(&app, &resp);
    assert_eq!(passkey_count(&app, BOB).await, 0);
    // The refusal used up the pending challenge too; a fresh ceremony succeeds.
    let resp = finish(
        &app,
        &action,
        &csrf,
        &factor,
        &registration(&auth, &challenge_of(&second)),
    )
    .await;
    assert_refused(&app, &resp);
    let third = creation_options(&app, &options, &csrf).await;
    let resp = finish(
        &app,
        &action,
        &csrf,
        &factor,
        &registration(&auth, &challenge_of(&third)),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(passkey_count(&app, BOB).await, 1);
    let failures = audit(&app, AuditAction::LoginFailed).await;
    // Only the response that was actually checked is audited (the second had nothing pending).
    assert_eq!(failures.len(), 1, "{failures:?}");
}

#[tokio::test]
async fn a_passkey_enrolment_challenge_from_another_flow_is_refused() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let auth = authenticator(user_id(&app, BOB).await);
    // Flow A: a challenge whose response is never posted there.
    let page_a = password(&app, "/ui/login", BOB).await;
    let (options_a, _, csrf_a, _) = passkey_enrol_form(&app, &page_a);
    let from_a = registration(
        &auth,
        &challenge_of(&creation_options(&app, &options_a, &csrf_a).await),
    );
    // Flow B (another browser): its own challenge pending, A's response posted.
    app.clear_cookies();
    let page_b = password(&app, "/ui/login", BOB).await;
    let (options_b, action_b, csrf_b, factor_b) = passkey_enrol_form(&app, &page_b);
    creation_options(&app, &options_b, &csrf_b).await;
    let resp = finish(&app, &action_b, &csrf_b, &factor_b, &from_a).await;
    assert_refused(&app, &resp);
    assert_eq!(passkey_count(&app, BOB).await, 0);
}

#[tokio::test]
async fn a_passkey_finish_without_a_pending_challenge_is_refused() {
    // The user went the authenticator-app way (never asked for passkey options): a registration
    // made for a challenge this flow never issued is refused.
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let bob = user_id(&app, BOB).await;
    let page = password(&app, "/ui/login", BOB).await;
    let (_, action, csrf, factor) = passkey_enrol_form(&app, &page);
    let rp = relying_party(&default_tenant(&app), &app.issuer(None)).expect("relying party");
    let foreign = WebauthnPasskeys
        .start_registration(
            &rp,
            &PasskeyUser {
                id: bob,
                name: BOB.into(),
                display_name: BOB.into(),
            },
            &[],
        )
        .expect("start");
    let foreign: serde_json::Value = serde_json::from_str(&foreign.options_json).expect("json");
    let auth = authenticator(bob);
    let resp = finish(
        &app,
        &action,
        &csrf,
        &factor,
        &registration(&auth, &challenge_of(&foreign)),
    )
    .await;
    assert_refused(&app, &resp);
    assert_eq!(passkey_count(&app, BOB).await, 0);
    // The authenticator-app choice still works afterwards.
    let code = code_for_page(&app, &resp.html());
    let done = post_code(&app, &resp, &code).await;
    assert_eq!(done.status, 200, "{}", done.text());
}

#[tokio::test]
async fn passkey_enrolment_routes_are_bound_to_the_flow_and_its_enrolment_step() {
    let app = app().await;
    set_policy(&app, MfaPolicy::Required).await;
    let page = password(&app, "/ui/login", BOB).await;
    let (options, action, csrf, factor) = passkey_enrol_form(&app, &page);

    // Options: without or with a wrong CSRF token, or without the flow cookie: 403.
    let resp = app.post_form(&options, &[]).await;
    assert_eq!(resp.status, 403);
    assert_eq!(json(&resp)["error"], "csrf");
    let resp = app.post_form(&options, &[("csrf_token", "wrong")]).await;
    assert_eq!(resp.status, 403);
    assert_eq!(json(&resp)["error"], "csrf");
    // Finish: the csrf page, nothing stored.
    let resp = app
        .post_form(&action, &[("factor_token", &factor), ("response", "{}")])
        .await;
    assert_eq!(resp.status, 403);
    assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    let resp = finish(&app, &action, "wrong", &factor, "{}").await;
    assert_eq!(resp.status, 403);
    app.clear_cookies();
    let resp = app.post_form(&options, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 403);
    let resp = finish(&app, &action, &csrf, &factor, "{}").await;
    assert_eq!(resp.status, 403);
    assert!(session_cookie(&app).is_none());

    // A login flow that is not at the enrolment step offers no passkey enrolment.
    let login = app.get("/ui/login").await;
    let html = login.html();
    let flow_action = form_action(&app, &html);
    let flow = flow_action
        .split("?flow=")
        .nth(1)
        .expect("flow id")
        .to_owned();
    let resp = app
        .post_form(
            &format!("/ui/login/enroll/passkey/start?flow={flow}"),
            &[("csrf_token", &csrf_from(&html))],
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(json(&resp)["error"], PASSKEY_FAILED);
    let resp = app
        .post_form(
            &format!("/ui/login/enroll/passkey/finish?flow={flow}"),
            &[("csrf_token", &csrf_from(&html)), ("response", "{}")],
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(session_cookie(&app).is_none());
    assert_eq!(passkey_count(&app, BOB).await, 0);
}

#[tokio::test]
async fn optional_and_off_never_show_the_enrolment_choice() {
    let app = app().await;
    for policy in [MfaPolicy::Off, MfaPolicy::Optional] {
        set_policy(&app, policy).await;
        app.clear_cookies();
        let resp = password(&app, "/ui/login", BOB).await;
        assert!(!resp.html().contains("mfa-enroll-passkey"), "{policy:?}");
        assert_signed_in_single_factor(&app, &resp).await;
    }
}
