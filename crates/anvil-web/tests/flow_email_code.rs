//! Email one-time code and magic-link sign-in (AUTH-06) through the built-in pages, on the selected
//! backend (`ANVILID_TEST_DB`): the sign-in page offers it only when the tenant enables it, a known
//! verified user gets one sealed `login_code` email (code, link, 10 minutes), the code and the
//! link sign in single-factor (`amr` `[otp]`, pwd `acr`), the MFA policy applies afterwards
//! (`[otp, mfa]` after enrolment), the authorization request continues, and `login_hint`
//! prefills the address. The negative controls are in `security_email_code.rs`.

mod email_code_support;
mod support;
mod token_support;
mod ui_helpers;

use anvil_core::model::{
    ACR_MFA, ACR_PWD, AuditAction, ClientAuthMethod, ClientUpdate, ConsentMode, MfaPolicy,
};
use anvil_core::ports::Clock as _;
use aws_lc_rs::hmac;
use email_code_support::*;
use support::{csrf_from, location};
use token_support::{CHALLENGE, REDIRECT, web_input};
use ui_helpers::*;

#[tokio::test]
async fn enabled_tenant_sends_one_sealed_code_that_signs_in_with_otp() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert_eq!(message_keys(&html), vec!["email_code.sent"]);
    assert!(html.contains(r#"autocomplete="one-time-code""#), "{html}");
    assert!(html.contains(r#"inputmode="numeric""#), "{html}");
    assert!(!html.contains("<script"), "the page needs no JavaScript");

    let mail = one_code(&app).await;
    assert_eq!(mail.to, ALICE);
    assert_eq!(mail.code.len(), 6);
    assert!(mail.code.bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(mail.expires_minutes, "10");
    assert!(
        mail.link.starts_with("/ui/login/email-link?flow="),
        "{}",
        mail.link
    );
    assert_eq!(audit(&app, AuditAction::EmailCodeSent).await.len(), 1);

    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["login.signed_in"]);
    let s = session(&app).await.expect("signed in");
    assert_eq!(s.user_id, user_id(&app, ALICE).await);
    assert_eq!(s.amr, strs(&["otp"]));
    assert_eq!(s.acr, ACR_PWD);
    assert!(flow_cookie(&app).is_none(), "the flow is finished");
    // Newest first (registration signed the users in before).
    let ok = audit(&app, AuditAction::LoginSucceeded).await;
    assert!(
        format!("{:?}", ok[0].details).contains("email_code"),
        "{ok:?}"
    );
}

#[tokio::test]
async fn magic_link_posted_from_the_same_browser_signs_in() {
    let app = setup().await;
    request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let (page, resp) = open_link(&app, &mail.link).await;
    assert_eq!(page.header("cache-control"), Some("no-store"));
    assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
    assert!(page.html().contains("id=\"magic-link-submit\""));
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["login.signed_in"]);
    let s = session(&app).await.expect("signed in");
    assert_eq!(s.amr, strs(&["otp"]));
    assert_eq!(s.acr, ACR_PWD);
    let ok = audit(&app, AuditAction::LoginSucceeded).await;
    assert!(
        format!("{:?}", ok[0].details).contains("magic_link"),
        "{ok:?}"
    );
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

async fn set_policy(app: &support::TestApp, policy: MfaPolicy) {
    update_settings(app, |s| s.mfa_policy = policy).await;
}

/// Confirms the enrolment page with the current code for its key.
async fn confirm_enrolment(
    app: &support::TestApp,
    page: &support::TestResponse,
) -> support::TestResponse {
    let html = page.html();
    let seed = base32_decode(&element_text(&html, "totp-secret"));
    let code = totp_code(&seed, app.clock().now().unix_timestamp());
    let csrf = csrf_from(&html);
    let token = hidden(&html, "factor_token").expect("second-factor token");
    app.post_form(
        &form_action(app, &html),
        &[
            ("csrf_token", csrf.as_str()),
            ("factor_token", token.as_str()),
            ("code", code.as_str()),
        ],
    )
    .await
}

#[tokio::test]
async fn required_mfa_policy_applies_after_the_code_and_after_the_link() {
    let app = setup().await;
    set_policy(&app, MfaPolicy::Required).await;

    // Code: enrolment follows (no session yet), then [otp, mfa].
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let enroll = submit_code(&app, &page, &mail.code).await;
    assert_eq!(enroll.status, 200, "{}", enroll.text());
    assert!(
        enroll.html().contains("id=\"mfa-enroll\""),
        "{}",
        enroll.html()
    );
    assert!(
        session(&app).await.is_none(),
        "no session before the second factor"
    );
    let done = confirm_enrolment(&app, &enroll).await;
    assert_eq!(done.status, 200, "{}", done.text());
    let s = session(&app).await.expect("signed in");
    assert_eq!(s.amr, strs(&["otp", "mfa"]));
    assert_eq!(s.acr, ACR_MFA);
    assert!(!s.amr.contains(&"pwd".to_owned()));

    // Link: the second factor continues in a fresh flow (new flow cookie + CSRF token).
    app.clear_cookies();
    app.clock().advance(std::time::Duration::from_secs(60));
    request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let (_, second) = open_link(&app, &mail.link).await;
    assert_eq!(second.status, 200, "{}", second.text());
    assert!(
        second.html().contains("id=\"second-factor\""),
        "{}",
        second.html()
    );
    assert!(session(&app).await.is_none());
    assert!(
        flow_cookie(&app).is_some(),
        "a fresh flow carries the second factor"
    );
}

#[tokio::test]
async fn disabled_tenant_offers_nothing_and_refuses_the_routes() {
    let app = setup().await;
    let page = app.get("/ui/login").await;
    assert!(page.html().contains("id=\"email-code-request\""));
    enable(&app, false).await;
    let page = app.get("/ui/login").await;
    let html = page.html();
    assert!(!html.contains("email-code"), "{html}");
    let csrf = csrf_from(&html);
    let flow = flow_in(&form_action(&app, &html));
    for path in [
        format!("/ui/login/email-code?flow={flow}"),
        format!("/ui/login/email-code/verify?flow={flow}"),
        format!("/ui/login/email-link?flow={flow}"),
    ] {
        let resp = app
            .post_form(&path, &[("csrf_token", csrf.as_str()), ("email", ALICE)])
            .await;
        assert_eq!(resp.status, 404, "{path}: {}", resp.text());
    }
    let resp = app
        .get(&format!("/ui/login/email-link?flow={flow}&token=abc"))
        .await;
    assert_eq!(resp.status, 404);
    assert!(login_codes(&app).await.is_empty());
}

#[tokio::test]
async fn login_hint_prefills_the_address_and_the_request_continues() {
    let app = setup().await;
    let t = default_tenant(&app);
    let rp =
        token_support::register(&app, t.id, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    app.storage()
        .clients()
        .update(
            t.id,
            rp.id(),
            &ClientUpdate {
                consent_mode: Some(ConsentMode::SkipFirstParty),
                ..ClientUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client");
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", rp.id()),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("state", "st-1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("login_hint", " Alice@Example.com "),
        ])
        .finish();
    let resp = app.get(&format!("/authorize?{q}")).await;
    let login = to_path(&app, &location(&resp));
    let page = app.get(&login).await;
    let html = page.html();
    let form_start = html.find("id=\"email-code-request\"").expect("email form");
    assert!(
        html[form_start..].contains("value=\"alice@example.com\""),
        "{html}"
    );
    assert!(html.contains("id=\"email-code-toggle\" open"), "{html}");

    let page = request_code_at(&app, &login, ALICE).await;
    let mail = one_code(&app).await;
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).contains("/authorize/continue?request="),
        "{}",
        location(&resp)
    );
    let resp = app.follow(&resp).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
}
