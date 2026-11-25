//! Negative tests for email code and magic-link sign-in (AUTH-06), on the selected backend
//! (`ANVILID_TEST_DB`). Every control has a test that it rejects bad input:
//!
//! - no account enumeration: unknown, unverified and blocked addresses get the same page and no
//!   email; an address unverified after the send cannot use its code;
//! - single use (also under a concurrent double submit), the five-attempt cap, the 10-minute TTL,
//!   the three-sends cap;
//! - the magic link: GET consumes nothing, a second POST is refused, a POST from another browser
//!   (no flow cookie) consumes nothing, wrong CSRF tokens are 403;
//! - the code is not stored in clear; the limiter escalates per address across peers and locks code
//!   attempts per user; `amr` never contains `mfa`.
//! - `email_otp` and `magic_link` are separate: a method that is off (or was off when the email
//!   was sent) cannot sign in, at the route (404) and in core (the code is refused before any
//!   attempt is counted, the link consumes nothing).

mod email_code_support;
mod support;
mod ui_helpers;

use std::net::SocketAddr;

use anvil_core::model::{ACR_PWD, AuditAction, FlowId};
use anvil_core::ports::Clock as _;
use email_code_support::*;
use support::{TestApp, csrf_from};
use ui_helpers::*;

async fn sign_ins(app: &TestApp) -> usize {
    audit(app, AuditAction::LoginSucceeded)
        .await
        .iter()
        .filter(|e| {
            format!("{:?}", e.details).contains("email_code")
                || format!("{:?}", e.details).contains("magic_link")
        })
        .count()
}

#[tokio::test]
async fn unknown_unverified_and_blocked_addresses_look_the_same_and_get_nothing() {
    let app = setup().await;
    register(&app, "", "carol@example.com", PASSWORD).await;
    set_verified(&app, "carol@example.com", true).await;
    block_user(&app, default_tenant(&app).id, "carol@example.com").await;

    let known = request_code(&app, ALICE).await;
    assert_eq!(one_code(&app).await.to, ALICE);
    let expected = normalized(&known.html());
    for email in [
        "nobody@example.com",
        BOB,                 // registered, email not verified
        "carol@example.com", // verified but blocked
    ] {
        app.clear_cookies();
        let resp = request_code(&app, email).await;
        assert_eq!(resp.status, known.status, "{email}");
        assert_eq!(normalized(&resp.html()), expected, "{email}");
        assert!(login_codes(&app).await.is_empty(), "no email for {email}");
    }
    assert_eq!(audit(&app, AuditAction::EmailCodeSent).await.len(), 1);

    // Bob (unverified) cannot sign in even with a guessed code: no code was ever sent, and the
    // stored hash is of a code nobody knows. Five tries invalidate it like any other.
    app.clear_cookies();
    let page = request_code(&app, BOB).await;
    let resp = submit_code(&app, &page, "000000").await;
    assert_eq!(resp.status, 400);
    assert_eq!(message_keys(&resp.html()), vec!["email_code.invalid"]);
    assert!(session(&app).await.is_none());
}

#[tokio::test]
async fn an_address_unverified_after_the_send_cannot_use_its_code_or_link() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    set_verified(&app, ALICE, false).await;
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(session(&app).await.is_none());

    set_verified(&app, ALICE, true).await;
    app.clear_cookies();
    request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    set_verified(&app, ALICE, false).await;
    let (_, resp) = open_link(&app, &mail.link).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["email_code.link_invalid"]);
    assert!(session(&app).await.is_none());
}

#[tokio::test]
async fn a_code_works_once() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let first = submit_code(&app, &page, &mail.code).await;
    assert_eq!(first.status, 200, "{}", first.text());
    let first_session = session(&app).await.expect("signed in");
    // The same form again: the flow is gone, a new sign-in starts.
    let again = submit_code(&app, &page, &mail.code).await;
    assert_eq!(again.status, 400, "{}", again.text());
    assert_eq!(message_keys(&again.html()), vec!["flow.expired"]);
    assert_eq!(sign_ins(&app).await, 1);
    assert_eq!(session(&app).await.map(|s| s.id), Some(first_session.id));
    // The link of the used code is dead too.
    let (_, link) = open_link(&app, &mail.link).await;
    assert_eq!(link.status, 400);
    assert_eq!(sign_ins(&app).await, 1);
}

#[tokio::test]
async fn concurrent_submits_of_one_code_sign_in_once() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let (a, b) = tokio::join!(
        submit_code(&app, &page, &mail.code),
        submit_code(&app, &page, &mail.code)
    );
    let signed = [&a, &b]
        .iter()
        .filter(|r| message_keys(&r.html()) == vec!["login.signed_in"])
        .count();
    assert_eq!(signed, 1, "{} / {}", a.text(), b.text());
    assert_eq!(sign_ins(&app).await, 1);
}

#[tokio::test]
async fn five_wrong_codes_invalidate_the_code_and_the_link() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let wrong = if mail.code == "000000" {
        "111111"
    } else {
        "000000"
    };
    for i in 1..=5 {
        let resp = submit_code(&app, &page, wrong).await;
        assert_eq!(resp.status, 400, "attempt {i}: {}", resp.text());
        let expected = if i == 5 {
            "email_code.invalidated"
        } else {
            "email_code.invalid"
        };
        assert_eq!(message_keys(&resp.html()), vec![expected], "attempt {i}");
    }
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(resp.status, 400);
    assert_eq!(message_keys(&resp.html()), vec!["email_code.invalidated"]);
    let (_, link) = open_link(&app, &mail.link).await;
    assert_eq!(link.status, 400);
    assert_eq!(message_keys(&link.html()), vec!["email_code.link_invalid"]);
    assert!(session(&app).await.is_none());
    assert!(audit(&app, AuditAction::LoginFailed).await.len() >= 5);
}

#[tokio::test]
async fn code_attempts_are_locked_per_user_across_new_codes() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let wrong = if mail.code == "000000" {
        "111111"
    } else {
        "000000"
    };
    for _ in 0..5 {
        submit_code(&app, &page, wrong).await;
    }
    // A new code in the same flow does not reset the per-user limiter: the sixth wrong code locks.
    let page = resend(&app, &page).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let mail = one_code(&app).await;
    let wrong = if mail.code == "000000" {
        "111111"
    } else {
        "000000"
    };
    let resp = submit_code(&app, &page, wrong).await;
    assert_eq!(resp.status, 429, "{}", resp.text());
    assert!(resp.header("retry-after").is_some());
    // While locked even the right code is not checked.
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(resp.status, 429);
    assert!(session(&app).await.is_none());
}

#[tokio::test]
async fn expired_code_and_link_are_refused() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    app.clock().advance(std::time::Duration::from_secs(11 * 60));
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["email_code.expired"]);
    let (_, link) = open_link(&app, &mail.link).await;
    assert_eq!(link.status, 400);
    assert_eq!(message_keys(&link.html()), vec!["email_code.link_invalid"]);
    assert!(session(&app).await.is_none());
}

#[tokio::test]
async fn a_flow_sends_at_most_three_emails() {
    let app = setup().await;
    let mut page = request_code(&app, ALICE).await;
    for _ in 0..2 {
        page = resend(&app, &page).await;
        assert_eq!(page.status, 200, "{}", page.text());
    }
    assert_eq!(login_codes(&app).await.len(), 3);
    let fourth = resend(&app, &page).await;
    assert_eq!(fourth.status, 400, "{}", fourth.text());
    assert_eq!(
        message_keys(&fourth.html()),
        vec!["email_code.too_many_sends"]
    );
    assert!(login_codes(&app).await.is_empty());
}

#[tokio::test]
async fn a_new_code_replaces_the_previous_one() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let old = one_code(&app).await;
    let page = resend(&app, &page).await;
    let new = one_code(&app).await;
    if old.code != new.code {
        let resp = submit_code(&app, &page, &old.code).await;
        assert_eq!(resp.status, 400, "{}", resp.text());
    }
    let (_, link) = open_link(&app, &old.link).await;
    assert_eq!(link.status, 400, "the old link is replaced");
    let resp = submit_code(&app, &page, &new.code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn link_get_consumes_nothing_and_the_post_works_once() {
    let app = setup().await;
    request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    // Link scanners: any number of GETs, nothing happens.
    for _ in 0..3 {
        let page = app.get(&mail.link).await;
        assert_eq!(page.status, 200);
        assert_eq!(page.header("cache-control"), Some("no-store"));
        assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
    }
    assert!(session(&app).await.is_none());
    let (page, resp) = open_link(&app, &mail.link).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(sign_ins(&app).await, 1);
    let again = post_link(&app, &page, None).await;
    assert_eq!(again.status, 400, "{}", again.text());
    assert_eq!(sign_ins(&app).await, 1);
}

#[tokio::test]
async fn link_from_another_browser_consumes_nothing() {
    let app = setup().await;
    request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let page = app.get(&mail.link).await;
    // Another browser: no flow cookie (the jar's cookies are not sent).
    let resp = post_link(&app, &page, Some("unrelated=1")).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["email_code.other_browser"]);
    assert_eq!(sign_ins(&app).await, 0);
    // A wrong flow cookie is another browser too.
    let (name, _) = flow_cookie(&app).expect("flow cookie");
    let resp = post_link(&app, &page, Some(&format!("{name}=forged"))).await;
    assert_eq!(message_keys(&resp.html()), vec!["email_code.other_browser"]);
    // Nothing was consumed: the original browser still signs in.
    let resp = post_link(&app, &page, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(sign_ins(&app).await, 1);
}

#[tokio::test]
async fn posts_without_or_with_a_wrong_csrf_token_are_403() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let html = page.html();
    let verify = action_of(&app, &html, "email-code");
    let resend_action = action_of(&app, &html, "email-code-resend");
    let token = hidden(&html, "factor_token").expect("token");
    let link_action = format!("/ui/login/email-link?flow={}", flow_in(&verify));
    let link_token = mail.link.split("token=").nth(1).expect("token").to_owned();
    // Missing CSRF token.
    for (path, pairs) in [
        (
            &verify,
            vec![
                ("factor_token", token.as_str()),
                ("code", mail.code.as_str()),
            ],
        ),
        (&resend_action, vec![("factor_token", token.as_str())]),
        (&link_action, vec![("token", link_token.as_str())]),
    ] {
        let resp = app.post_form(path, &pairs).await;
        assert_eq!(resp.status, 403, "{path}: {}", resp.text());
    }
    // Wrong CSRF token (with the right flow cookie).
    let resp = app
        .post_form(
            &verify,
            &[
                ("csrf_token", "wrong"),
                ("factor_token", token.as_str()),
                ("code", mail.code.as_str()),
            ],
        )
        .await;
    assert_eq!(resp.status, 403);
    let resp = app
        .post_form(
            &link_action,
            &[("csrf_token", "wrong"), ("token", link_token.as_str())],
        )
        .await;
    assert_eq!(resp.status, 403);
    // The form's CSRF token is not the link page's: the link POST needs the derived one.
    let csrf = csrf_from(&html);
    let resp = app
        .post_form(
            &link_action,
            &[
                ("csrf_token", csrf.as_str()),
                ("token", link_token.as_str()),
            ],
        )
        .await;
    assert_eq!(resp.status, 403);
    // A tampered limiter token restarts the sign-in (a new flow and cookie) without checking the
    // code.
    let resp = app
        .post_form(
            &verify,
            &[
                ("csrf_token", csrf.as_str()),
                ("factor_token", "tampered"),
                ("code", mail.code.as_str()),
            ],
        )
        .await;
    assert_eq!(message_keys(&resp.html()), vec!["flow.expired"]);
    assert_eq!(sign_ins(&app).await, 0);
}

#[tokio::test]
async fn rejected_posts_consume_nothing() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let verify = action_of(&app, &page.html(), "email-code");
    let link_action = format!("/ui/login/email-link?flow={}", flow_in(&verify));
    let link_token = mail.link.split("token=").nth(1).expect("token").to_owned();
    let resp = app
        .post_form(
            &link_action,
            &[("csrf_token", "wrong"), ("token", link_token.as_str())],
        )
        .await;
    assert_eq!(resp.status, 403);
    let resp = app
        .post_form(&verify, &[("code", mail.code.as_str())])
        .await;
    assert_eq!(resp.status, 403);
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(sign_ins(&app).await, 1);
}

#[tokio::test]
async fn the_code_and_the_link_token_are_not_stored_in_clear() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    let flow = flow_in(&action_of(&app, &page.html(), "email-code"));
    let id = FlowId(uuid::Uuid::parse_str(&flow).expect("flow id"));
    let stored = app
        .storage()
        .flows()
        .get(default_tenant(&app).id, id, app.clock().now())
        .await
        .expect("flow lookup")
        .expect("flow");
    let token = mail.link.split("token=").nth(1).expect("token");
    assert!(!stored.state.contains(token), "{}", stored.state);
    let digit_runs: Vec<&str> = stored
        .state
        .split(|c: char| !c.is_ascii_digit())
        .filter(|r| !r.is_empty())
        .collect();
    assert!(
        !digit_runs.contains(&mail.code.as_str()),
        "{}",
        stored.state
    );
    assert!(stored.state.contains("code_hash"), "{}", stored.state);
}

#[tokio::test]
async fn sends_per_address_escalate_across_peers() {
    let app = setup_with(|c| c.rate_limits.loose_threshold_per_hour = 3).await;
    let mut statuses = Vec::new();
    for i in 0..5u8 {
        let peer: SocketAddr = format!("198.51.100.{}:4000", 10 + i).parse().expect("peer");
        app.clear_cookies();
        let page = get_from(&app, peer, "/ui/login").await;
        let html = page.html();
        let action = action_of(&app, &html, "email-code-request");
        let csrf = csrf_from(&html);
        let resp = post_from(
            &app,
            peer,
            &action,
            &[
                ("csrf_token", csrf.as_str()),
                ("email", "nobody@example.com"),
            ],
        )
        .await;
        statuses.push(resp.status.as_u16());
    }
    // Three sends for the address (from three peers), then a delay from any peer.
    assert_eq!(statuses, vec![200, 200, 200, 429, 429]);
    // Another address is not affected.
    let resp = request_code(&app, ALICE).await;
    assert_eq!(resp.status, 200);
}

#[tokio::test]
async fn email_sign_in_never_claims_mfa() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    submit_code(&app, &page, &mail.code).await;
    let s = session(&app).await.expect("signed in");
    assert_eq!(s.acr, ACR_PWD);
    assert!(!s.amr.contains(&"mfa".to_owned()), "{:?}", s.amr);
    assert!(!s.amr.contains(&"pwd".to_owned()), "{:?}", s.amr);
}

// ---------------------------------------------------------------------------------------------
// email_otp and magic_link are enforced separately: at the route and in core
// ---------------------------------------------------------------------------------------------

/// The flow id of a "check your email" page.
fn page_flow(app: &TestApp, page: &support::TestResponse) -> String {
    flow_in(&action_of(app, &page.html(), "email-code"))
}

async fn failed_logins(app: &TestApp) -> usize {
    audit(app, AuditAction::LoginFailed).await.len()
}

#[tokio::test]
async fn code_only_tenant_refuses_the_link_routes() {
    let app = setup().await;
    set_email_methods(&app, true, false).await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    assert!(mail.link.is_empty(), "no link in a code-only email");
    let flow = page_flow(&app, &page);
    let link = format!("/ui/login/email-link?flow={flow}&token=internal-token");
    let resp = app.get(&link).await;
    assert_eq!(resp.status, 404, "{}", resp.text());
    let csrf = csrf_from(&page.html());
    let resp = app
        .post_form(
            &format!("/ui/login/email-link?flow={flow}"),
            &[("csrf_token", csrf.as_str()), ("token", "internal-token")],
        )
        .await;
    assert_eq!(resp.status, 404, "{}", resp.text());
    assert!(session(&app).await.is_none());
    assert_eq!(sign_ins(&app).await, 0);
    // Nothing was consumed: the code still signs in.
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(message_keys(&resp.html()), vec!["login.signed_in"]);
}

#[tokio::test]
async fn link_only_tenant_refuses_the_code_route() {
    let app = setup().await;
    set_email_methods(&app, false, true).await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    assert!(mail.code.is_empty(), "no code in a link-only email");
    // The page has no code input, but the form (csrf, factor_token) is there: post a code anyway.
    let resp = submit_code(&app, &page, "123456").await;
    assert_eq!(resp.status, 404, "{}", resp.text());
    assert!(session(&app).await.is_none());
    assert_eq!(failed_logins(&app).await, 0, "no attempt counted");
    // Nothing was consumed: the link still signs in.
    let (_, resp) = open_link(&app, &mail.link).await;
    assert_eq!(message_keys(&resp.html()), vec!["login.signed_in"]);
    assert_eq!(sign_ins(&app).await, 1);
}

#[tokio::test]
async fn a_method_switched_off_after_the_send_is_refused() {
    let app = setup().await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    assert!(!mail.code.is_empty() && !mail.link.is_empty());
    let link_page = app.get(&mail.link).await;
    assert_eq!(link_page.status, 200);

    // email_otp off: the right code is refused at the route.
    set_email_methods(&app, false, true).await;
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(resp.status, 404, "{}", resp.text());
    assert!(session(&app).await.is_none());

    // magic_link off: the link page and its POST are refused.
    set_email_methods(&app, true, false).await;
    assert_eq!(app.get(&mail.link).await.status, 404);
    let resp = post_link(&app, &link_page, None).await;
    assert_eq!(resp.status, 404, "{}", resp.text());
    assert!(session(&app).await.is_none());
    assert_eq!(sign_ins(&app).await, 0);
    assert_eq!(failed_logins(&app).await, 0, "no attempt counted");

    // Both back on: nothing was consumed.
    set_email_methods(&app, true, true).await;
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(message_keys(&resp.html()), vec!["login.signed_in"]);
}

#[tokio::test]
async fn core_refuses_a_code_the_email_did_not_carry() {
    let app = setup().await;
    set_email_methods(&app, false, true).await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    // email_otp switched on after a link-only send: the route lets the POST through, the core
    // refuses (the email had no code), before any attempt is counted.
    set_email_methods(&app, true, true).await;
    for code in ["123456", "000000"] {
        let resp = submit_code(&app, &page, code).await;
        assert_eq!(resp.status, 404, "{}", resp.text());
    }
    assert!(session(&app).await.is_none());
    assert_eq!(failed_logins(&app).await, 0, "no attempt counted");
    let (_, resp) = open_link(&app, &mail.link).await;
    assert_eq!(message_keys(&resp.html()), vec!["login.signed_in"]);
}

#[tokio::test]
async fn core_refuses_a_link_the_email_did_not_carry() {
    let app = setup().await;
    set_email_methods(&app, true, false).await;
    let page = request_code(&app, ALICE).await;
    let mail = one_code(&app).await;
    // magic_link switched on after a code-only send: the link page opens for any token, but the
    // POST is refused (the email had no link) and consumes nothing.
    set_email_methods(&app, true, true).await;
    let flow = page_flow(&app, &page);
    let link_page = app
        .get(&format!("/ui/login/email-link?flow={flow}&token=guessed"))
        .await;
    assert_eq!(link_page.status, 200, "{}", link_page.text());
    let resp = post_link(&app, &link_page, None).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["email_code.link_invalid"]);
    assert!(session(&app).await.is_none());
    let resp = submit_code(&app, &page, &mail.code).await;
    assert_eq!(message_keys(&resp.html()), vec!["login.signed_in"]);
}
