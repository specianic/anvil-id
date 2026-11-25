//! Password recovery through the built-in pages (AUTH-03, UI-01) on the selected backend
//! (`ANVILID_TEST_DB`).

mod support;
mod ui_helpers;

use anvil_core::model::SecretHash;
use anvil_core::ports::Clock as _;
use support::TestApp;
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const OLD: &str = "correct horse battery";
const NEW: &str = "a brand new passphrase";

async fn session_active(app: &TestApp, cookie: &str) -> bool {
    app.storage()
        .sessions()
        .get_active(
            default_tenant(app).id,
            &SecretHash(anvil_jose::encoding::secret_hash(cookie)),
            app.clock().now(),
        )
        .await
        .expect("session lookup")
        .is_some()
}

#[tokio::test]
async fn recovery_resets_the_password_revokes_sessions_and_is_single_use() {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, OLD).await;
    take_emails(&app).await; // the verification email

    // An existing session (signed in before the reset).
    assert_eq!(login(&app, "", EMAIL, OLD).await.status, 200);
    let (_, old_session) = session_cookie(&app).expect("signed in");
    assert!(session_active(&app, &old_session).await);
    app.clear_cookies();

    // Request: always `recovery.sent`.
    let resp = submit_form(&app, "/ui/recovery", &[("email", EMAIL)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["recovery.sent".to_owned()]);
    let emails = take_emails(&app).await;
    let link = link_of(&app, &emails, "recovery");
    assert!(link.starts_with("/ui/recovery?token="), "{link}");

    // The link shows the reset form (GET does not consume the token).
    let page = app.get(&link).await;
    assert_eq!(page.status, 200);
    assert!(page.html().contains("id=\"recovery-reset-submit\""));

    // Reset.
    let resp = submit_form(&app, &link, &[("password", NEW)]).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["recovery.done".to_owned()]);
    assert!(!resp.html().contains(NEW), "password never echoed");

    // Old password fails, new one works.
    app.clear_cookies();
    assert_eq!(login(&app, "", EMAIL, OLD).await.status, 400);
    app.clear_cookies();
    assert_eq!(login(&app, "", EMAIL, NEW).await.status, 200);

    // Every session from before the reset is revoked.
    assert!(
        !session_active(&app, &old_session).await,
        "prior sessions are revoked by the reset"
    );

    // The token cannot be reused.
    app.clear_cookies();
    let resp = submit_form(&app, &link, &[("password", "yet another passphrase")]).await;
    assert_eq!(resp.status, 400);
    assert!(
        message_keys(&resp.html()).contains(&"recovery.invalid_token".to_owned()),
        "{}",
        resp.html()
    );

    // The user was told about the change.
    let emails = take_emails(&app).await;
    let notices: Vec<_> = emails
        .iter()
        .filter(|e| e.template == "password_changed")
        .collect();
    assert_eq!(notices.len(), 1, "{emails:?}");
    assert_eq!(notices[0].to, EMAIL);
}

#[tokio::test]
async fn recovery_for_an_unknown_email_sends_nothing_but_answers_the_same() {
    let app = TestApp::new().await;
    let resp = submit_form(&app, "/ui/recovery", &[("email", "nobody@example.com")]).await;
    assert_eq!(resp.status, 200);
    assert_eq!(message_keys(&resp.html()), vec!["recovery.sent".to_owned()]);
    assert!(take_emails(&app).await.is_empty());
}

#[tokio::test]
async fn reset_with_a_short_password_keeps_the_token() {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, OLD).await;
    take_emails(&app).await;
    submit_form(&app, "/ui/recovery", &[("email", EMAIL)]).await;
    let link = link_of(&app, &take_emails(&app).await, "recovery");
    let resp = submit_form(&app, &link, &[("password", "short")]).await;
    assert_eq!(resp.status, 400);
    assert!(message_keys(&resp.html()).contains(&"password.too_short".to_owned()));
    // The token was handed back unconsumed: a valid reset still works.
    let resp = submit_form(&app, &link, &[("password", NEW)]).await;
    assert_eq!(message_keys(&resp.html()), vec!["recovery.done".to_owned()]);
}
