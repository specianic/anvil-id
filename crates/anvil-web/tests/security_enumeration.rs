//! Account enumeration resistance (SEC-04): recovery and login answer identically for existing
//! and unknown accounts, and login always runs an Argon2 verification (the dummy hash for unknown
//! users). Selected backend via `ANVILID_TEST_DB`.

mod support;
mod ui_helpers;

use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

async fn app() -> OwnApp {
    let app = OwnApp::installed().await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
}

#[tokio::test]
async fn recovery_for_an_existing_and_an_unknown_email_is_identical() {
    let app = app().await;
    let existing = submit_form(&app, "/ui/recovery", &[("email", EMAIL)]).await;
    app.clear_cookies();
    let unknown = submit_form(&app, "/ui/recovery", &[("email", "nobody@example.com")]).await;
    assert_eq!(existing.status, unknown.status);
    assert_eq!(existing.status, 200);
    assert_eq!(normalize(&existing.html()), normalize(&unknown.html()));
    assert_eq!(
        message_keys(&existing.html()),
        vec!["recovery.sent".to_owned()]
    );
}

#[tokio::test]
async fn unknown_user_and_wrong_password_are_identical_and_both_run_argon2() {
    let app = app().await;

    let before = app.hasher.verifications();
    let wrong = login(&app, "", EMAIL, "not the password").await;
    let after_wrong = app.hasher.verifications();
    app.clear_cookies();
    let unknown = login(&app, "", "nobody@example.com", "not the password").await;
    let after_unknown = app.hasher.verifications();

    assert_eq!(wrong.status, 400);
    assert_eq!(wrong.status, unknown.status);
    // The identifier is echoed, so compare with it masked.
    let w = normalize(&wrong.html()).replace(EMAIL, "IDENTIFIER");
    let u = normalize(&unknown.html()).replace("nobody@example.com", "IDENTIFIER");
    assert_eq!(w, u);
    assert_eq!(
        message_keys(&wrong.html()),
        vec!["login.invalid_credentials".to_owned()]
    );
    assert_eq!(after_wrong, before + 1, "wrong password verified once");
    assert_eq!(
        after_unknown,
        after_wrong + 1,
        "unknown user ran the dummy hash"
    );
}
