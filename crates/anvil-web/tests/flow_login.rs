//! Login through the built-in page (AUTH-01, UI-01) on the selected backend (`ANVILID_TEST_DB`).

mod support;
mod ui_helpers;

use std::time::Duration;

use anvil_core::model::{RegistrationMode, SecretHash, TenantSettings};
use anvil_core::ports::Clock as _;
use support::{TestApp, csrf_from, location};
use ui_helpers::*;

const REQUEST: &str = "0192f0c4-7a1b-7c3d-8e9f-0123456789ab";
const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

async fn app_with_user() -> TestApp {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
}

#[tokio::test]
async fn login_form_has_the_stable_selectors() {
    let app = TestApp::new().await;
    let resp = app.get(&format!("/ui/login?request={REQUEST}")).await;
    assert_eq!(resp.status, 200);
    let html = resp.html();
    for id in [
        "id=\"login\"",
        "id=\"identifier\"",
        "id=\"password\"",
        "id=\"login-submit\"",
        "id=\"link-recovery\"",
        "id=\"link-registration\"",
    ] {
        assert!(html.contains(id), "{id} in {html}");
    }
    assert!(flow_cookie(&app).is_some(), "flow cookie set on GET");
    assert_eq!(
        form_action(&app, &html).split('?').next(),
        Some("/ui/login"),
        "the form posts back to the login page"
    );
    insta::assert_snapshot!("login_form", form_fragment(&html));
}

#[tokio::test]
async fn valid_credentials_redirect_303_to_the_authorize_continuation_and_rotate_the_session() {
    let app = app_with_user().await;
    let resp = submit_form(
        &app,
        &format!("/ui/login?request={REQUEST}"),
        &[("identifier", EMAIL), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        location(&resp),
        format!("{}/authorize/continue?request={REQUEST}", app.issuer(None))
    );
    let (name, first) = session_cookie(&app).expect("session cookie set");
    assert!(
        flow_cookie(&app).is_none(),
        "flow cookie cleared on completion"
    );

    // Signing in again (with the old session cookie present) rotates the session.
    let resp = submit_form(
        &app,
        &format!("/ui/login?request={REQUEST}"),
        &[("identifier", EMAIL), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(resp.status, 303);
    let (name2, second) = session_cookie(&app).expect("session cookie set");
    assert_eq!(name, name2);
    assert_ne!(first, second, "a new session cookie value is issued");
    let tenant = default_tenant(&app);
    let old = app
        .storage()
        .sessions()
        .get_active(
            tenant.id,
            &SecretHash(anvil_jose::encoding::secret_hash(&first)),
            app.clock().now(),
        )
        .await
        .expect("session lookup");
    assert!(old.is_none(), "the previous session is revoked");
}

#[tokio::test]
async fn login_without_request_shows_the_signed_in_page() {
    let app = app_with_user().await;
    let resp = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.signed_in".to_owned()]
    );
    assert!(session_cookie(&app).is_some());
}

#[tokio::test]
async fn wrong_password_rerenders_with_400_and_echoes_only_the_identifier() {
    let app = app_with_user().await;
    let resp = login(&app, "", EMAIL, "wrong password 123").await;
    assert_eq!(resp.status, 400);
    let html = resp.html();
    assert_eq!(
        message_keys(&html),
        vec!["login.invalid_credentials".to_owned()]
    );
    assert!(
        html.contains(&format!("value=\"{EMAIL}\"")),
        "identifier echoed"
    );
    assert!(
        !html.contains("wrong password 123"),
        "password never echoed"
    );
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn blocked_user_gets_the_same_response_as_a_wrong_password() {
    let app = app_with_user().await;
    let wrong = login(&app, "", EMAIL, "wrong password 123").await;
    app.clear_cookies();
    block_user(&app, default_tenant(&app).id, EMAIL).await;
    let blocked = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(blocked.status, wrong.status);
    assert_eq!(normalize(&blocked.html()), normalize(&wrong.html()));
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn expired_flow_restarts_with_flow_expired() {
    let app = app_with_user().await;
    let (action, csrf) = open_form(&app, "/ui/login").await;
    app.clock().advance(Duration::from_secs(16 * 60));
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    let html = resp.html();
    assert!(
        message_keys(&html).contains(&"flow.expired".to_owned()),
        "{html}"
    );
    assert!(
        session_cookie(&app).is_none(),
        "no sign-in on an expired flow"
    );
    // The restarted flow works.
    let next = form_action(&app, &html);
    assert_ne!(next, action);
    let resp = app
        .post_form(
            &next,
            &[
                ("csrf_token", &csrf_from(&html)),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
}

#[tokio::test]
async fn path_tenant_login_works() {
    let app = TestApp::new().await;
    create_tenant(&app, "acme").await;
    register(&app, "/t/acme", EMAIL, PASSWORD).await;
    let resp = app.get("/t/acme/ui/login").await;
    assert_eq!(resp.status, 200);
    let action = form_action(&app, &resp.html());
    assert!(action.starts_with("/t/acme/ui/login?flow="), "{action}");
    let resp = login(&app, "/t/acme", EMAIL, PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
    // The default tenant does not know this user.
    app.clear_cookies();
    assert_eq!(login(&app, "", EMAIL, PASSWORD).await.status, 400);
}

#[tokio::test]
async fn login_page_hides_the_registration_link_when_registration_is_disabled() {
    let app = TestApp::new().await;
    set_settings(
        &app,
        default_tenant(&app).id,
        TenantSettings {
            registration: RegistrationMode::Disabled,
            require_verified_email: false,
            ..TenantSettings::default()
        },
    )
    .await;
    let html = app.get("/ui/login").await.html();
    assert!(!html.contains("link-registration"), "{html}");
    assert!(html.contains("link-recovery"));
}

#[tokio::test]
async fn malformed_request_parameter_is_an_invalid_request_page() {
    let app = TestApp::new().await;
    let resp = app.get("/ui/login?request=not-a-uuid").await;
    assert_eq!(resp.status, 400);
    assert_eq!(error_key(&resp.html()).as_deref(), Some("invalid_request"));
}
