//! Self-registration and email verification through the built-in pages (AUTH-02, UI-01) on the
//! selected backend (`ANVILID_TEST_DB`).

mod support;
mod token_support;
mod ui_helpers;

use anvil_core::model::{RegistrationMode, TenantSettings};
use support::{TestApp, location};
use ui_helpers::*;

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

#[tokio::test]
async fn open_registration_creates_the_user_signs_in_and_sends_a_verification_link() {
    let app = TestApp::new().await;
    let request = live_request(&app).await;
    let resp = submit_form(
        &app,
        &format!("/ui/registration?request={request}"),
        &[
            ("email", "  Bob@Example.COM "),
            ("password", PASSWORD),
            ("name", "Bob"),
        ],
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        location(&resp),
        format!("{}/authorize/continue?request={request}", app.issuer(None))
    );
    assert!(session_cookie(&app).is_some(), "registration signs in");

    let tenant = default_tenant(&app);
    let user = app
        .storage()
        .users()
        .get_by_email(tenant.id, "bob@example.com")
        .await
        .expect("lookup")
        .expect("user exists with the normalised email");
    assert!(!user.email_verified);
    assert_eq!(user.claims.name.as_deref(), Some("Bob"));

    let emails = take_emails(&app).await;
    let link = link_of(&app, &emails, "verification");
    assert!(link.starts_with("/ui/verification?token="), "{link}");
    assert_eq!(emails[0].to, "bob@example.com");

    // GET only shows the confirmation page; the token is not consumed.
    for _ in 0..2 {
        let page = app.get(&link).await;
        assert_eq!(page.status, 200);
        let html = page.html();
        assert!(html.contains("id=\"verification-submit\""), "{html}");
    }
    let user = app
        .storage()
        .users()
        .get(tenant.id, user.id)
        .await
        .expect("lookup")
        .expect("user");
    assert!(!user.email_verified, "GET does not verify");

    // POST confirms.
    let resp = submit_form(&app, &link, &[]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["verification.done".to_owned()]
    );
    let user = app
        .storage()
        .users()
        .get(tenant.id, user.id)
        .await
        .expect("lookup")
        .expect("user");
    assert!(user.email_verified, "POST verifies the email");

    // The token is single-use: the link says so on GET (07.1-07) ...
    let page = app.get(&link).await;
    assert_eq!(page.status, 400, "{}", page.text());
    assert!(message_keys(&page.html()).contains(&"links.expired".to_owned()));
    // ... and a POST of the used token is refused by the flow.
    let token = link
        .split("token=")
        .nth(1)
        .and_then(|t| t.split('&').next())
        .expect("token")
        .to_owned();
    let resp = submit_form(&app, "/ui/verification", &[("token", &token)]).await;
    assert_eq!(resp.status, 400);
    assert!(
        message_keys(&resp.html()).contains(&"verification.invalid_token".to_owned()),
        "{}",
        resp.html()
    );
}

#[tokio::test]
async fn disabled_registration_shows_the_disabled_page() {
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
    let resp = app.get("/ui/registration").await;
    assert_eq!(resp.status, 200);
    let html = resp.html();
    assert_eq!(
        message_keys(&html),
        vec!["registration.disabled".to_owned()]
    );
    assert!(!html.contains("registration-submit"), "no form");
    assert!(flow_cookie(&app).is_none(), "no flow is started");
}

#[tokio::test]
async fn system_tenant_registration_is_disabled() {
    let app = TestApp::new().await;
    // The harness installs system with default settings; production installs it Disabled.
    set_settings(
        &app,
        system_tenant(&app).id,
        TenantSettings {
            registration: RegistrationMode::Disabled,
            require_verified_email: false,
            ..TenantSettings::default()
        },
    )
    .await;
    let resp = app.get("/t/system/ui/registration").await;
    assert_eq!(
        message_keys(&resp.html()),
        vec!["registration.disabled".to_owned()]
    );
}

#[tokio::test]
async fn duplicate_email_is_registration_email_taken() {
    let app = TestApp::new().await;
    register(&app, "", "dave@example.com", PASSWORD).await;
    let resp = submit_form(
        &app,
        "/ui/registration",
        &[("email", "DAVE@example.com"), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(resp.status, 400);
    let html = resp.html();
    assert!(
        message_keys(&html).contains(&"registration.email_taken".to_owned()),
        "{html}"
    );
    assert!(!html.contains(PASSWORD), "password never echoed");
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn short_password_is_password_too_short() {
    let app = TestApp::new().await;
    let resp = submit_form(
        &app,
        "/ui/registration",
        &[("email", "erin@example.com"), ("password", "1234567")],
    )
    .await;
    assert_eq!(resp.status, 400);
    assert!(
        message_keys(&resp.html()).contains(&"password.too_short".to_owned()),
        "{}",
        resp.html()
    );
    let user = app
        .storage()
        .users()
        .get_by_email(default_tenant(&app).id, "erin@example.com")
        .await
        .expect("lookup");
    assert!(user.is_none(), "no user created");
}
