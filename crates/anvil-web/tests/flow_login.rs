//! Login through the built-in page (AUTH-01, UI-01) on the selected backend (`ANVILID_TEST_DB`).

mod support;
mod token_support;
mod ui_helpers;

use std::time::Duration;

use anvil_core::model::{
    AuthRequestId, ClientAuthMethod, NewAuthorizationRequest, NewPasswordCredential, NewUser,
    RegistrationMode, SecretHash, TenantSettings, UserId, UserStatus,
};
use anvil_core::ports::Clock as _;
use support::{TestApp, csrf_from, location};
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

async fn app_with_user() -> TestApp {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
}

/// A live authorization request of the default tenant (stored through the port) for a new test
/// client: a `request=` on the sign-in page must name one (a stale id stops at the
/// `flow_expired` page, `flow_nav.rs`).
async fn live_request(app: &TestApp) -> String {
    let tenant = default_tenant(app).id;
    let rp = token_support::register(
        app,
        tenant,
        token_support::web_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let id = AuthRequestId(uuid::Uuid::now_v7());
    let now = app.clock().now();
    app.storage()
        .grants()
        .create_authorization_request(
            tenant,
            &NewAuthorizationRequest {
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
async fn login_form_has_the_stable_selectors() {
    let app = TestApp::new().await;
    let request = live_request(&app).await;
    let resp = app.get(&format!("/ui/login?request={request}")).await;
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
    let request = live_request(&app).await;
    let resp = submit_form(
        &app,
        &format!("/ui/login?request={request}"),
        &[("identifier", EMAIL), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        location(&resp),
        format!("{}/authorize/continue?request={request}", app.issuer(None))
    );
    let (name, first) = session_cookie(&app).expect("session cookie set");
    assert!(
        flow_cookie(&app).is_none(),
        "flow cookie cleared on completion"
    );

    // Signing in again (with the old session cookie present) rotates the session.
    let resp = submit_form(
        &app,
        &format!("/ui/login?request={request}"),
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

/// The `href` (or `action`) attribute `attr` of the element with `id`, decoded.
fn attr_of(html: &str, id: &str, attr: &str) -> Option<String> {
    let start = html.find(&format!("id=\"{id}\""))?;
    let tag_start = html[..start].rfind('<')?;
    let tag_end = html[start..].find('>')? + start;
    let tag = &html[tag_start..tag_end];
    let marker = format!("{attr}=\"");
    let at = tag.find(&marker)? + marker.len();
    let end = tag[at..].find('"')? + at;
    Some(tag[at..end].replace("&#x2f;", "/").replace("&amp;", "&"))
}

/// U-H2: the signed-in page stays a page (no redirect) but offers a way forward: the account
/// page and a sign-out form that posts to the end-session endpoint (which asks first; nothing
/// signs out on a GET). No console link outside the system tenant.
#[tokio::test]
async fn signed_in_page_offers_the_account_and_a_sign_out_form() {
    let app = app_with_user().await;
    let resp = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(resp.status, 200);
    let html = resp.html();
    assert!(message_keys(&html).contains(&"login.signed_in".to_owned()));
    let issuer = app.issuer(None);
    assert_eq!(
        attr_of(&html, "link-account", "href"),
        Some(format!("{issuer}/ui/account/profile"))
    );
    assert_eq!(
        attr_of(&html, "form-sign-out", "action"),
        Some(format!("{issuer}/logout"))
    );
    assert!(
        html.contains("method=\"post\" action=\"https://op.test/logout\""),
        "{html}"
    );
    assert!(!html.contains("id=\"link-console\""), "{html}");
    assert!(!html.contains("id=\"link-continue\""), "{html}");
    assert!(
        flow_cookie(&app).is_none(),
        "no flow is started for the sign-out form"
    );

    // The form asks for confirmation; the session survives the POST.
    let resp = app.post_form("/logout", &[]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).starts_with(&format!("{issuer}/ui/logout")),
        "{}",
        location(&resp)
    );
    assert!(
        session_cookie(&app).is_some(),
        "nothing signed out before confirming"
    );
}

/// In the system tenant the signed-in page also links the admin console on the installation's
/// public URL.
#[tokio::test]
async fn signed_in_page_in_the_system_tenant_links_the_console() {
    let app = TestApp::new().await;
    let system = system_tenant(&app);
    // System registration is closed: the admin is created through the port.
    let hasher = anvil_web::adapters::PasswordDispatcher::new(
        anvil_web::adapters::argon2::Argon2Pool::new(
            argon2::Params::new(256, 1, 1, None).expect("argon2 params"),
            1,
        )
        .expect("argon2 pool"),
    );
    let phc = anvil_core::ports::PasswordHasher::hash(&hasher, PASSWORD)
        .await
        .expect("hash");
    let now = app.clock().now();
    app.storage()
        .users()
        .create(
            system.id,
            &NewUser {
                id: UserId::new_v7(),
                email: "admin@example.com".into(),
                email_verified: true,
                username: None,
                claims: Default::default(),
                status: UserStatus::Active,
                created_at: now,
            },
            Some(&NewPasswordCredential {
                phc,
                created_at: now,
            }),
            None,
            None,
        )
        .await
        .expect("admin created");
    let resp = login(&app, "/t/system", "admin@example.com", PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(message_keys(&html).contains(&"login.signed_in".to_owned()));
    assert_eq!(
        attr_of(&html, "link-console", "href").as_deref(),
        Some("https://op.test/console/")
    );
    assert!(html.contains("id=\"link-account\""));
    assert!(html.contains("id=\"form-sign-out\""));
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
async fn malformed_request_parameter_is_the_flow_expired_page() {
    // Malformed, unknown, expired and foreign ids look the same (flow_nav.rs).
    let app = TestApp::new().await;
    let resp = app.get("/ui/login?request=not-a-uuid").await;
    assert_eq!(resp.status, 400);
    let html = resp.html();
    assert_eq!(error_key(&html).as_deref(), Some("flow_expired"));
    assert!(!html.contains("name=\"password\""), "{html}");
}
