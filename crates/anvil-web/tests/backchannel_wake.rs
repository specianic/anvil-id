//! Back-channel logout wake (OIDC-12) on the selected backend (`ANVILID_TEST_DB`): every request
//! that revokes sessions wakes the delivery worker through `AppState::wake_logout_worker`, so its
//! back-channel logouts go out at once instead of at the next poll. Covered: RP-initiated
//! `/logout`, the `/ui/logout` confirmation, a password sign-in (every sign-in goes through
//! `signed_in_response`), the account sessions page (one session and all others), a password
//! change that signs out the other sessions, recovery completion, and the admin session and user
//! deletion routes. A read of the sessions page does not wake. End to end, a session switch in
//! one browser delivers the old user's logout token with a 1 h poll.

mod admin_support;
mod logout_support;
mod support;
mod token_support;
mod ui_helpers;

use std::sync::Arc;
use std::time::Duration;

use admin_support::{API, admin_token, call};
use anvil_core::model::{
    ApplicationType, ClientAuthMethod, ClientId, ClientType, ConsentMode, GrantType,
    NewAuthorizationCode, NewBrowserSession, NewClient, NewTokenFamily, SecretHash, SessionId,
    TokenFamilyId, TokenFormat, UserId,
};
use anvil_core::ports::Clock;
use anvil_jose::encoding::{random_token, secret_hash};
use anvil_web::adapters::backchannel::LogoutDeliveryWorker;
use anvil_web::adapters::outbound::{OutboundClient, OutboundPolicy};
use axum::http::Method;
use logout_support::{BYE, Fx, confirm_form, fixture};
use support::{TestApp, csrf_from};
use time::OffsetDateTime;
use ui_helpers::{
    default_tenant, link_of, login, session_cookie, submit_form, take_emails, to_path,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const PASSWORD: &str = "correct horse battery";
const NEW_PASSWORD: &str = "a whole new passphrase";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// Consumes a pending wake permit, if any, so the next check sees only the request under test.
async fn drain(app: &TestApp) {
    let wake = app.logout_wake();
    while tokio::time::timeout(Duration::from_millis(10), wake.notified())
        .await
        .is_ok()
    {}
}

/// Whether the app's wake holds a permit (the worker would run now).
async fn woke(app: &TestApp) -> bool {
    let wake = app.logout_wake();
    tokio::time::timeout(Duration::from_millis(100), wake.notified())
        .await
        .is_ok()
}

/// An app with `email` registered and signed in through the login page (session in the jar).
async fn signed_in(email: &str) -> TestApp {
    let app = TestApp::new().await;
    ui_helpers::register(&app, "", email, PASSWORD).await;
    let resp = login(&app, "", email, PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    take_emails(&app).await;
    app
}

async fn user_id(app: &TestApp, email: &str) -> UserId {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, email)
        .await
        .expect("lookup")
        .expect("user exists")
        .id
}

/// The jar's session.
async fn current_session(app: &TestApp) -> SessionId {
    let (_, token) = session_cookie(app).expect("session cookie");
    app.storage()
        .sessions()
        .get_active(
            default_tenant(app).id,
            &SecretHash(secret_hash(&token)),
            app.clock().now(),
        )
        .await
        .expect("session lookup")
        .expect("active session")
        .id
}

/// Another browser session of `user` (as if signed in on another device).
async fn other_session(app: &TestApp, user: UserId) -> SessionId {
    let now = app.clock().now();
    let id = SessionId::new_v7();
    app.storage()
        .sessions()
        .create(
            default_tenant(app).id,
            &NewBrowserSession {
                id,
                user_id: user,
                token_hash: SecretHash(secret_hash(&random_token())),
                auth_time: now,
                acr: "0".into(),
                amr: vec!["pwd".into()],
                created_at: now,
                expires_at: now + time::Duration::days(1),
                idle_expires_at: now + time::Duration::days(1),
                ip: None,
                user_agent: Some("Other device".into()),
            },
        )
        .await
        .expect("session");
    id
}

/// A client whose back-channel logout URI is `uri`, and an RP session of `session` for it (the
/// code is recorded through `GrantRepo::create_code`, as the authorization endpoint does).
async fn rp_session_for(app: &TestApp, user: UserId, session: SessionId, uri: &str) -> String {
    let tenant = default_tenant(app).id;
    let now = app.clock().now();
    let client = app
        .storage()
        .clients()
        .create(
            tenant,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: "bcl-app".into(),
                name: "BCL app".into(),
                client_type: ClientType::Confidential,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::ClientSecretBasic,
                secret_hash: Some(SecretHash(secret_hash("secret"))),
                jwks: None,
                redirect_uris: vec!["https://rp.test/cb".into()],
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec!["openid".into()],
                require_pkce: true,
                token_format: TokenFormat::Jwt,
                consent_mode: ConsentMode::Required,
                id_token_signed_response_alg: None,
                can_introspect: false,
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: Some(uri.into()),
                backchannel_logout_session_required: true,
                allowed_resources: vec![],
                mfa_policy: None,
                created_at: now,
                metadata_expires_at: None,
                registration_access_token_hash: None,
                registration_source: anvil_core::model::ClientSource::Static,
                organization: anvil_core::model::OrgClientPolicy::Off,
                require_pushed_authorization_requests: false,
                client_kind: anvil_core::model::ClientKind::Application,
                headless_native: false,
                client_uri: None,
                initiate_login_uri: None,
            },
        )
        .await
        .expect("client");
    let family = TokenFamilyId::new_v7();
    app.storage()
        .grants()
        .create_code(
            tenant,
            &NewAuthorizationCode {
                code_hash: SecretHash(secret_hash(&random_token())),
                client_id: client.client_id.clone(),
                user_id: user,
                session_id: session,
                redirect_uri: "https://rp.test/cb".into(),
                scope: "openid".into(),
                resource: vec![],
                nonce: None,
                code_challenge: None,
                auth_time: now,
                acr: "0".into(),
                amr: vec!["pwd".into()],
                token_family_id: family,
                issuer: app.issuer(None),
                expires_at: now + time::Duration::minutes(1),
                created_at: now,
                org_id: None,
            },
            &NewTokenFamily {
                id: family,
                client_id: client.client_id.clone(),
                user_id: Some(user),
                scope: "openid".into(),
                resource: vec![],
                auth_time: Some(now),
                acr: None,
                amr: vec![],
                session_id: Some(session),
                claims: None,
                created_at: now,
                absolute_expires_at: now + time::Duration::days(1),
                org_id: None,
            },
        )
        .await
        .expect("code");
    client.client_id
}

/// The `action` of the form with `id`, as a path.
fn action_of(app: &TestApp, html: &str, form_id: &str) -> String {
    let start = html
        .find(&format!("<form id=\"{form_id}\""))
        .unwrap_or_else(|| panic!("form #{form_id} in {html}"));
    let marker = "action=\"";
    let a = html[start..].find(marker).expect("action") + start + marker.len();
    let b = html[a..].find('"').expect("quoted") + a;
    to_path(app, &html[a..b].replace("&amp;", "&"))
}

/// Opens `page` and posts its form `form_id` with the page's CSRF token and `pairs`.
async fn submit_named(
    app: &TestApp,
    page: &str,
    form_id: &str,
    pairs: &[(&str, &str)],
) -> support::TestResponse {
    let resp = app.get(page).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    let action = action_of(app, &html, form_id);
    let csrf = csrf_from(&html);
    let mut all = vec![("csrf_token", csrf.as_str())];
    all.extend_from_slice(pairs);
    app.post_form(&action, &all).await
}

// ---------------------------------------------------------------------------------------------
// Wake per revocation path
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn rp_initiated_logout_wakes_the_worker() {
    let f = fixture().await;
    let id_token = f.id_token().await;
    drain(&f.app).await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", BYE),
        ]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(!f.session_active().await);
    assert!(woke(&f.app).await, "/logout wakes the worker");
}

#[tokio::test]
async fn ui_logout_confirmation_wakes_the_worker() {
    let f = fixture().await;
    assert_eq!(f.get("/logout").await.status, 303);
    let page = f.get("/ui/logout").await;
    assert_eq!(page.status, 200, "{}", page.text());
    let (action, csrf) = confirm_form(&f.app, &page);
    drain(&f.app).await;
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(!f.session_active().await);
    assert!(woke(&f.app).await, "/ui/logout wakes the worker");
}

#[tokio::test]
async fn every_sign_in_wakes_the_worker() {
    let app = TestApp::new().await;
    ui_helpers::register(&app, "", ALICE, PASSWORD).await;
    drain(&app).await;
    // Opening the login page is a read.
    assert_eq!(app.get("/ui/login").await.status, 200);
    assert!(!woke(&app).await, "the login page does not wake");
    let resp = login(&app, "", ALICE, PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(woke(&app).await, "a sign-in wakes the worker");
}

#[tokio::test]
async fn account_session_revocation_wakes_and_the_page_read_does_not() {
    let app = signed_in(ALICE).await;
    let alice = user_id(&app, ALICE).await;
    let other = other_session(&app, alice).await;
    drain(&app).await;

    let resp = app.get("/ui/account/sessions").await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(!woke(&app).await, "reading the sessions page does not wake");

    let resp = submit_named(
        &app,
        "/ui/account/sessions",
        &format!("session-revoke-{other}"),
        &[],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(woke(&app).await, "signing out one session wakes");

    other_session(&app, alice).await;
    other_session(&app, alice).await;
    drain(&app).await;
    // The first POST only asks for confirmation (07.1-21): no revocation, no wake.
    let resp = submit_named(&app, "/ui/account/sessions", "sessions-revoke-others", &[]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(!woke(&app).await, "the confirmation step does not wake");
    let resp = submit_named(
        &app,
        "/ui/account/sessions",
        "sessions-revoke-others",
        &[("confirm", "yes")],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(woke(&app).await, "signing out all others wakes");
}

#[tokio::test]
async fn password_change_signing_out_others_wakes_the_worker() {
    let app = signed_in(ALICE).await;
    let alice = user_id(&app, ALICE).await;
    let other = other_session(&app, alice).await;
    drain(&app).await;
    let resp = submit_named(
        &app,
        "/ui/account/password",
        "password-form",
        &[("new_password", NEW_PASSWORD), ("revoke_others", "on")],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let revoked = app
        .storage()
        .sessions()
        .get(default_tenant(&app).id, other)
        .await
        .expect("lookup")
        .expect("exists")
        .revoked_at;
    assert!(revoked.is_some(), "the other session is signed out");
    assert!(woke(&app).await, "the password change wakes");
}

#[tokio::test]
async fn recovery_completion_wakes_the_worker() {
    let app = signed_in(ALICE).await;
    app.clear_cookies();
    let resp = submit_form(&app, "/ui/recovery", &[("email", ALICE)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let link = link_of(&app, &take_emails(&app).await, "recovery");
    drain(&app).await;
    let resp = submit_form(&app, &link, &[("password", NEW_PASSWORD)]).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.text());
    assert!(woke(&app).await, "recovery completion wakes");
}

#[tokio::test]
async fn admin_session_and_user_deletion_wake_the_worker() {
    let app = signed_in(ALICE).await;
    let alice = user_id(&app, ALICE).await;
    let one = other_session(&app, alice).await;
    other_session(&app, alice).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    drain(&app).await;

    // A read does not wake.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/{alice}/sessions"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(!woke(&app).await, "listing sessions does not wake");

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/sessions/{one}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    assert!(woke(&app).await, "admin session revocation wakes");

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/users/{alice}/sessions"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(woke(&app).await, "admin revoke-all wakes");

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/users/{alice}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    assert!(woke(&app).await, "admin user deletion wakes");
}

// ---------------------------------------------------------------------------------------------
// End to end: a session switch delivers without waiting for the poll
// ---------------------------------------------------------------------------------------------

/// The app's test clock, shared with the worker (the app is leaked for the whole test).
struct AppClock(&'static TestApp);

impl Clock for AppClock {
    fn now(&self) -> OffsetDateTime {
        self.0.clock().now()
    }
}

#[tokio::test]
async fn session_switch_delivers_the_old_users_logout_without_waiting_for_the_poll() {
    let app: &'static TestApp = Box::leak(Box::new(TestApp::new().await));
    ui_helpers::register(app, "", ALICE, PASSWORD).await;
    ui_helpers::register(app, "", BOB, PASSWORD).await;
    take_emails(app).await;

    let rp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bc"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&rp)
        .await;

    // Alice signs in and to the back-channel client.
    assert_eq!(login(app, "", ALICE, PASSWORD).await.status, 200);
    let alice = user_id(app, ALICE).await;
    let alice_session = current_session(app).await;
    rp_session_for(app, alice, alice_session, &format!("{}/bc", rp.uri())).await;

    // The worker on the app's wake, with a poll that never fires during the test.
    let mut worker = LogoutDeliveryWorker::new(
        app.storage_arc(),
        Arc::new(AppClock(app)),
        app.kek_arc(),
        app.config.public_url.clone(),
        Arc::new(OutboundClient::new(&OutboundPolicy::loopback_dev()).expect("outbound client")),
        app.logout_wake(),
    );
    worker.poll = Duration::from_secs(3600);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(worker.run(async {
        let _ = stop_rx.await;
    }));
    // Let the first (empty) batch run so the worker is waiting on the wake.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob signs in in the same browser: Alice's session is switched away.
    let resp = login(app, "", BOB, PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_ne!(current_session(app).await, alice_session);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let requests = loop {
        let got = rp.received_requests().await.expect("recording on");
        if !got.is_empty() {
            break got;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the switch's back-channel logout was not delivered within 5 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(requests.len(), 1);
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&requests[0].body)
        .into_owned()
        .collect();
    assert_eq!(pairs.len(), 1, "{pairs:?}");
    assert_eq!(pairs[0].0, "logout_token");
    let payload = pairs[0].1.split('.').nth(1).expect("jwt payload");
    let claims: serde_json::Value =
        serde_json::from_slice(&anvil_jose::encoding::b64url_decode(payload).expect("b64"))
            .expect("json");
    assert_eq!(claims["sid"], alice_session.to_string(), "Alice's session");
    assert_eq!(claims["sub"], alice.to_string());

    stop_tx.send(()).expect("worker running");
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("worker stops on shutdown")
        .expect("worker task");
}
