//! Account profile, email change and password change (AUTH-13) on the selected backend
//! (`ANVILID_TEST_DB`): pages, settings-flow binding (CSRF, flow cookie), re-authentication,
//! single-use POST confirmation of email changes, the notices, other-session revocation with
//! back-channel deliveries, and the refusals (policy, breach, taken address, tampered link).

mod support;
mod ui_helpers;

use std::sync::Arc;
use std::time::Duration;

use anvil_core::error::CoreError;
use anvil_core::model::{
    ApplicationType, AuditAction, AuditEvent, AuditOutcome, AuditQuery, BrowserSession,
    ClientAuthMethod, ClientId, ClientType, ConsentMode, GrantType, NewAuthorizationCode,
    NewBrowserSession, NewClient, NewTokenFamily, NewUser, RequestContext, SecretHash, SessionId,
    StandardClaims, TokenFamilyId, TokenFormat, UserId, UserStatus,
};
use anvil_core::policy::PasswordPolicy;
use anvil_core::ports::{
    BreachChecker, Clock as _, PasskeyCeremonies, PasskeyError, PasswordHasher, RelyingParty,
};
use anvil_core::service::account::{
    AccountError, AccountFailure, AccountService, PasswordDeps, SettingsBinding, StartedSettings,
};
use anvil_jose::encoding::{random_token, secret_hash};
use axum::body::Body;
use axum::http::{Method, Request, header};
use secrecy::{ExposeSecret as _, SecretString};
use support::{TestApp, TestResponse, csrf_from, location};
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const NEW_EMAIL: &str = "alice.new@example.com";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// An app with a registered user who is signed in (session cookie in the jar). The registration
/// emails are drained.
async fn signed_in() -> TestApp {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, PASSWORD).await;
    let resp = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
    take_emails(&app).await;
    app
}

async fn user_by_email(app: &TestApp, email: &str) -> Option<anvil_core::model::User> {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, email)
        .await
        .expect("lookup")
}

async fn user_id(app: &TestApp, email: &str) -> UserId {
    user_by_email(app, email).await.expect("user exists").id
}

async fn current_session(app: &TestApp) -> BrowserSession {
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

/// Opens `page` and returns (form action, CSRF token).
async fn open(app: &TestApp, page: &str, form_id: &str) -> (String, String) {
    let resp = app.get(page).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    (action_of(app, &html, form_id), csrf_from(&html))
}

async fn audit_events(app: &TestApp) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

async fn events_of(app: &TestApp, action: AuditAction) -> Vec<AuditEvent> {
    audit_events(app)
        .await
        .into_iter()
        .filter(|e| e.action == action)
        .collect()
}

fn assert_message(resp: &TestResponse, status: u16, key: &str) {
    assert_eq!(resp.status, status, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec![key.to_owned()]);
}

async fn password_phc(app: &TestApp, user: UserId) -> Option<String> {
    app.storage()
        .users()
        .password(default_tenant(app).id, user)
        .await
        .expect("password lookup")
        .map(|p| p.phc)
}

/// The hidden `token` of the confirmation form.
fn hidden_token(html: &str) -> String {
    hidden_inputs(html)
        .into_iter()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v)
        .expect("token field")
}

/// Requests an email change to `new_email` through the page and returns the confirmation link
/// path from the email.
async fn request_change(app: &TestApp, new_email: &str) -> String {
    let (action, csrf) = open(app, "/ui/account/email", "email-change").await;
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("new_email", new_email)])
        .await;
    assert_message(&resp, 200, "account.email_change_sent");
    let emails = take_emails(app).await;
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert_eq!(emails[0].to, new_email);
    link_of(app, &emails, "email_change")
}

// ---------------------------------------------------------------------------------------------
// Access, navigation, binding
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn without_a_session_the_pages_send_the_user_to_sign_in() {
    let app = TestApp::new().await;
    for page in [
        "/ui/account/profile",
        "/ui/account/email",
        "/ui/account/password",
    ] {
        let resp = app.get(page).await;
        assert_eq!(resp.status, 303, "{page}");
        assert_eq!(location(&resp), format!("{}/ui/login", app.issuer(None)));
        let resp = app.post_form(page, &[("csrf_token", "x")]).await;
        assert_eq!(resp.status, 303, "{page}");
    }
}

#[tokio::test]
async fn account_navigation_lists_every_section_and_marks_the_current_one() {
    let app = signed_in().await;
    for (page, current) in [
        ("/ui/account/profile", "profile"),
        ("/ui/account/email", "email"),
        ("/ui/account/password", "password"),
        ("/ui/account/security", "security"),
        ("/ui/account/sessions", "sessions"),
        ("/ui/account/apps", "apps"),
    ] {
        let resp = app.get(page).await;
        assert_eq!(resp.status, 200, "{page}: {}", resp.text());
        let html = resp.html().replace("&#x2f;", "/");
        for section in [
            "profile", "email", "password", "security", "sessions", "apps",
        ] {
            assert!(
                html.contains(&format!("id=\"account-nav-{section}\"")),
                "{page}: nav {section}"
            );
        }
        assert_eq!(html.matches("aria-current=\"page\"").count(), 1, "{page}");
        assert!(
            html.contains(&format!(
                "id=\"account-nav-{current}\" href=\"/ui/account/{current}\" aria-current=\"page\""
            )),
            "{page}"
        );
    }
    // The new pages are script-free and not cached.
    for page in [
        "/ui/account/profile",
        "/ui/account/email",
        "/ui/account/password",
    ] {
        let resp = app.get(page).await;
        assert_eq!(resp.header("cache-control"), Some("no-store"), "{page}");
        assert!(!resp.html().contains("<script"), "{page}");
        let csp = resp.header("content-security-policy").expect("csp");
        assert!(!csp.contains("script-src 'self'"), "{page}: {csp}");
    }
}

#[tokio::test]
async fn posts_without_csrf_wrong_token_or_flow_cookie_are_forbidden_and_change_nothing() {
    let app = signed_in().await;
    let user = user_id(&app, EMAIL).await;
    let phc = password_phc(&app, user).await;
    for (page, form, field, value) in [
        ("/ui/account/profile", "profile-form", "name", "Mallory"),
        ("/ui/account/email", "email-change", "new_email", NEW_EMAIL),
        (
            "/ui/account/password",
            "password-form",
            "new_password",
            "a whole new passphrase",
        ),
    ] {
        let (action, csrf) = open(&app, page, form).await;
        for pairs in [
            vec![(field, value)],
            vec![("csrf_token", "wrong"), (field, value)],
        ] {
            let resp = app.post_form(&action, &pairs).await;
            assert_eq!(resp.status, 403, "{page} {pairs:?}");
            assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
        }
        // Missing flow parameter.
        let resp = app
            .post_form(page, &[("csrf_token", &csrf), (field, value)])
            .await;
        assert_eq!(resp.status, 403, "{page}");

        // Without the flow cookie (another browser) the token alone is not enough.
        let mut jar = app.cookies();
        jar.retain(|k, _| !k.contains("anvil_flow_"));
        let cookie = jar
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        let body = format!("csrf_token={csrf}&{field}={}", urlencode(value));
        let resp = app
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri(&action)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, cookie)
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await;
        assert_eq!(resp.status, 403, "{page}");
    }
    let user_after = user_by_email(&app, EMAIL).await.expect("user");
    assert_eq!(user_after.claims.name, None);
    assert_eq!(password_phc(&app, user).await, phc);
    assert!(take_emails(&app).await.is_empty());
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ---------------------------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn profile_update_persists_is_audited_and_feeds_the_page_language() {
    let app = signed_in().await;
    let (action, csrf) = open(&app, "/ui/account/profile", "profile-form").await;
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("name", "  Ada Lovelace "),
                ("given_name", "Ada"),
                ("family_name", "Lovelace"),
                ("locale", "en-GB"),
            ],
        )
        .await;
    assert_message(&resp, 200, "account.profile_saved");
    let html = resp.html();
    assert!(html.contains("value=\"Ada Lovelace\""), "{html}");
    assert!(html.contains("<html lang=\"en-GB\"") || html.contains("<html lang=\"en\""));

    let user = user_by_email(&app, EMAIL).await.expect("user");
    assert_eq!(user.claims.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(user.claims.given_name.as_deref(), Some("Ada"));
    assert_eq!(user.claims.family_name.as_deref(), Some("Lovelace"));
    assert_eq!(user.claims.locale.as_deref(), Some("en-GB"));

    let events = events_of(&app, AuditAction::ProfileUpdated).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, AuditOutcome::Success);
    assert_eq!(
        events[0].target.as_deref(),
        Some(user.id.to_string().as_str())
    );
    let details = serde_json::to_string(events[0].details.as_map()).expect("json");
    for f in ["name", "given_name", "family_name", "locale"] {
        assert!(details.contains(&format!("\"{f}\"")), "{details}");
    }

    // Saving the same values again changes nothing and is not audited; clearing a field is.
    let same = [
        ("csrf_token", csrf.as_str()),
        ("name", "Ada Lovelace"),
        ("given_name", "Ada"),
        ("family_name", "Lovelace"),
        ("locale", "en-GB"),
    ];
    let resp = app.post_form(&action, &same).await;
    assert_message(&resp, 200, "account.profile_saved");
    assert_eq!(events_of(&app, AuditAction::ProfileUpdated).await.len(), 1);
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("name", "Ada Lovelace"),
                ("given_name", "Ada"),
                ("family_name", "Lovelace"),
                ("locale", ""),
            ],
        )
        .await;
    assert_message(&resp, 200, "account.profile_saved");
    assert_eq!(
        user_by_email(&app, EMAIL).await.unwrap().claims.locale,
        None
    );
    assert_eq!(events_of(&app, AuditAction::ProfileUpdated).await.len(), 2);
}

#[tokio::test]
async fn invalid_profile_input_is_rejected_and_kept_in_the_form() {
    let app = signed_in().await;
    let (action, csrf) = open(&app, "/ui/account/profile", "profile-form").await;
    let long = "x".repeat(201);
    for (field, value, key) in [
        ("locale", "en_US", "account.invalid_locale"),
        ("locale", "english", "account.invalid_locale"),
        ("locale", "en-<b>", "account.invalid_locale"),
        ("name", long.as_str(), "account.invalid_name"),
        ("given_name", "line\nbreak", "account.invalid_name"),
    ] {
        let resp = app
            .post_form(&action, &[("csrf_token", &csrf), (field, value)])
            .await;
        assert_message(&resp, 400, key);
        if field == "locale" && value == "en_US" {
            assert!(resp.html().contains("value=\"en_US\""));
        }
    }
    let user = user_by_email(&app, EMAIL).await.expect("user");
    assert_eq!(user.claims, StandardClaims::default());
    assert!(
        events_of(&app, AuditAction::ProfileUpdated)
            .await
            .is_empty()
    );
}

// ---------------------------------------------------------------------------------------------
// Email change
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn email_change_needs_a_recent_sign_in() {
    let app = signed_in().await;
    // Open the page 10 minutes after sign-in, submit 16 minutes after it.
    app.clock().advance(Duration::from_secs(10 * 60));
    let resp = app.get("/ui/account/email").await;
    let html = resp.html();
    assert!(!html.contains("id=\"account-reauth\""));
    let (action, csrf) = (action_of(&app, &html, "email-change"), csrf_from(&html));
    app.clock().advance(Duration::from_secs(6 * 60));
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("new_email", NEW_EMAIL)])
        .await;
    assert_message(&resp, 400, "account.reauth_required");
    let html = resp.html();
    assert!(html.contains("id=\"account-reauth\""));
    assert!(html.contains("id=\"link-reauth\""));
    assert!(take_emails(&app).await.is_empty());
    assert!(
        events_of(&app, AuditAction::EmailChangeRequested)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn email_change_is_confirmed_by_post_only_switches_and_notifies_the_old_address() {
    let app = signed_in().await;
    let user = user_id(&app, EMAIL).await;
    let (action, csrf) = open(&app, "/ui/account/email", "email-change").await;
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("new_email", " Alice.New@Example.com "),
            ],
        )
        .await;
    assert_message(&resp, 200, "account.email_change_sent");

    // Exactly one outbox row, to the new address, with a sealed payload.
    let raw = app
        .storage()
        .outbox()
        .claim_due(
            app.clock().now() + time::Duration::seconds(1),
            100,
            Duration::from_secs(1),
        )
        .await
        .expect("claim");
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0].to, NEW_EMAIL);
    assert_eq!(raw[0].template, "email_change");
    assert_eq!(
        raw[0].payload.keys().collect::<Vec<_>>(),
        vec!["sealed"],
        "payload is sealed"
    );
    assert!(!raw[0].payload["sealed"].contains(NEW_EMAIL));
    // The lease is short: claim again (opened) after it ends.
    app.clock().advance(Duration::from_secs(2));
    let emails = take_emails(&app).await;
    assert_eq!(emails.len(), 1);
    let payload = &emails[0].payload;
    let keys: Vec<&str> = payload.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        vec!["expires_minutes", "link", "new_email", "tenant_name"]
    );
    assert_eq!(payload["new_email"], NEW_EMAIL);
    assert_eq!(payload["expires_minutes"], "1440");
    let link = link_of(&app, &emails, "email_change");
    assert!(
        link.starts_with("/ui/account/email/confirm?token="),
        "{link}"
    );

    // GET only shows the button and consumes nothing.
    for _ in 0..2 {
        let resp = app.get(&link).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        assert!(resp.html().contains("id=\"email-confirm\""));
    }
    let token = hidden_token(&app.get(&link).await.html());
    assert_eq!(
        user_by_email(&app, EMAIL).await.expect("unchanged").id,
        user
    );
    assert!(take_emails(&app).await.is_empty());

    // POST confirms.
    let resp = app
        .post_form("/ui/account/email/confirm", &[("token", &token)])
        .await;
    assert_message(&resp, 200, "account.email_changed");
    assert!(user_by_email(&app, EMAIL).await.is_none());
    let changed = user_by_email(&app, NEW_EMAIL).await.expect("switched");
    assert_eq!(changed.id, user);
    assert!(changed.email_verified);
    let emails = take_emails(&app).await;
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert_eq!(emails[0].to, EMAIL, "the notice goes to the old address");
    assert_eq!(emails[0].template, "email_changed");
    assert_eq!(emails[0].payload["new_email"], NEW_EMAIL);
    assert_eq!(
        emails[0].payload["tenant_name"],
        default_tenant(&app).display_name
    );

    // A second POST: the link is used up.
    let resp = app
        .post_form("/ui/account/email/confirm", &[("token", &token)])
        .await;
    assert_message(&resp, 400, "account.email_token_invalid");
    assert!(take_emails(&app).await.is_empty());

    assert_eq!(
        events_of(&app, AuditAction::EmailChangeRequested)
            .await
            .len(),
        1
    );
    let changed_events = events_of(&app, AuditAction::EmailChanged).await;
    assert_eq!(changed_events.len(), 1);
    assert_eq!(
        changed_events[0].target.as_deref(),
        Some(user.to_string().as_str())
    );
}

#[tokio::test]
async fn unchanged_malformed_and_taken_addresses() {
    let app = signed_in().await;
    let (action, csrf) = open(&app, "/ui/account/email", "email-change").await;
    for (value, key) in [
        ("ALICE@example.com", "account.email_unchanged"),
        ("not-an-address", "account.invalid_email"),
        ("", "account.invalid_email"),
    ] {
        let resp = app
            .post_form(&action, &[("csrf_token", &csrf), ("new_email", value)])
            .await;
        assert_message(&resp, 400, key);
    }

    // Another account's address: the same answer as success, but nothing is sent.
    app.clear_cookies();
    register(&app, "", "bob@example.com", PASSWORD).await;
    take_emails(&app).await;
    app.clear_cookies();
    login(&app, "", EMAIL, PASSWORD).await;
    let (action, csrf) = open(&app, "/ui/account/email", "email-change").await;
    let resp = app
        .post_form(
            &action,
            &[("csrf_token", &csrf), ("new_email", "bob@example.com")],
        )
        .await;
    assert_message(&resp, 200, "account.email_change_sent");
    assert!(take_emails(&app).await.is_empty());
    let events = events_of(&app, AuditAction::EmailChangeRequested).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, AuditOutcome::Failure);
}

#[tokio::test]
async fn address_taken_at_confirmation_keeps_the_token_until_it_is_free() {
    let app = signed_in().await;
    let link = request_change(&app, "carol@example.com").await;
    let token = hidden_token(&app.get(&link).await.html());

    // Someone registers the address in the meantime.
    let tenant = default_tenant(&app);
    let carol = app
        .storage()
        .users()
        .create(
            tenant.id,
            &NewUser {
                id: UserId::new_v7(),
                email: "carol@example.com".into(),
                email_verified: false,
                username: None,
                claims: StandardClaims::default(),
                status: UserStatus::Active,
                created_at: app.clock().now(),
            },
            None,
            None,
            None,
        )
        .await
        .expect("carol");
    let resp = app
        .post_form("/ui/account/email/confirm", &[("token", &token)])
        .await;
    assert_message(&resp, 409, "account.email_taken");
    assert_eq!(
        hidden_token(&resp.html()),
        token,
        "the button is offered again"
    );
    assert!(user_by_email(&app, EMAIL).await.is_some(), "unchanged");
    assert!(take_emails(&app).await.is_empty());

    // Once the address is free again the same link works.
    assert!(
        app.storage()
            .users()
            .delete(tenant.id, carol.id)
            .await
            .expect("delete")
    );
    let resp = app
        .post_form("/ui/account/email/confirm", &[("token", &token)])
        .await;
    assert_message(&resp, 200, "account.email_changed");
    assert!(user_by_email(&app, "carol@example.com").await.is_some());
}

#[tokio::test]
async fn tampered_expired_or_missing_links_are_rejected() {
    let app = signed_in().await;
    let link = request_change(&app, NEW_EMAIL).await;
    let token = hidden_token(&app.get(&link).await.html());
    let (random, sealed) = token.split_once('.').expect("two parts");

    let mut flipped = sealed.to_owned();
    let last = flipped.pop().expect("non-empty");
    flipped.push(if last == 'A' { 'B' } else { 'A' });
    let other = random_token();
    for bad in [
        String::new(),
        random.to_owned(),
        format!("{random}."),
        format!("{random}.{flipped}"),
        // The sealed address is bound to its token.
        format!("{other}.{sealed}"),
        format!("{random}.{sealed}x"),
    ] {
        let resp = app
            .post_form("/ui/account/email/confirm", &[("token", &bad)])
            .await;
        assert_message(&resp, 400, "account.email_token_invalid");
    }
    let resp = app.get("/ui/account/email/confirm").await;
    assert_message(&resp, 400, "account.email_token_invalid");
    assert!(user_by_email(&app, EMAIL).await.is_some());

    // After 24 hours the link has expired.
    app.clock().advance(Duration::from_secs(24 * 3600 + 1));
    let resp = app
        .post_form("/ui/account/email/confirm", &[("token", &token)])
        .await;
    assert_message(&resp, 400, "account.email_token_invalid");
    assert!(user_by_email(&app, EMAIL).await.is_some());
}

// ---------------------------------------------------------------------------------------------
// Password
// ---------------------------------------------------------------------------------------------

/// Stores another active session of `user` (another device) and returns its id.
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

/// A client with a back-channel logout URI and an RP session of `session` for it.
async fn rp_session_for(app: &TestApp, user: UserId, session: SessionId) -> String {
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
                backchannel_logout_uri: Some("https://rp.test/bcl".into()),
                backchannel_logout_session_required: true,
                allowed_resources: vec![],
                mfa_policy: None,
                created_at: now,
                metadata_expires_at: None,
                registration_access_token_hash: None,
                registration_source: anvil_core::model::ClientSource::Static,
                organization: anvil_core::model::OrgClientPolicy::Off,
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
                issuer: "https://op.test".into(),
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

async fn is_active(app: &TestApp, session: SessionId) -> bool {
    app.storage()
        .sessions()
        .list_for_user(
            default_tenant(app).id,
            user_id(app, EMAIL).await,
            app.clock().now(),
        )
        .await
        .expect("sessions")
        .iter()
        .any(|s| s.id == session)
}

#[tokio::test]
async fn password_policy_violations_are_refused_and_change_nothing() {
    let app = signed_in().await;
    let user = user_id(&app, EMAIL).await;
    let phc = password_phc(&app, user).await;
    let (action, csrf) = open(&app, "/ui/account/password", "password-form").await;
    let long = "a".repeat(1025);
    for (value, key) in [
        ("short", "account.password_too_short"),
        ("", "account.password_too_short"),
        (long.as_str(), "account.password_too_long"),
    ] {
        let resp = app
            .post_form(&action, &[("csrf_token", &csrf), ("new_password", value)])
            .await;
        assert_message(&resp, 400, key);
    }
    assert_eq!(password_phc(&app, user).await, phc);
    assert!(take_emails(&app).await.is_empty());
    assert!(
        events_of(&app, AuditAction::PasswordChanged)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn password_change_needs_a_recent_sign_in() {
    let app = signed_in().await;
    let user = user_id(&app, EMAIL).await;
    let phc = password_phc(&app, user).await;
    app.clock().advance(Duration::from_secs(10 * 60));
    let (action, csrf) = open(&app, "/ui/account/password", "password-form").await;
    app.clock().advance(Duration::from_secs(6 * 60));
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("new_password", "a whole new passphrase"),
            ],
        )
        .await;
    assert_message(&resp, 400, "account.reauth_required");
    assert_eq!(password_phc(&app, user).await, phc);
}

#[tokio::test]
async fn password_change_revokes_other_sessions_with_deliveries_and_keeps_this_one() {
    let app = signed_in().await;
    let user = user_id(&app, EMAIL).await;
    let current = current_session(&app).await.id;
    let other = other_session(&app, user).await;
    let client_id = rp_session_for(&app, user, other).await;
    let phc = password_phc(&app, user).await;

    let resp = app.get("/ui/account/password").await;
    let html = resp.html();
    assert!(
        html.contains("checked"),
        "signing out others is the default"
    );
    let (action, csrf) = (action_of(&app, &html, "password-form"), csrf_from(&html));
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("new_password", "a whole new passphrase"),
                ("revoke_others", "on"),
            ],
        )
        .await;
    assert_message(&resp, 200, "account.password_changed");
    assert_ne!(password_phc(&app, user).await, phc);
    assert!(is_active(&app, current).await, "this session stays");
    assert!(
        !is_active(&app, other).await,
        "the other device is signed out"
    );
    let deliveries = app
        .storage()
        .logout()
        .deliveries_for_client(default_tenant(&app).id, &client_id)
        .await
        .expect("deliveries");
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].sid, other.to_string());
    assert_eq!(deliveries[0].sub, user.to_string());

    let emails = take_emails(&app).await;
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert_eq!(emails[0].to, EMAIL);
    assert_eq!(emails[0].template, "password_changed");
    let events = events_of(&app, AuditAction::PasswordChanged).await;
    assert_eq!(events.len(), 1);
    let details = serde_json::to_string(events[0].details.as_map()).expect("json");
    assert!(details.contains("account_change"), "{details}");

    // The new password signs in.
    app.clear_cookies();
    let resp = login(&app, "", EMAIL, "a whole new passphrase").await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
}

#[tokio::test]
async fn password_change_without_revoking_keeps_other_sessions() {
    let app = signed_in().await;
    let user = user_id(&app, EMAIL).await;
    let other = other_session(&app, user).await;
    let (action, csrf) = open(&app, "/ui/account/password", "password-form").await;
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("new_password", "a whole new passphrase"),
            ],
        )
        .await;
    assert_message(&resp, 200, "account.password_changed");
    assert!(is_active(&app, other).await);
    assert!(!resp.html().contains("checked"), "the choice is kept");
}

// ---------------------------------------------------------------------------------------------
// Service level: breach check and users without a password
// ---------------------------------------------------------------------------------------------

/// Breach corpus double: every password containing "breached" is in it.
struct FakeBreach;

#[async_trait::async_trait]
impl BreachChecker for FakeBreach {
    async fn is_breached(&self, password: &str) -> Result<bool, CoreError> {
        Ok(password.contains("breached"))
    }
}

/// Hasher double: a recognisable PHC-shaped string (no Argon2 in this service-level test).
struct FakeHasher;

#[async_trait::async_trait]
impl PasswordHasher for FakeHasher {
    async fn hash(&self, password: &str) -> Result<String, CoreError> {
        Ok(format!("$fake${}", password.len()))
    }

    async fn verify(
        &self,
        _phc: Option<&str>,
        _password: &str,
    ) -> Result<anvil_core::ports::PasswordCheck, CoreError> {
        Err(CoreError::Internal("not used".into()))
    }
}

/// Passkey ceremonies are not used by these tests.
struct NoPasskeys;

impl PasskeyCeremonies for NoPasskeys {
    fn start_registration(
        &self,
        _: &RelyingParty,
        _: &anvil_core::ports::PasskeyUser,
        _: &[Vec<u8>],
    ) -> Result<anvil_core::ports::Challenge, CoreError> {
        Err(CoreError::Internal("not used".into()))
    }

    fn finish_registration(
        &self,
        _: &RelyingParty,
        _: &str,
        _: &str,
    ) -> Result<anvil_core::ports::RegisteredPasskey, PasskeyError> {
        Err(PasskeyError::Invalid)
    }

    fn start_discoverable(
        &self,
        _: &RelyingParty,
    ) -> Result<anvil_core::ports::Challenge, CoreError> {
        Err(CoreError::Internal("not used".into()))
    }

    fn identify(&self, _: &str) -> Result<anvil_core::ports::AssertionIdentity, PasskeyError> {
        Err(PasskeyError::Invalid)
    }

    fn finish_discoverable(
        &self,
        _: &RelyingParty,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<anvil_core::ports::VerifiedAssertion, PasskeyError> {
        Err(PasskeyError::Invalid)
    }
}

struct FixedClock(time::OffsetDateTime);

impl anvil_core::ports::Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

fn binding(s: &StartedSettings) -> SettingsBinding<'_> {
    SettingsBinding {
        flow_id: s.flow_id,
        cookie_token: Some(s.cookie_token.expose_secret()),
        csrf_token: s.csrf_token.expose_secret(),
    }
}

/// A social-only user (no password row) with a fresh session, and the service.
async fn passwordless_fixture() -> (TestApp, AccountService, BrowserSession) {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let user = app
        .storage()
        .users()
        .create(
            tenant.id,
            &NewUser {
                id: UserId::new_v7(),
                email: "social@example.com".into(),
                email_verified: true,
                username: None,
                claims: StandardClaims::default(),
                status: UserStatus::Active,
                created_at: app.clock().now(),
            },
            None,
            None,
            None,
        )
        .await
        .expect("user");
    let token = random_token();
    let now = app.clock().now();
    app.storage()
        .sessions()
        .create(
            tenant.id,
            &NewBrowserSession {
                id: SessionId::new_v7(),
                user_id: user.id,
                token_hash: SecretHash(secret_hash(&token)),
                auth_time: now,
                acr: "0".into(),
                amr: vec!["fed".into()],
                created_at: now,
                expires_at: now + time::Duration::days(1),
                idle_expires_at: now + time::Duration::days(1),
                ip: None,
                user_agent: None,
            },
        )
        .await
        .expect("session");
    let session = app
        .storage()
        .sessions()
        .get_active(tenant.id, &SecretHash(secret_hash(&token)), now)
        .await
        .expect("lookup")
        .expect("active");
    let service = AccountService {
        storage: app.storage_arc(),
        clock: Arc::new(FixedClock(now)),
        kek: app.kek_arc(),
        passkeys: Arc::new(NoPasskeys),
    };
    (app, service, session)
}

#[tokio::test]
async fn breached_password_is_refused_and_a_social_only_user_can_set_one() {
    let (app, service, session) = passwordless_fixture().await;
    let tenant = default_tenant(&app);
    let deps = PasswordDeps {
        hasher: &FakeHasher,
        breach: &FakeBreach,
        policy: PasswordPolicy::default(),
    };
    let ctx = RequestContext::system();
    let started = service.start(tenant.id, &session).await.expect("flow");
    assert!(
        !service
            .profile(tenant.id, &session)
            .await
            .expect("profile")
            .has_password
    );

    let r = service
        .change_password(
            &tenant,
            &session,
            &binding(&started),
            &SecretString::from("this one was breached".to_owned()),
            true,
            &deps,
            &ctx,
        )
        .await;
    assert!(
        matches!(
            r,
            Err(AccountError::Failure(AccountFailure::PasswordBreached))
        ),
        "{r:?}"
    );
    assert_eq!(password_phc(&app, session.user_id).await, None);

    let revoked = service
        .change_password(
            &tenant,
            &session,
            &binding(&started),
            &SecretString::from("a fresh first passphrase".to_owned()),
            true,
            &deps,
            &ctx,
        )
        .await
        .expect("set");
    assert_eq!(revoked, 0);
    assert_eq!(
        password_phc(&app, session.user_id).await.as_deref(),
        Some("$fake$24")
    );
    assert!(
        service
            .profile(tenant.id, &session)
            .await
            .expect("profile")
            .has_password
    );
    let events = events_of(&app, AuditAction::PasswordChanged).await;
    assert_eq!(events.len(), 1);
    let details = serde_json::to_string(events[0].details.as_map()).expect("json");
    assert!(details.contains("account_set"), "{details}");

    // A wrong binding is forbidden and changes nothing.
    let wrong = SettingsBinding {
        flow_id: started.flow_id,
        cookie_token: Some("not-the-cookie"),
        csrf_token: started.csrf_token.expose_secret(),
    };
    let r = service
        .change_password(
            &tenant,
            &session,
            &wrong,
            &SecretString::from("another passphrase here".to_owned()),
            false,
            &deps,
            &ctx,
        )
        .await;
    assert!(
        matches!(r, Err(AccountError::Core(CoreError::Forbidden))),
        "{r:?}"
    );
    assert_eq!(
        password_phc(&app, session.user_id).await.as_deref(),
        Some("$fake$24")
    );
}
