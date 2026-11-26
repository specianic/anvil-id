//! Organization invitation acceptance (ORG-02, plan 06-20): the `org_invitation` email through
//! the outbox worker, the GET page that consumes nothing, acceptance bound to the signed-in user's
//! verified email (single use under concurrency), the wrong-account and unverified cases keeping
//! the token, registration through an invitation (open, invite_only, disabled, existing address),
//! one page for every invalid token, and the CSRF binding of the forms. Plan 06-31: the sign-in
//! link returns to the invitation (password, second factor, upstream; the allowlist and the
//! sealed target refuse everything else), and registering through an invitation signs in.

mod admin_support;
mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use admin_support::{API, admin_token, call, create_org, create_role};
use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditAction, AuditActor, AuditQuery, BrowserSession, CredentialId, FlowId, NewOrgInvitation,
    NewTotp, OrgId, OrgInvitationId, Organization, RegistrationMode, RequestContext, RoleId,
    SecretHash, TOTP_SEED_PURPOSE, Tenant, TenantSettings, UserId, UserUpdate, credential_aad,
};
use anvil_core::ports::{BreachChecker, Clock as _};
use anvil_core::service::account::new_recovery_codes;
use anvil_core::service::org_invitation::{
    OrgInvitationService, RegisterOutcome, RegistrationChecks,
};
use anvil_jose::encoding::{random_token, secret_hash};
use anvil_jose::otp::TotpSecret;
use anvil_mail::worker::TransportFactory;
use anvil_mail::{
    EmailRenderer, MailError, MailTransport, OutboxWorker, OutgoingMail, StorageOutbox,
};
use aws_lc_rs::hmac;
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::json;
use support::{TestApp, TestResponse, csrf_from, location};
use time::Duration;
use ui_helpers::{default_tenant, message_keys, register, set_settings};
use upstream_support::MOCK_SUBJECT;

const PASSWORD: &str = "correct horse battery staple";
const INVITED: &str = "invitee@example.test";
const OTHER: &str = "someone.else@example.test";

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.enabled = false).await
}

/// An open invitation created through storage with a known token.
struct Invitation {
    id: OrgInvitationId,
    token: String,
}

async fn invite(
    app: &TestApp,
    tenant: &Tenant,
    org: &Organization,
    email: &str,
    roles: &[RoleId],
) -> Invitation {
    invite_at(app, tenant, org.id, email, roles, app.clock().now()).await
}

async fn invite_at(
    app: &TestApp,
    tenant: &Tenant,
    org: OrgId,
    email: &str,
    roles: &[RoleId],
    created_at: time::OffsetDateTime,
) -> Invitation {
    let token = random_token();
    let inv = app
        .storage()
        .organizations()
        .create_invitation(
            tenant.id,
            &NewOrgInvitation {
                id: OrgInvitationId::new_v7(),
                org_id: org,
                email: email.to_owned(),
                role_ids: roles.to_vec(),
                token_hash: SecretHash(secret_hash(&token)),
                invited_by: AuditActor::admin("test-admin"),
                created_at,
                expires_at: created_at + Duration::days(7),
            },
        )
        .await
        .expect("create the invitation");
    Invitation { id: inv.id, token }
}

fn page_path(token: &str) -> String {
    format!("/ui/invitation?token={token}")
}

/// GETs the invitation page (expects the offer) and returns the CSRF token.
async fn open(app: &TestApp, inv: &Invitation) -> String {
    let resp = app.get(&page_path(&inv.token)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.offer");
    csrf_from(&resp.html())
}

async fn post_accept(app: &TestApp, inv: &Invitation, csrf: &str) -> TestResponse {
    app.post_form(
        "/ui/invitation",
        &[("csrf_token", csrf), ("token", &inv.token)],
    )
    .await
}

async fn post_register(
    app: &TestApp,
    inv: &Invitation,
    csrf: &str,
    extra: &[(&str, &str)],
) -> TestResponse {
    let mut pairs = vec![("csrf_token", csrf), ("token", inv.token.as_str())];
    pairs.extend_from_slice(extra);
    app.post_form("/ui/invitation/register", &pairs).await
}

/// The `data-message-key` of the page's main message.
fn view_key(resp: &TestResponse) -> String {
    let html = resp.html();
    let marker = "id=\"invitation-message\" data-message-key=\"";
    let start = html
        .find(marker)
        .unwrap_or_else(|| panic!("an invitation page: {html}"))
        + marker.len();
    let end = html[start..].find('"').expect("quoted") + start;
    html[start..end].to_owned()
}

/// Registers `email` through self-registration (password `PASSWORD`), optionally marks the email
/// verified, and returns the user id. The jar is left empty.
async fn user(app: &TestApp, tenant: &Tenant, email: &str, verified: bool) -> UserId {
    register(app, "", email, PASSWORD).await;
    let u = app
        .storage()
        .users()
        .get_by_email(tenant.id, email)
        .await
        .unwrap()
        .expect("registered");
    if verified {
        app.storage()
            .users()
            .update(
                tenant.id,
                u.id,
                &UserUpdate {
                    email_verified: Some(true),
                    ..UserUpdate::default()
                },
                app.clock().now(),
            )
            .await
            .unwrap()
            .expect("user exists");
    }
    u.id
}

async fn sign_in(app: &TestApp, email: &str) {
    app.clear_cookies();
    let resp = ui_helpers::login(app, "", email, PASSWORD).await;
    assert!(
        ui_helpers::session_cookie(app).is_some(),
        "signed in as {email}: {} {}",
        resp.status,
        resp.text()
    );
}

async fn is_open(app: &TestApp, tenant: &Tenant, inv: &Invitation) -> bool {
    let stored = app
        .storage()
        .organizations()
        .invitation_by_hash(tenant.id, &SecretHash(secret_hash(&inv.token)))
        .await
        .unwrap()
        .expect("stored");
    stored.accepted_at.is_none() && stored.revoked_at.is_none()
}

async fn is_member(app: &TestApp, tenant: &Tenant, org: &Organization, user: UserId) -> bool {
    app.storage()
        .organizations()
        .is_member(tenant.id, org.id, user)
        .await
        .unwrap()
}

async fn audited(app: &TestApp, tenant: &Tenant, action: AuditAction) -> Vec<String> {
    app.storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(action),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .filter_map(|e| e.target)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------------------------

/// Captures what the worker sends (a Mailpit-like test transport).
#[derive(Default)]
struct Capture(Mutex<Vec<OutgoingMail>>);

#[async_trait::async_trait]
impl MailTransport for Capture {
    async fn send(&self, mail: OutgoingMail) -> Result<(), MailError> {
        self.0.lock().unwrap().push(mail);
        Ok(())
    }
}

/// No tenant in these tests has SMTP settings, so the factory is never asked.
struct NoTenantSmtp;

impl TransportFactory for NoTenantSmtp {
    fn transport(
        &self,
        _tenant: anvil_core::model::TenantId,
        _settings: &anvil_core::model::SmtpSettings,
    ) -> Result<Arc<dyn MailTransport>, MailError> {
        Err(MailError::Config("no tenant SMTP in this test".into()))
    }

    fn evict(&self, _tenant: anvil_core::model::TenantId) {}
}

struct At(time::OffsetDateTime);

impl anvil_core::ports::Clock for At {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

#[tokio::test]
async fn org_invitation_email_renders() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let token = admin_token(&app, "admin:organizations:write").await;
    create_org(&app, tenant.id, "globex").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/organizations/globex/invitations"),
        Some(&token),
        Some(json!({"email": INVITED, "role_ids": []})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());

    // Sealed at rest: the stored payload carries neither the link nor the org name in clear.
    let now = app.clock().now();
    let rows = app
        .storage()
        .outbox()
        .claim_due(now, 10, std::time::Duration::from_secs(1))
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.template == "org_invitation")
        .expect("queued");
    let raw = format!("{:?}", row.payload);
    assert!(!raw.contains("/ui/invitation"), "payload is sealed");
    assert!(!raw.contains("GLOBEX"), "payload is sealed");

    let capture = Arc::new(Capture::default());
    let worker = OutboxWorker {
        source: Arc::new(StorageOutbox(app.storage_arc())),
        transport: Some(capture.clone() as Arc<dyn MailTransport>),
        transports: Arc::new(NoTenantSmtp),
        renderer: EmailRenderer::embedded(),
        clock: Arc::new(At(now + Duration::seconds(30))),
        from: "AnvilID <noreply@example.test>".to_owned(),
        kek: app.kek_arc(),
    };
    assert_eq!(worker.run_once().await.unwrap(), 1);
    let sent = capture.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let mail = &sent[0];
    assert_eq!(mail.to, INVITED);
    assert!(mail.subject.contains("GLOBEX"), "{}", mail.subject);
    assert!(mail.text.contains("GLOBEX") && mail.html.contains("GLOBEX"));
    assert!(mail.text.contains("7 days"));
    let link_start = mail
        .text
        .find("https://op.test/ui/invitation?token=")
        .expect("the text body carries the link");
    let link: String = mail.text[link_start..]
        .chars()
        .take_while(|c| !c.is_whitespace())
        .collect();
    assert!(mail.html.contains(&link.replace('/', "&#x2f;")) || mail.html.contains(&link));
    // The link opens the offer page with the org name.
    let path = link.strip_prefix("https://op.test").unwrap();
    let page = app.get(path).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_eq!(view_key(&page), "invitation.offer");
    assert!(page.html().contains("GLOBEX"));
}

// ---------------------------------------------------------------------------------------------
// Signed in
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn invitation_get_consumes_nothing() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let invitee = user(&app, &tenant, INVITED, true).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;

    // Signed out and signed in, twice each: nothing is consumed.
    for _ in 0..2 {
        let resp = app.get(&page_path(&inv.token)).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        assert_eq!(resp.header("referrer-policy"), Some("no-referrer"));
        let html = resp.html();
        assert!(html.contains("GLOBEX"));
        assert!(html.contains("id=\"invitation-accept-submit\""));
        assert!(!html.contains(INVITED), "the GET page shows only the org");
    }
    sign_in(&app, INVITED).await;
    for _ in 0..2 {
        open(&app, &inv).await;
    }
    assert!(is_open(&app, &tenant, &inv).await);
    assert!(!is_member(&app, &tenant, &org, invitee).await);

    let csrf = open(&app, &inv).await;
    let resp = post_accept(&app, &inv, &csrf).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.accepted");
    assert!(is_member(&app, &tenant, &org, invitee).await);
}

#[tokio::test]
async fn invitation_accept_signed_in_matching_verified_email() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let viewer = create_role(&app, tenant.id, None, "viewer", &["docs:read"]).await;
    let editor = create_role(&app, tenant.id, Some(org.id), "editor", &["docs:write"]).await;
    let invitee = user(&app, &tenant, INVITED, true).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[viewer.id, editor.id]).await;

    sign_in(&app, INVITED).await;
    let csrf = open(&app, &inv).await;
    let resp = post_accept(&app, &inv, &csrf).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.accepted");
    assert!(resp.html().contains("GLOBEX"));

    assert!(is_member(&app, &tenant, &org, invitee).await);
    let mut roles: Vec<String> = app
        .storage()
        .roles()
        .roles_for_user_in_org(tenant.id, invitee, org.id)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect();
    roles.sort();
    assert_eq!(roles, ["editor", "viewer"]);
    assert!(!is_open(&app, &tenant, &inv).await);
    assert_eq!(
        audited(&app, &tenant, AuditAction::OrgInvitationAccepted).await,
        [inv.id.to_string()]
    );
    assert_eq!(
        audited(&app, &tenant, AuditAction::OrgMemberAdded).await,
        [invitee.to_string()]
    );

    // Single use: the same token again is the invalid page.
    let again = post_accept(&app, &inv, &csrf).await;
    assert_eq!(again.status, 400);
    assert_eq!(view_key(&again), "invitation.invalid");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invitation_accept_concurrent_posts_one_winner() {
    let app = Arc::new(app().await);
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let invitee = user(&app, &tenant, INVITED, true).await;
    let inv = Arc::new(invite(&app, &tenant, &org, INVITED, &[]).await);
    sign_in(&app, INVITED).await;
    let csrf = open(&app, &inv).await;

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (app, inv, csrf) = (Arc::clone(&app), Arc::clone(&inv), csrf.clone());
        set.spawn(async move { post_accept(&app, &inv, &csrf).await });
    }
    let mut keys = Vec::new();
    while let Some(resp) = set.join_next().await {
        let resp = resp.expect("task");
        keys.push((resp.status.as_u16(), view_key(&resp)));
    }
    let winners = keys
        .iter()
        .filter(|(s, k)| *s == 200 && k == "invitation.accepted")
        .count();
    let losers = keys
        .iter()
        .filter(|(s, k)| *s == 400 && k == "invitation.invalid")
        .count();
    assert_eq!((winners, losers), (1, 7), "{keys:?}");
    assert!(is_member(&app, &tenant, &org, invitee).await);
    assert_eq!(
        audited(&app, &tenant, AuditAction::OrgInvitationAccepted)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn invitation_accept_wrong_account_keeps_token() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let invitee = user(&app, &tenant, INVITED, true).await;
    let other = user(&app, &tenant, OTHER, true).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;

    sign_in(&app, OTHER).await;
    let csrf = open(&app, &inv).await;
    let resp = post_accept(&app, &inv, &csrf).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.wrong_account");
    let html = resp.html();
    // Neither the invited nor the current account is named.
    assert!(!html.contains(INVITED) && !html.contains(OTHER), "{html}");
    assert!(html.contains("id=\"invitation-sign-out\""));
    assert!(is_open(&app, &tenant, &inv).await);
    assert!(!is_member(&app, &tenant, &org, other).await);

    // The right user accepts afterwards.
    sign_in(&app, INVITED).await;
    let csrf = open(&app, &inv).await;
    let resp = post_accept(&app, &inv, &csrf).await;
    assert_eq!(view_key(&resp), "invitation.accepted");
    assert!(is_member(&app, &tenant, &org, invitee).await);
}

#[tokio::test]
async fn invitation_unverified_email_account_cannot_accept() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let invitee = user(&app, &tenant, INVITED, false).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;

    sign_in(&app, INVITED).await;
    let csrf = open(&app, &inv).await;
    let resp = post_accept(&app, &inv, &csrf).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.verify_email");
    assert!(is_open(&app, &tenant, &inv).await);
    assert!(!is_member(&app, &tenant, &org, invitee).await);

    // Once verified, the same token works.
    app.storage()
        .users()
        .update(
            tenant.id,
            invitee,
            &UserUpdate {
                email_verified: Some(true),
                ..UserUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .unwrap();
    let resp = post_accept(&app, &inv, &csrf).await;
    assert_eq!(view_key(&resp), "invitation.accepted");
    assert!(is_member(&app, &tenant, &org, invitee).await);
}

#[tokio::test]
async fn invitation_already_member_keeps_token() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let invitee = user(&app, &tenant, INVITED, true).await;
    admin_support::add_member(&app, tenant.id, org.id, invitee, &[]).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;

    sign_in(&app, INVITED).await;
    let csrf = open(&app, &inv).await;
    let resp = post_accept(&app, &inv, &csrf).await;
    assert_eq!(view_key(&resp), "invitation.already_member");
    assert!(is_open(&app, &tenant, &inv).await);
}

// ---------------------------------------------------------------------------------------------
// Signed out: registration
// ---------------------------------------------------------------------------------------------

/// Opens the page signed out, posts accept and returns the signed-out page and its CSRF token.
async fn signed_out_offer(app: &TestApp, inv: &Invitation) -> (TestResponse, String) {
    app.clear_cookies();
    let csrf = open(app, inv).await;
    let resp = post_accept(app, inv, &csrf).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.signed_out");
    (resp, csrf)
}

async fn registers_and_joins(app: &TestApp, tenant: &Tenant) {
    let org = create_org(app, tenant.id, "globex").await;
    let viewer = create_role(app, tenant.id, None, "viewer", &["docs:read"]).await;
    let inv = invite(app, tenant, &org, INVITED, &[viewer.id]).await;

    let (offer, csrf) = signed_out_offer(app, &inv).await;
    let html = offer.html();
    assert!(html.contains("id=\"invitation-register-form\""));
    assert!(html.contains("id=\"invitation-sign-in\""));
    // The invited address is shown read-only and is not a form field.
    assert!(html.contains(&format!(
        "id=\"invitation-email\" type=\"email\" value=\"{INVITED}\" readonly"
    )));
    assert!(!html.contains("name=\"email\""));

    // A posted `email` is ignored: the account is created for the invited address.
    let resp = post_register(
        app,
        &inv,
        &csrf,
        &[("password", PASSWORD), ("name", "Ivy"), ("email", OTHER)],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.registered");
    assert!(resp.html().contains("GLOBEX"));
    let users = app.storage().users();
    assert!(
        users
            .get_by_email(tenant.id, OTHER)
            .await
            .unwrap()
            .is_none()
    );
    let created = users
        .get_by_email(tenant.id, INVITED)
        .await
        .unwrap()
        .expect("created");
    assert!(created.email_verified);
    assert_eq!(created.claims.name.as_deref(), Some("Ivy"));
    assert!(is_member(app, tenant, &org, created.id).await);
    let roles = app
        .storage()
        .roles()
        .roles_for_user_in_org(tenant.id, created.id, org.id)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert!(!is_open(app, tenant, &inv).await);
    assert_eq!(
        audited(app, tenant, AuditAction::UserRegistered).await,
        [created.id.to_string()]
    );
    assert_eq!(
        audited(app, tenant, AuditAction::OrgInvitationAccepted).await,
        [inv.id.to_string()]
    );
    // The password works.
    sign_in(app, INVITED).await;
}

#[tokio::test]
async fn invitation_signed_out_registration_creates_verified_user_and_membership() {
    let app = app().await;
    let tenant = default_tenant(&app);
    registers_and_joins(&app, &tenant).await;
}

#[tokio::test]
async fn invitation_registration_allowed_under_invite_only() {
    let app = app().await;
    let tenant = default_tenant(&app);
    set_settings(
        &app,
        tenant.id,
        TenantSettings {
            registration: RegistrationMode::InviteOnly,
            ..tenant.settings.clone()
        },
    )
    .await;
    // Self-registration is closed...
    let page = app.get("/ui/registration").await;
    assert!(message_keys(&page.html()).contains(&"registration.disabled".to_owned()));
    // ...but an invitation registers.
    registers_and_joins(&app, &default_tenant(&app)).await;
}

#[tokio::test]
async fn invitation_registration_refused_when_registration_disabled() {
    let app = app().await;
    let tenant = default_tenant(&app);
    set_settings(
        &app,
        tenant.id,
        TenantSettings {
            registration: RegistrationMode::Disabled,
            ..tenant.settings.clone()
        },
    )
    .await;
    let org = create_org(&app, tenant.id, "globex").await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;

    let (offer, csrf) = signed_out_offer(&app, &inv).await;
    let html = offer.html();
    assert!(!html.contains("invitation-register-form"), "{html}");
    assert!(html.contains("id=\"invitation-registration-disabled\""));
    assert!(html.contains("id=\"invitation-sign-in\""));

    // Posting the form anyway creates nothing and keeps the token.
    let resp = post_register(&app, &inv, &csrf, &[("password", PASSWORD)]).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert!(
        app.storage()
            .users()
            .get_by_email(tenant.id, INVITED)
            .await
            .unwrap()
            .is_none()
    );
    assert!(is_open(&app, &tenant, &inv).await);
}

#[tokio::test]
async fn invitation_registration_existing_email_offers_sign_in() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let existing = user(&app, &tenant, INVITED, true).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let before = app
        .storage()
        .users()
        .list(tenant.id, Default::default())
        .await
        .unwrap()
        .items
        .len();

    let (_, csrf) = signed_out_offer(&app, &inv).await;
    let resp = post_register(&app, &inv, &csrf, &[("password", "a different password")]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.email_taken");
    let html = resp.html();
    assert!(html.contains("id=\"invitation-sign-in\""));
    assert!(!html.contains("invitation-register-form"));
    let after = app
        .storage()
        .users()
        .list(tenant.id, Default::default())
        .await
        .unwrap()
        .items
        .len();
    assert_eq!(before, after, "no account created");
    assert!(!is_member(&app, &tenant, &org, existing).await);
    assert!(is_open(&app, &tenant, &inv).await);
    // The existing password is unchanged; signing in and accepting works.
    sign_in(&app, INVITED).await;
    let csrf = open(&app, &inv).await;
    assert_eq!(
        view_key(&post_accept(&app, &inv, &csrf).await),
        "invitation.accepted"
    );
}

#[tokio::test]
async fn invitation_registration_password_policy_applies() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let (_, csrf) = signed_out_offer(&app, &inv).await;
    let resp = post_register(&app, &inv, &csrf, &[("password", "short")]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.signed_out");
    assert!(message_keys(&resp.html()).contains(&"password.too_short".to_owned()));
    assert!(
        app.storage()
            .users()
            .get_by_email(tenant.id, INVITED)
            .await
            .unwrap()
            .is_none()
    );
    assert!(is_open(&app, &tenant, &inv).await);
}

/// A breach checker that reports every password as breached (test double).
struct AlwaysBreached;

#[async_trait::async_trait]
impl BreachChecker for AlwaysBreached {
    async fn is_breached(&self, _password: &str) -> Result<bool, CoreError> {
        Ok(true)
    }
}

/// A hasher the breach refusal must never reach.
struct NoHasher;

#[async_trait::async_trait]
impl anvil_core::ports::PasswordHasher for NoHasher {
    async fn hash(&self, _password: &str) -> Result<String, CoreError> {
        panic!("a breached password is never hashed")
    }
    async fn verify(
        &self,
        _phc: Option<&str>,
        _password: &str,
        _profile: Option<&anvil_core::model::HashProfileMaterial>,
    ) -> Result<anvil_core::ports::PasswordCheck, CoreError> {
        panic!("not used")
    }
}

#[tokio::test]
async fn invitation_registration_breached_password_refused() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let service = OrgInvitationService {
        storage: app.storage_arc(),
        clock: Arc::new(At(app.clock().now())),
        kek: app.kek_arc(),
    };
    let checks = RegistrationChecks {
        policy: app.config.password_policy,
        hasher: &NoHasher,
        breach: &AlwaysBreached,
    };
    let outcome = service
        .accept_with_registration(
            &tenant,
            &inv.token,
            PASSWORD,
            None,
            &checks,
            &RequestContext::system(),
        )
        .await
        .unwrap();
    assert_eq!(
        outcome,
        RegisterOutcome::PasswordRejected("password.breached")
    );
    assert!(is_open(&app, &tenant, &inv).await);
}

// ---------------------------------------------------------------------------------------------
// Invalid tokens, CSRF
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn invitation_invalid_tokens_share_one_page() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let org2 = create_org(&app, tenant.id, "initech").await;
    let org3 = create_org(&app, tenant.id, "hooli").await;
    user(&app, &tenant, INVITED, true).await;
    sign_in(&app, INVITED).await;
    let now = app.clock().now();

    // Each starts valid, so the browser holds a CSRF token for it.
    let used = invite(&app, &tenant, &org, INVITED, &[]).await;
    let revoked = invite(&app, &tenant, &org2, INVITED, &[]).await;
    let expired = invite_at(
        &app,
        &tenant,
        org3.id,
        INVITED,
        &[],
        now - Duration::days(7) + Duration::minutes(1),
    )
    .await;
    let csrf_used = open(&app, &used).await;
    let csrf_revoked = open(&app, &revoked).await;
    let csrf_expired = open(&app, &expired).await;

    assert_eq!(
        view_key(&post_accept(&app, &used, &csrf_used).await),
        "invitation.accepted"
    );
    assert!(
        app.storage()
            .organizations()
            .revoke_invitation(tenant.id, org2.id, revoked.id, now)
            .await
            .unwrap()
    );
    app.clock().advance(std::time::Duration::from_secs(120));
    let unknown = Invitation {
        id: OrgInvitationId::new_v7(),
        token: random_token(),
    };
    // A token of another tenant is unknown here.
    let acme = ui_helpers::create_tenant(&app, "acme").await;
    let acme_org = create_org(&app, acme.id, "globex").await;
    let foreign = invite(&app, &acme, &acme_org, INVITED, &[]).await;

    let mut gets = BTreeMap::new();
    for (name, inv) in [
        ("unknown", &unknown),
        ("used", &used),
        ("revoked", &revoked),
        ("expired", &expired),
        ("foreign", &foreign),
    ] {
        let get = app.get(&page_path(&inv.token)).await;
        assert_eq!(view_key(&get), "invitation.invalid", "{name}");
        assert!(!get.html().contains(&inv.token), "{name}: token echoed");
        assert!(!get.html().contains("csrf_token"), "{name}: a form");
        gets.insert(name, (get.status, get.text()));
    }
    let first = gets["unknown"].clone();
    assert_eq!(first.0, 400);
    for (name, got) in &gets {
        assert_eq!(got, &first, "GET {name} differs from unknown");
    }

    // POSTs with a valid CSRF binding: the same page as the GET of an unknown token.
    for (name, inv, csrf) in [
        ("used", &used, &csrf_used),
        ("revoked", &revoked, &csrf_revoked),
        ("expired", &expired, &csrf_expired),
    ] {
        let post = post_accept(&app, inv, csrf).await;
        assert_eq!((post.status, post.text()), first, "POST {name}");
        let reg = post_register(&app, inv, csrf, &[("password", PASSWORD)]).await;
        assert_eq!((reg.status, reg.text()), first, "POST register {name}");
    }
    // Signed out too.
    app.clear_cookies();
    let get = app.get(&page_path(&used.token)).await;
    assert_eq!((get.status, get.text()), first);
}

#[tokio::test]
async fn invitation_page_csrf_required() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let invitee = user(&app, &tenant, INVITED, true).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let other = invite(&app, &tenant, &org, OTHER, &[]).await;
    sign_in(&app, INVITED).await;
    let csrf = open(&app, &inv).await;
    let csrf_other = open(&app, &other).await;
    let nonce_cookie = app
        .cookies()
        .into_iter()
        .find(|(k, _)| k.contains("anvil_invitation"))
        .expect("the GET sets the nonce cookie");
    assert!(nonce_cookie.0.starts_with("__Host-"), "{nonce_cookie:?}");

    for path in ["/ui/invitation", "/ui/invitation/register"] {
        // No CSRF token, a wrong one, and the token of another invitation.
        for pairs in [
            vec![("token", inv.token.as_str()), ("password", PASSWORD)],
            vec![
                ("csrf_token", "forged"),
                ("token", inv.token.as_str()),
                ("password", PASSWORD),
            ],
            vec![
                ("csrf_token", csrf_other.as_str()),
                ("token", inv.token.as_str()),
                ("password", PASSWORD),
            ],
        ] {
            let resp = app.post_form(path, &pairs).await;
            assert_eq!(resp.status, 403, "{path} {pairs:?}: {}", resp.text());
        }
        // A cross-site post is stopped by the Fetch-Metadata layer.
        let body = format!("csrf_token={csrf}&token={}", inv.token);
        let resp = app
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("sec-fetch-site", "cross-site")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status, 403, "{path} cross-site");
    }
    // The right CSRF token without the nonce cookie (another browser).
    let session = ui_helpers::session_cookie(&app).expect("signed in");
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("csrf_token", csrf.as_str()), ("token", inv.token.as_str())])
        .finish();
    let resp = app
        .send(
            Request::builder()
                .method(Method::POST)
                .uri("/ui/invitation")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin")
                .header(header::COOKIE, format!("{}={}", session.0, session.1))
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());

    // Nothing was consumed: the bound post accepts.
    assert!(is_open(&app, &tenant, &inv).await);
    assert!(!is_member(&app, &tenant, &org, invitee).await);
    let resp = post_accept(&app, &inv, &csrf).await;
    assert_eq!(view_key(&resp), "invitation.accepted");
}

// ---------------------------------------------------------------------------------------------
// Return to the invitation after signing in (06-31)
// ---------------------------------------------------------------------------------------------

/// The invitation page as the sign-in returns to it (absolute, on the tenant's own origin).
fn invitation_url(app: &TestApp, inv: &Invitation) -> String {
    format!("{}{}", app.issuer(None), page_path(&inv.token))
}

/// The `href` of the element with `id`, unescaped, as a path on the public origin.
fn href_of(app: &TestApp, html: &str, id: &str) -> String {
    let marker = format!("id=\"{id}\" href=\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("#{id} in {html}"))
        + marker.len();
    let end = html[start..].find('"').expect("quoted") + start;
    let href = html[start..end]
        .replace("&#x2f;", "/")
        .replace("&amp;", "&");
    ui_helpers::to_path(app, &href)
}

/// Signed out: opens the invitation, posts accept and returns the sign-in link of the
/// signed-out page.
async fn sign_in_link(app: &TestApp, inv: &Invitation) -> String {
    let (offer, _) = signed_out_offer(app, inv).await;
    let link = href_of(app, &offer.html(), "invitation-sign-in");
    let encoded: String =
        url::form_urlencoded::byte_serialize(page_path(&inv.token).as_bytes()).collect();
    assert_eq!(link, format!("/ui/login?return_to={encoded}"));
    link
}

/// The login page's flow id (from its form action).
fn flow_of(app: &TestApp, html: &str) -> FlowId {
    let action = ui_helpers::form_action(app, html);
    let id = action
        .split("flow=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("the form carries the flow");
    FlowId(uuid::Uuid::parse_str(id).expect("flow id"))
}

async fn flow_state(app: &TestApp, tenant: &Tenant, flow: FlowId) -> String {
    app.storage()
        .flows()
        .get(tenant.id, flow, app.clock().now())
        .await
        .unwrap()
        .expect("flow stored")
        .state
}

/// Back on the invitation page after signing in: the offer, and one click accepts.
async fn accepts_after_return(app: &TestApp, inv: &Invitation, resp: &TestResponse) {
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(location(resp), invitation_url(app, inv));
    let page = app.follow(resp).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_eq!(view_key(&page), "invitation.offer");
    let csrf = csrf_from(&page.html());
    let accepted = post_accept(app, inv, &csrf).await;
    assert_eq!(view_key(&accepted), "invitation.accepted");
}

/// The answer is the normal signed-in page (no redirect anywhere).
fn signed_in_page(resp: &TestResponse, what: &str) {
    assert_eq!(resp.status, 200, "{what}: {}", resp.text());
    assert!(resp.header("location").is_none(), "{what}");
    assert!(
        message_keys(&resp.html()).contains(&"login.signed_in".to_owned()),
        "{what}: {}",
        resp.text()
    );
}

/// `true` if the response sets a session cookie.
fn sets_session(resp: &TestResponse) -> bool {
    resp.headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains("anvil_session_") && !v.contains("Max-Age=0"))
}

async fn active_session(app: &TestApp, tenant: &Tenant) -> BrowserSession {
    let (_, value) = ui_helpers::session_cookie(app).expect("session cookie");
    app.storage()
        .sessions()
        .get_active(
            tenant.id,
            &SecretHash(secret_hash(&value)),
            app.clock().now(),
        )
        .await
        .unwrap()
        .expect("active session")
}

#[tokio::test]
async fn invitation_sign_in_returns_to_invitation() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let invitee = user(&app, &tenant, INVITED, true).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;

    let link = sign_in_link(&app, &inv).await;
    let page = app.get(&link).await;
    assert_eq!(page.status, 200, "{}", page.text());
    // The URL carries the token: never sent on as a referrer, never cached.
    assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(page.header("cache-control"), Some("no-store"));
    let resp = ui_helpers::submit_form(
        &app,
        &link,
        &[("identifier", INVITED), ("password", PASSWORD)],
    )
    .await;
    accepts_after_return(&app, &inv, &resp).await;
    assert!(is_member(&app, &tenant, &org, invitee).await);
}

/// Enrols an authenticator app for `user` (random seed, sealed like production) and returns the
/// seed.
async fn enrol_totp(app: &TestApp, tenant: &Tenant, user: UserId) -> Vec<u8> {
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
            tenant.id,
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
    seed.as_bytes().to_vec()
}

/// RFC 6238 code (SHA-1, 6 digits, 30 s) of `seed` now (test code).
fn totp_now(app: &TestApp, seed: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let counter = u64::try_from(app.clock().now().unix_timestamp() / 30).expect("time");
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[off]) & 0x7f) << 24
        | u32::from(h[off + 1]) << 16
        | u32::from(h[off + 2]) << 8
        | u32::from(h[off + 3]);
    format!("{:06}", bin % 1_000_000)
}

/// Submits the second-factor form of `page` with the current TOTP code.
async fn totp_step(app: &TestApp, page: &TestResponse, seed: &[u8]) -> TestResponse {
    let html = page.html();
    assert!(html.contains("id=\"second-factor\""), "{html}");
    assert!(ui_helpers::session_cookie(app).is_none(), "no session yet");
    let action = ui_helpers::form_action(app, &html);
    let csrf = csrf_from(&html);
    let factor = ui_helpers::hidden_inputs(&html)
        .into_iter()
        .find(|(n, _)| n == "factor_token")
        .map(|(_, v)| v)
        .expect("factor_token");
    let code = totp_now(app, seed);
    app.post_form(
        &action,
        &[
            ("csrf_token", csrf.as_str()),
            ("factor_token", factor.as_str()),
            ("code", code.as_str()),
        ],
    )
    .await
}

#[tokio::test]
async fn invitation_sign_in_with_second_factor_returns_to_invitation() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let invitee = user(&app, &tenant, INVITED, true).await;
    let seed = enrol_totp(&app, &tenant, invitee).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;

    let link = sign_in_link(&app, &inv).await;
    let page = ui_helpers::submit_form(
        &app,
        &link,
        &[("identifier", INVITED), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(page.status, 200, "{}", page.text());
    let resp = totp_step(&app, &page, &seed).await;
    accepts_after_return(&app, &inv, &resp).await;
    assert!(is_member(&app, &tenant, &org, invitee).await);
}

#[tokio::test]
async fn invitation_sso_sign_in_returns_to_invitation() {
    // An account linked to the provider signs in with the upstream button of the login page the
    // invitation linked to: once directly, once continuing in a fresh flow at the second factor
    // (the target moves to the new flow, resealed).
    let u = upstream_flow::setup(true).await;
    let app = &u.app;
    let tenant = default_tenant(app);
    let org = create_org(app, tenant.id, "globex").await;
    let invitee = user(app, &tenant, INVITED, true).await;
    let invitee_user = app
        .storage()
        .users()
        .get(tenant.id, invitee)
        .await
        .unwrap()
        .expect("user");
    upstream_flow::link_identity(app, &invitee_user, &u.conn, MOCK_SUBJECT).await;
    let inv = invite(app, &tenant, &org, INVITED, &[]).await;
    let claims = json!({ "email": INVITED, "email_verified": true });

    let sso = |link: String| {
        let claims = claims.clone();
        let u = &u;
        async move {
            let page = u.app.get(&link).await;
            assert_eq!(page.status, 200, "{}", page.text());
            let html = page.html();
            let action = upstream_flow::button_action(&u.app, &html, upstream_flow::SLUG);
            let started = upstream_flow::post_start(&u.app, &action, &csrf_from(&html)).await;
            upstream_flow::reply_for(u, &started, claims);
            upstream_flow::callback(u, &started).await
        }
    };

    let resp = sso(sign_in_link(app, &inv).await).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(location(&resp), invitation_url(app, &inv));
    assert_eq!(active_session(app, &tenant).await.user_id, invitee);

    // With a second factor: the callback continues in a new flow.
    let seed = enrol_totp(app, &tenant, invitee).await;
    let page = sso(sign_in_link(app, &inv).await).await;
    let resp = totp_step(app, &page, &seed).await;
    accepts_after_return(app, &inv, &resp).await;
    assert!(is_member(app, &tenant, &org, invitee).await);
}

#[tokio::test]
async fn return_to_rejects_open_redirects() {
    let app = app().await;
    let tenant = default_tenant(&app);
    user(&app, &tenant, INVITED, true).await;
    let oversized = format!("/ui/invitation?token={}", "a".repeat(129));
    let rejected = [
        "",
        "https://evil.example/ui/invitation?token=a",
        "//evil.example/ui/invitation?token=a",
        "/\\evil.example",
        "\\\\evil.example",
        "/ui/invitation",
        "/ui/invitation?token=",
        "/ui/invitation?token=a&x=1",
        "/ui/invitation?x=1&token=a",
        "/ui/invitation?token=a#f",
        "/ui/invitation?token=a%2F",
        "/ui/../ui/invitation?token=a",
        "/ui/account",
        "/ui/invitation/register?token=a",
        "/UI/invitation?token=a",
        "/ui/invitation?token=a+b",
        "/ui/invitation?token=a/b",
        "/ui/invitation?token=a=",
        "/ui/invitation?token=a b",
        "/ui/invitation?token=a\r\nLocation: https://evil.example",
        "/ui/invitation?token=aé",
        "javascript:alert(1)",
        oversized.as_str(),
    ];
    for raw in rejected {
        app.clear_cookies();
        let encoded: String = url::form_urlencoded::byte_serialize(raw.as_bytes()).collect();
        let path = format!("/ui/login?return_to={encoded}");
        let page = app.get(&path).await;
        assert_eq!(page.status, 200, "{raw:?}: ignored, not an error page");
        let flow = flow_of(&app, &page.html());
        assert!(
            !flow_state(&app, &tenant, flow)
                .await
                .contains("return_to_sealed"),
            "{raw:?}: nothing stored"
        );
        let resp = ui_helpers::submit_form(
            &app,
            &path,
            &[("identifier", INVITED), ("password", PASSWORD)],
        )
        .await;
        signed_in_page(&resp, raw);
    }
}

#[tokio::test]
async fn return_to_tampered_or_moved_sealed_value_is_ignored() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    user(&app, &tenant, INVITED, true).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let encoded: String =
        url::form_urlencoded::byte_serialize(page_path(&inv.token).as_bytes()).collect();
    let path = format!("/ui/login?return_to={encoded}");

    // A sealed value taken from another login flow.
    app.clear_cookies();
    let donor = app.get(&path).await;
    let donor_state = flow_state(&app, &tenant, flow_of(&app, &donor.html())).await;
    let donor_sealed =
        serde_json::from_str::<serde_json::Value>(&donor_state).unwrap()["return_to_sealed"]
            .as_str()
            .expect("sealed")
            .to_owned();
    // The same value with one character changed.
    let mut tampered = donor_sealed.clone().into_bytes();
    let i = tampered.len() / 2;
    tampered[i] = if tampered[i] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();

    for (what, sealed) in [("moved", donor_sealed), ("tampered", tampered)] {
        app.clear_cookies();
        let page = app.get(&path).await;
        let html = page.html();
        let flow = flow_of(&app, &html);
        let mut state: serde_json::Value =
            serde_json::from_str(&flow_state(&app, &tenant, flow).await).unwrap();
        state["return_to_sealed"] = serde_json::Value::String(sealed);
        assert!(
            app.storage()
                .flows()
                .update_state(tenant.id, flow, &state.to_string(), app.clock().now())
                .await
                .unwrap()
        );
        let action = ui_helpers::form_action(&app, &html);
        let resp = app
            .post_form(
                &action,
                &[
                    ("csrf_token", csrf_from(&html).as_str()),
                    ("identifier", INVITED),
                    ("password", PASSWORD),
                ],
            )
            .await;
        signed_in_page(&resp, what);
    }
}

#[tokio::test]
async fn return_to_ignored_with_authorization_request() {
    const REQUEST: &str = "0192f0c4-7a1b-7c3d-8e9f-0123456789ab";
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    user(&app, &tenant, INVITED, true).await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let encoded: String =
        url::form_urlencoded::byte_serialize(page_path(&inv.token).as_bytes()).collect();
    let path = format!("/ui/login?request={REQUEST}&return_to={encoded}");
    app.clear_cookies();
    let page = app.get(&path).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let state = flow_state(&app, &tenant, flow_of(&app, &page.html())).await;
    assert!(!state.contains("return_to_sealed"), "{state}");
    let resp = ui_helpers::submit_form(
        &app,
        &path,
        &[("identifier", INVITED), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        location(&resp),
        format!("{}/authorize/continue?request={REQUEST}", app.issuer(None))
    );
}

#[tokio::test]
async fn return_to_token_not_stored_in_plaintext() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let link = sign_in_link(&app, &inv).await;
    let page = app.get(&link).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let state = flow_state(&app, &tenant, flow_of(&app, &page.html())).await;
    assert!(state.contains("return_to_sealed"), "{state}");
    assert!(!state.contains(&inv.token), "{state}");
    assert!(!state.contains("/ui/invitation"), "{state}");
    // Nor in the page itself (the target lives in the flow, not in a form field).
    assert!(!page.html().contains(&inv.token));
}

// ---------------------------------------------------------------------------------------------
// Signed in after registering through an invitation (06-31)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn invitation_registration_signs_in() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let (_, csrf) = signed_out_offer(&app, &inv).await;
    let resp = post_register(&app, &inv, &csrf, &[("password", PASSWORD)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.registered");
    assert!(sets_session(&resp), "the registration signs in");
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let html = resp.html();
    assert_eq!(
        href_of(&app, &html, "invitation-continue"),
        "/ui/account/profile"
    );
    assert!(!html.contains("id=\"invitation-sign-in\""));

    let created = app
        .storage()
        .users()
        .get_by_email(tenant.id, INVITED)
        .await
        .unwrap()
        .expect("created");
    assert!(is_member(&app, &tenant, &org, created.id).await);
    let session = active_session(&app, &tenant).await;
    assert_eq!(session.user_id, created.id);
    assert_eq!(session.amr, vec!["pwd".to_owned()]);
    // The account page needs no further sign-in.
    let account = app.get("/ui/account/profile").await;
    assert_eq!(account.status, 200, "{}", account.text());
    // Audited as a sign-in with its own method.
    let events = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::LoginSucceeded),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        events[0].target.as_deref(),
        Some(created.id.to_string().as_str())
    );
    assert_eq!(
        events[0]
            .details
            .as_map()
            .get("method")
            .and_then(|v| v.as_str()),
        Some("invitation_registration")
    );
}

#[tokio::test]
async fn invitation_registration_replaces_other_users_session() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;
    let other = user(&app, &tenant, OTHER, true).await;
    sign_in(&app, OTHER).await;
    let before = active_session(&app, &tenant).await;
    assert_eq!(before.user_id, other);
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let csrf = open(&app, &inv).await;

    let resp = post_register(&app, &inv, &csrf, &[("password", PASSWORD)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(view_key(&resp), "invitation.registered");
    assert!(sets_session(&resp));
    let created = app
        .storage()
        .users()
        .get_by_email(tenant.id, INVITED)
        .await
        .unwrap()
        .expect("the account is the invited address's");
    assert_eq!(active_session(&app, &tenant).await.user_id, created.id);
    assert!(is_member(&app, &tenant, &org, created.id).await);
    assert!(!is_member(&app, &tenant, &org, other).await);
    let old = app
        .storage()
        .sessions()
        .get(tenant.id, before.id)
        .await
        .unwrap()
        .expect("old session row");
    assert!(
        old.revoked_at.is_some(),
        "the other user's session is revoked"
    );
}

#[tokio::test]
async fn invitation_registration_failures_set_no_session() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "globex").await;

    // The address already has an account.
    user(&app, &tenant, OTHER, true).await;
    let taken = invite(&app, &tenant, &org, OTHER, &[]).await;
    let (_, csrf) = signed_out_offer(&app, &taken).await;
    let resp = post_register(&app, &taken, &csrf, &[("password", PASSWORD)]).await;
    assert_eq!(view_key(&resp), "invitation.email_taken");
    assert!(!sets_session(&resp), "email_taken");
    // Its sign-in link returns to the invitation.
    let encoded: String =
        url::form_urlencoded::byte_serialize(page_path(&taken.token).as_bytes()).collect();
    assert_eq!(
        href_of(&app, &resp.html(), "invitation-sign-in"),
        format!("/ui/login?return_to={encoded}")
    );

    // A refused password, a forged CSRF token.
    let inv = invite(&app, &tenant, &org, INVITED, &[]).await;
    let (_, csrf) = signed_out_offer(&app, &inv).await;
    let resp = post_register(&app, &inv, &csrf, &[("password", "short")]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(!sets_session(&resp), "password");
    let resp = post_register(&app, &inv, "forged", &[("password", PASSWORD)]).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert!(!sets_session(&resp), "csrf");

    // Registration disabled.
    set_settings(
        &app,
        tenant.id,
        TenantSettings {
            registration: RegistrationMode::Disabled,
            ..tenant.settings.clone()
        },
    )
    .await;
    let resp = post_register(&app, &inv, &csrf, &[("password", PASSWORD)]).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert!(!sets_session(&resp), "disabled");
    set_settings(&app, tenant.id, tenant.settings.clone()).await;

    // The invitation expired after the page was opened.
    app.clock()
        .advance(std::time::Duration::from_secs(8 * 24 * 3600));
    let resp = post_register(&app, &inv, &csrf, &[("password", PASSWORD)]).await;
    assert_eq!(view_key(&resp), "invitation.invalid");
    assert!(!sets_session(&resp), "invalid");

    assert!(ui_helpers::session_cookie(&app).is_none());
    assert!(
        app.storage()
            .users()
            .get_by_email(tenant.id, INVITED)
            .await
            .unwrap()
            .is_none()
    );
}
