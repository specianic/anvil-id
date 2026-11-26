//! Organization invitation acceptance (ORG-02, plan 06-20): the `org_invitation` email through
//! the outbox worker, the GET page that consumes nothing, acceptance bound to the signed-in user's
//! verified email (single use under concurrency), the wrong-account and unverified cases keeping
//! the token, registration through an invitation (open, invite_only, disabled, existing address),
//! one page for every invalid token, and the CSRF binding of the forms.

mod admin_support;
mod support;
mod ui_helpers;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use admin_support::{API, admin_token, call, create_org, create_role};
use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditAction, AuditActor, AuditQuery, NewOrgInvitation, OrgId, OrgInvitationId, Organization,
    RegistrationMode, RequestContext, RoleId, SecretHash, Tenant, TenantSettings, UserId,
    UserUpdate,
};
use anvil_core::ports::{BreachChecker, Clock as _};
use anvil_core::service::org_invitation::{
    OrgInvitationService, RegisterOutcome, RegistrationChecks,
};
use anvil_jose::encoding::{random_token, secret_hash};
use anvil_mail::worker::TransportFactory;
use anvil_mail::{
    EmailRenderer, MailError, MailTransport, OutboxWorker, OutgoingMail, StorageOutbox,
};
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::json;
use support::{TestApp, TestResponse, csrf_from};
use time::Duration;
use ui_helpers::{default_tenant, message_keys, register, set_settings};

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
