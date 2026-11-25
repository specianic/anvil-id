//! Password recovery through the built-in pages (AUTH-03, UI-01) on the selected backend
//! (`ANVILID_TEST_DB`).

mod support;
mod ui_helpers;

use anvil_core::model::{
    ActorKind, AuditAction, AuditOutcome, AuditQuery, SecretHash, SmtpSettings, TenantId,
};
use anvil_core::ports::Clock as _;
use anvil_mail::worker::TransportFactory;
use anvil_mail::{
    EmailRenderer, MailError, MailTransport, OutboxWorker, OutgoingMail, StorageOutbox,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
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

    // The auth route class allows a burst of 5 POSTs per client IP; let the bucket refill
    // instead of disabling the limiter.
    app.clock().advance(Duration::from_secs(60));

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
    app.clock().advance(Duration::from_secs(60));
    app.clear_cookies();
    let resp = submit_form(&app, &link, &[("password", "yet another passphrase")]).await;
    assert_eq!(resp.status, 400);
    assert!(
        message_keys(&resp.html()).contains(&"recovery.invalid_token".to_owned()),
        "{}",
        resp.html()
    );

    // The user was told about the change: exactly one notice although the token was used twice
    // (once successfully, once refused), enqueued by the recovery transaction itself.
    let emails = take_emails(&app).await;
    let notices: Vec<_> = emails
        .iter()
        .filter(|e| e.template == "password_changed")
        .collect();
    assert_eq!(notices.len(), 1, "{emails:?}");
    assert_eq!(notices[0].to, EMAIL);
    // Sealed payload (take_emails opened it with the KEK). It was sealed before the token was
    // consumed, so it carries no address; the row is addressed to the token's email.
    assert!(!notices[0].payload.contains_key("email"));
    assert_eq!(
        notices[0].payload["tenant_name"],
        default_tenant(&app).display_name
    );

    // Delivered by the real outbox worker once take_emails' claim lease has passed: the rendered
    // body names the recipient (the worker fills `email` from the row).
    app.clock().advance(Duration::from_secs(3601));
    // (Every row claimed by take_emails is due again, so the earlier emails are re-sent too.)
    let sent: Vec<_> = deliver_outbox(&app)
        .await
        .into_iter()
        .filter(|m| m.subject.contains("password was changed"))
        .collect();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].to, EMAIL);
    assert!(
        sent[0]
            .text
            .contains(&format!("The password for {EMAIL} at")),
        "{}",
        sent[0].text
    );
    assert!(sent[0].html.contains(EMAIL));

    // The change is audited once, for the user.
    let changed: Vec<_> = audit(&app)
        .await
        .into_iter()
        .filter(|e| e.action == AuditAction::PasswordChanged)
        .collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].outcome, AuditOutcome::Success);
    assert_eq!(changed[0].actor.kind, ActorKind::User);
    assert_eq!(changed[0].target, changed[0].actor.id);
    assert_eq!(changed[0].ctx.ip, Some(support::DEFAULT_PEER.ip()));
}

/// Captures what the outbox worker sends.
#[derive(Default)]
struct Capture(Mutex<Vec<OutgoingMail>>);

#[async_trait::async_trait]
impl MailTransport for Capture {
    async fn send(&self, mail: OutgoingMail) -> Result<(), MailError> {
        self.0.lock().expect("capture lock").push(mail);
        Ok(())
    }
}

/// No tenant has SMTP settings in these tests; the installation transport is used.
struct NoTenantSmtp;

impl TransportFactory for NoTenantSmtp {
    fn transport(
        &self,
        _: TenantId,
        _: &SmtpSettings,
    ) -> Result<Arc<dyn MailTransport>, MailError> {
        Err(MailError::Config("no tenant SMTP in this test".into()))
    }

    fn evict(&self, _: TenantId) {}
}

/// The harness clock's current time, frozen (the worker only reads it).
struct Frozen(time::OffsetDateTime);

impl anvil_core::ports::Clock for Frozen {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

/// Runs one batch of the production outbox worker over the app's storage and KEK and returns
/// the mails it sent.
async fn deliver_outbox(app: &TestApp) -> Vec<OutgoingMail> {
    let capture = Arc::new(Capture::default());
    let worker = OutboxWorker {
        source: Arc::new(StorageOutbox(app.storage_arc())),
        transport: Some(capture.clone() as Arc<dyn MailTransport>),
        transports: Arc::new(NoTenantSmtp),
        renderer: EmailRenderer::embedded(),
        clock: Arc::new(Frozen(app.clock().now())),
        from: "AnvilID <noreply@example.test>".to_owned(),
        kek: app.kek_arc(),
    };
    worker.run_once().await.expect("outbox batch");
    std::mem::take(&mut *capture.0.lock().expect("capture lock"))
}

async fn audit(app: &TestApp) -> Vec<anvil_core::model::AuditEvent> {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

#[tokio::test]
async fn reset_with_an_invalid_token_enqueues_no_notice_and_audits_nothing() {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, OLD).await;
    take_emails(&app).await;
    let resp = submit_form(
        &app,
        "/ui/recovery?token=not-a-real-token",
        &[("password", NEW)],
    )
    .await;
    assert_eq!(resp.status, 400);
    assert!(message_keys(&resp.html()).contains(&"recovery.invalid_token".to_owned()));
    assert!(take_emails(&app).await.is_empty(), "no outbox row");
    assert!(
        !audit(&app)
            .await
            .iter()
            .any(|e| e.action == AuditAction::PasswordChanged)
    );
    // The old password still works.
    app.clear_cookies();
    assert_eq!(login(&app, "", EMAIL, OLD).await.status, 200);
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
