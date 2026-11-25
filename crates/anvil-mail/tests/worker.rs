//! Outbox worker semantics: send, backoff, give-up, render failures, sealed payloads, tenant
//! template overrides and per-tenant SMTP transport resolution.

mod support;

use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::{EmailKind, EmailTemplate, SmtpSettings, SmtpTls, TenantId};
use anvil_core::ports::{Clock, MailSettingsRepo, OutboxRepo};
use anvil_core::service::mail_settings::seal_smtp_password;
use anvil_jose::Kek;
use anvil_mail::worker::{
    MAX_ATTEMPTS, NO_SMTP_ERROR, PAYLOAD_DECRYPT_ERROR, SmtpTransportFactory, TransportFactory,
};
use anvil_mail::{EmailRenderer, OutboxWorker};
use secrecy::SecretString;
use support::{
    CapturingTransport, MemOutbox, RecordingFactory, TestClock, email_with_payload, new_email,
    payload, start_time,
};

const FROM: &str = "AnvilID <noreply@example.test>";

struct Harness {
    outbox: Arc<MemOutbox>,
    transport: Arc<CapturingTransport>,
    factory: Arc<RecordingFactory>,
    clock: Arc<TestClock>,
    kek: Arc<Kek>,
    tenant: TenantId,
    worker: OutboxWorker,
}

impl Harness {
    /// An email for the harness tenant, sealed with the worker's KEK.
    fn email(&self, to: &str, template: &str, link: &str) -> anvil_core::model::NewEmail {
        new_email(&self.kek, self.tenant, to, template, link, start_time())
    }
}

fn harness(transport: CapturingTransport) -> Harness {
    harness_with(Some(transport))
}

/// `installation = None`: no installation SMTP (`smtp_url` unset).
fn harness_with(installation: Option<CapturingTransport>) -> Harness {
    let outbox = Arc::new(MemOutbox::default());
    let has_installation = installation.is_some();
    let transport = Arc::new(installation.unwrap_or_default());
    let factory = Arc::new(RecordingFactory::default());
    let clock = Arc::new(TestClock::new(start_time()));
    let kek = Arc::new(Kek::generate());
    let worker = OutboxWorker {
        source: outbox.clone(),
        transport: has_installation
            .then(|| transport.clone() as Arc<dyn anvil_mail::MailTransport>),
        transports: factory.clone(),
        renderer: EmailRenderer::embedded(),
        clock: clock.clone(),
        from: FROM.to_owned(),
        kek: kek.clone(),
    };
    Harness {
        outbox,
        transport,
        factory,
        clock,
        kek,
        tenant: TenantId::new_v7(),
        worker,
    }
}

#[tokio::test]
async fn sends_due_rows_and_marks_them_sent() {
    let h = harness(CapturingTransport::default());
    let tenant = h.tenant;
    let mut ids = Vec::new();
    for (to, template) in [
        ("a@example.test", "verification"),
        ("b@example.test", "recovery"),
        ("c@example.test", "password_changed"),
    ] {
        let e = h.email(to, template, "https://id.test/l?token=tok");
        ids.push(e.id);
        h.outbox.enqueue(tenant, &e).await.unwrap();
    }

    assert_eq!(h.worker.run_once().await.unwrap(), 3);

    let sent = h.transport.sent();
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[0].to, "a@example.test");
    assert!(sent[0].subject.starts_with("Confirm your email address"));
    assert!(sent[0].text.contains("https://id.test/l?token=tok"));
    assert_eq!(sent[1].to, "b@example.test");
    assert!(sent[1].subject.starts_with("Reset your"));
    assert_eq!(sent[2].to, "c@example.test");
    assert!(sent[2].subject.contains("password was changed"));
    assert!(sent.iter().all(|m| m.from == FROM));
    for id in ids {
        assert_eq!(h.outbox.row(id).sent_at, Some(start_time()));
    }

    // Nothing left to do.
    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    assert_eq!(h.transport.calls(), 3);
}

#[tokio::test]
async fn failed_send_backs_off_30s_without_leaking_the_link() {
    let h = harness(CapturingTransport::failing(1));
    let link = "https://id.test/recovery?token=very-secret-token";
    let e = h.email("a@example.test", "recovery", link);
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    let row = h.outbox.row(e.id);
    assert_eq!(row.attempts, 1);
    assert_eq!(row.next_attempt_at, start_time() + Duration::from_secs(30));
    assert_eq!(row.sent_at, None);
    let err = row.last_error.expect("last_error recorded");
    assert!(!err.is_empty());
    assert!(!err.contains("very-secret-token"), "{err}");
    assert!(!err.contains("Reset your"), "{err}");

    // Before the backoff elapses nothing is sent.
    h.clock.advance(Duration::from_secs(29));
    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    assert!(h.transport.sent().is_empty());
    assert_eq!(h.transport.calls(), 1);

    // After 30 s it is sent.
    h.clock.advance(Duration::from_secs(1));
    assert_eq!(h.worker.run_once().await.unwrap(), 1);
    assert_eq!(h.transport.sent().len(), 1);
    let row = h.outbox.row(e.id);
    assert_eq!(row.attempts, 2);
    assert!(row.sent_at.is_some());
}

#[tokio::test]
async fn backoff_doubles_and_gives_up_after_max_attempts() {
    let h = harness(CapturingTransport::failing(u32::MAX));
    let e = h.email("a@example.test", "verification", "https://id.test/v");
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    let mut expected_delay = 30u64;
    for attempt in 1..=MAX_ATTEMPTS {
        let before = h.clock.now();
        assert_eq!(h.worker.run_once().await.unwrap(), 0);
        let row = h.outbox.row(e.id);
        assert_eq!(row.attempts, attempt);
        if attempt < MAX_ATTEMPTS {
            assert_eq!(
                row.next_attempt_at,
                before + Duration::from_secs(expected_delay),
                "attempt {attempt}"
            );
            h.clock.advance(Duration::from_secs(expected_delay));
            expected_delay = (expected_delay * 2).min(3600);
        } else {
            assert_eq!(row.next_attempt_at, row.expires_at, "parked at expiry");
        }
    }
    assert_eq!(h.transport.calls(), MAX_ATTEMPTS);

    // No longer claimed, even much later (up to just before expiry).
    h.clock.advance(Duration::from_secs(3600 * 12));
    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    assert_eq!(h.transport.calls(), MAX_ATTEMPTS);
    assert_eq!(h.outbox.row(e.id).attempts, MAX_ATTEMPTS);
}

#[tokio::test]
async fn render_failure_is_recorded_and_does_not_stop_the_batch() {
    let h = harness(CapturingTransport::default());
    let tenant = h.tenant;
    let bad = h.email("bad@example.test", "no_such_email", "https://id.test/x");
    h.outbox.enqueue(tenant, &bad).await.unwrap();
    for to in ["a@example.test", "b@example.test"] {
        let e = h.email(to, "verification", "https://id.test/v");
        h.outbox.enqueue(tenant, &e).await.unwrap();
    }

    assert_eq!(h.worker.run_once().await.unwrap(), 2);
    let tos: Vec<_> = h.transport.sent().into_iter().map(|m| m.to).collect();
    assert_eq!(tos, ["a@example.test", "b@example.test"]);

    let row = h.outbox.row(bad.id);
    assert_eq!(row.attempts, 1);
    assert_eq!(row.sent_at, None);
    assert_eq!(row.next_attempt_at, start_time() + Duration::from_secs(30));
    let err = row.last_error.unwrap();
    assert!(err.contains("unknown template"), "{err}");
    assert!(!err.contains("https://id.test/x"), "{err}");
}

#[tokio::test]
async fn missing_payload_key_fails_the_row_without_leaking_values() {
    let h = harness(CapturingTransport::default());
    let mut vars = payload("a@example.test", "https://id.test/s3cret");
    vars.remove("tenant_name");
    let e = email_with_payload(
        &h.kek,
        h.tenant,
        "a@example.test",
        "verification",
        &vars,
        start_time(),
    );
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    let err = h.outbox.row(e.id).last_error.unwrap();
    assert!(err.contains("undefined"), "{err}");
    assert!(
        !err.contains("s3cret") && !err.contains("a@example.test"),
        "{err}"
    );
    assert_eq!(h.transport.calls(), 0);
}

#[tokio::test]
async fn run_delivers_and_stops_on_shutdown() {
    let h = harness(CapturingTransport::default());
    let e = h.email("a@example.test", "verification", "https://id.test/v");
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let transport = h.transport.clone();
    let task = tokio::spawn(h.worker.run(async {
        let _ = rx.await;
    }));
    for _ in 0..200 {
        if !transport.sent().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(transport.sent().len(), 1);
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("worker stops on shutdown")
        .unwrap();
}

#[tokio::test]
async fn sealed_payload_is_opened_and_the_link_is_sent() {
    let h = harness(CapturingTransport::default());
    let link = "https://id.test/verification?token=sealed-marker-token";
    let e = h.email("a@example.test", "verification", link);
    // What is stored is sealed: no plaintext link in the row.
    assert_eq!(e.payload.len(), 1);
    assert!(
        e.payload
            .values()
            .all(|v| !v.contains("sealed-marker-token"))
    );
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 1);
    let sent = h.transport.sent();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].text.contains(link),
        "decrypted link in the text body"
    );
    assert!(
        sent[0].html.contains("sealed-marker-token"),
        "and in the HTML body"
    );
    assert!(h.outbox.row(e.id).sent_at.is_some());
}

#[tokio::test]
async fn payload_sealed_with_another_kek_is_failed_and_never_sent() {
    let h = harness(CapturingTransport::default());
    let link = "https://id.test/recovery?token=foreign-kek-token";
    let other = Kek::generate();
    let foreign = new_email(
        &other,
        h.tenant,
        "a@example.test",
        "recovery",
        link,
        start_time(),
    );
    h.outbox.enqueue(h.tenant, &foreign).await.unwrap();
    // Sealed for another tenant with the right KEK: the AAD does not match.
    let wrong_tenant = new_email(
        &h.kek,
        TenantId::new_v7(),
        "b@example.test",
        "recovery",
        link,
        start_time(),
    );
    h.outbox.enqueue(h.tenant, &wrong_tenant).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    assert_eq!(h.transport.calls(), 0, "nothing is handed to the transport");
    for id in [foreign.id, wrong_tenant.id] {
        let row = h.outbox.row(id);
        assert_eq!(row.attempts, 1);
        assert_eq!(row.sent_at, None);
        assert_eq!(row.next_attempt_at, start_time() + Duration::from_secs(30));
        assert_eq!(row.last_error.as_deref(), Some(PAYLOAD_DECRYPT_ERROR));
    }
}

#[tokio::test]
async fn unsealed_or_tampered_payload_is_failed_and_never_sent() {
    let h = harness(CapturingTransport::default());
    // A plaintext payload (no plaintext fallback).
    let mut plain = h.email("a@example.test", "verification", "https://id.test/v");
    plain.payload = payload("a@example.test", "https://id.test/v?token=plain-token");
    h.outbox.enqueue(h.tenant, &plain).await.unwrap();
    // A tampered sealed payload.
    let mut tampered = h.email("b@example.test", "verification", "https://id.test/v");
    // Change one base64url character in the middle (a full 6-bit symbol, so the decoded
    // ciphertext changes and the AEAD tag check fails).
    let v = tampered.payload.values_mut().next().unwrap();
    let mid = v.len() / 2;
    let flipped = if &v[mid..=mid] == "A" { "B" } else { "A" };
    v.replace_range(mid..=mid, flipped);
    h.outbox.enqueue(h.tenant, &tampered).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    assert_eq!(h.transport.calls(), 0);
    for id in [plain.id, tampered.id] {
        let err = h.outbox.row(id).last_error.unwrap();
        assert_eq!(err, PAYLOAD_DECRYPT_ERROR);
        assert!(!err.contains("plain-token"));
    }
}

fn tenant_smtp(from: &str) -> SmtpSettings {
    SmtpSettings {
        host: "smtp.tenant.example".into(),
        port: 587,
        username: Some("mailer".into()),
        password_enc: None,
        from: from.into(),
        tls: SmtpTls::Starttls,
        updated_at: start_time(),
    }
}

#[tokio::test]
async fn tenant_override_is_rendered_and_other_tenants_get_the_default() {
    let h = harness(CapturingTransport::default());
    h.outbox
        .put_template(
            h.tenant,
            &EmailTemplate {
                kind: EmailKind::Verification,
                subject: "Custom {{ tenant_name }} subject".into(),
                body_html: "<p>{{ email }}</p><a href=\"{{ link }}\">go</a>".into(),
                body_text: "Custom text {{ link }}".into(),
                updated_at: start_time(),
            },
        )
        .await
        .unwrap();
    let mine = h.email(
        "a@example.test",
        "verification",
        "https://id.test/v?token=t1",
    );
    h.outbox.enqueue(h.tenant, &mine).await.unwrap();
    let other_tenant = TenantId::new_v7();
    let theirs = new_email(
        &h.kek,
        other_tenant,
        "b@example.test",
        "verification",
        "https://id.test/v?token=t2",
        start_time(),
    );
    h.outbox.enqueue(other_tenant, &theirs).await.unwrap();
    // A kind without an override uses the default even for the overriding tenant.
    let recovery = h.email("c@example.test", "recovery", "https://id.test/r");
    h.outbox.enqueue(h.tenant, &recovery).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 3);
    let sent = h.transport.sent();
    assert_eq!(sent[0].subject, "Custom Acme subject");
    assert_eq!(sent[0].text, "Custom text https://id.test/v?token=t1");
    assert!(sent[0].html.starts_with("<p>a@example.test</p>"));
    assert!(sent[1].subject.starts_with("Confirm your email address"));
    assert!(sent[2].subject.starts_with("Reset your"));
}

#[tokio::test]
async fn broken_override_fails_the_row_with_backoff() {
    let h = harness(CapturingTransport::default());
    h.outbox
        .put_template(
            h.tenant,
            &EmailTemplate {
                kind: EmailKind::Recovery,
                subject: "S".into(),
                body_html: "x".into(),
                body_text: "{{ link }}\n{{ nope }}".into(),
                updated_at: start_time(),
            },
        )
        .await
        .unwrap();
    let e = h.email(
        "a@example.test",
        "recovery",
        "https://id.test/r?token=secret-r",
    );
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    let row = h.outbox.row(e.id);
    let err = row.last_error.unwrap();
    assert!(err.contains("recovery.txt:2"), "{err}");
    assert!(!err.contains("secret-r"), "{err}");
    assert_eq!(row.next_attempt_at, start_time() + Duration::from_secs(30));
    assert_eq!(h.transport.calls(), 0);
}

#[tokio::test]
async fn tenant_smtp_settings_route_mail_through_the_tenant_transport() {
    let h = harness(CapturingTransport::default());
    let settings = tenant_smtp("Acme <noreply@acme.example>");
    h.outbox.put_smtp(h.tenant, &settings).await.unwrap();
    let mine = h.email("a@example.test", "verification", "https://id.test/v");
    h.outbox.enqueue(h.tenant, &mine).await.unwrap();
    let other_tenant = TenantId::new_v7();
    let theirs = new_email(
        &h.kek,
        other_tenant,
        "b@example.test",
        "verification",
        "https://id.test/v",
        start_time(),
    );
    h.outbox.enqueue(other_tenant, &theirs).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 2);

    let requests = h.factory.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, h.tenant);
    assert_eq!(requests[0].1, settings);
    let via_tenant = h.factory.for_tenant(h.tenant).sent();
    assert_eq!(via_tenant.len(), 1);
    assert_eq!(via_tenant[0].to, "a@example.test");
    assert_eq!(via_tenant[0].from, "Acme <noreply@acme.example>");
    // The other tenant has no settings: the installation transport and sender.
    let via_installation = h.transport.sent();
    assert_eq!(via_installation.len(), 1);
    assert_eq!(via_installation[0].to, "b@example.test");
    assert_eq!(via_installation[0].from, FROM);
    assert!(h.factory.evicted.lock().unwrap().contains(&other_tenant));
}

#[tokio::test]
async fn without_any_smtp_the_row_fails_with_backoff() {
    let h = harness_with(None);
    let e = h.email(
        "a@example.test",
        "verification",
        "https://id.test/v?token=nosmtp",
    );
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 0);
    let row = h.outbox.row(e.id);
    assert_eq!(row.last_error.as_deref(), Some(NO_SMTP_ERROR));
    assert_eq!(row.attempts, 1);
    assert_eq!(row.sent_at, None);
    assert_eq!(row.next_attempt_at, start_time() + Duration::from_secs(30));
    assert_eq!(h.transport.calls(), 0);

    // Once the tenant configures SMTP the retry goes through its transport.
    h.outbox
        .put_smtp(h.tenant, &tenant_smtp("noreply@acme.example"))
        .await
        .unwrap();
    h.clock.advance(Duration::from_secs(30));
    assert_eq!(h.worker.run_once().await.unwrap(), 1);
    assert_eq!(h.factory.for_tenant(h.tenant).sent().len(), 1);
    assert!(h.outbox.row(e.id).sent_at.is_some());
}

#[tokio::test]
async fn production_factory_opens_the_sealed_password_and_caches_by_updated_at() {
    let kek = Arc::new(Kek::generate());
    let tenant = TenantId::new_v7();
    let mut settings = tenant_smtp("noreply@acme.example");
    settings.password_enc = Some(
        seal_smtp_password(&kek, tenant, &SecretString::from("factory-pw".to_owned())).unwrap(),
    );
    let factory = SmtpTransportFactory::new(kek.clone());

    let a = factory.transport(tenant, &settings).unwrap();
    let b = factory.transport(tenant, &settings).unwrap();
    assert!(Arc::ptr_eq(&a, &b), "cached while updated_at is unchanged");
    settings.updated_at += Duration::from_secs(1);
    let c = factory.transport(tenant, &settings).unwrap();
    assert!(!Arc::ptr_eq(&a, &c), "rebuilt after an update");
    factory.evict(tenant);
    let d = factory.transport(tenant, &settings).unwrap();
    assert!(!Arc::ptr_eq(&c, &d), "rebuilt after eviction");

    // Sealed for another tenant (AAD mismatch) or with another KEK: refused, generically.
    let other = SmtpTransportFactory::new(Arc::new(Kek::generate()));
    let err = other
        .transport(tenant, &settings)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("could not be decrypted"), "{err}");
    assert!(!err.contains("factory-pw"));
    let err = factory
        .transport(TenantId::new_v7(), &settings)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("could not be decrypted"), "{err}");
}

#[tokio::test]
async fn missing_email_variable_is_filled_from_the_recipient() {
    let h = harness(CapturingTransport::default());
    // The password_changed notice of a recovery is sealed before the address is known, so its
    // payload has no `email`; the worker supplies the row's recipient.
    let notice = std::collections::BTreeMap::from([("tenant_name".to_owned(), "Acme".to_owned())]);
    let e = email_with_payload(
        &h.kek,
        h.tenant,
        "alice@example.test",
        "password_changed",
        &notice,
        start_time(),
    );
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 1);
    let sent = h.transport.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, "alice@example.test");
    assert!(
        sent[0]
            .text
            .contains("The password for alice@example.test at Acme")
    );
    assert!(sent[0].html.contains("alice@example.test"));
    assert!(h.outbox.row(e.id).sent_at.is_some());
}

#[tokio::test]
async fn payload_email_variable_is_never_overridden_by_the_recipient() {
    let h = harness(CapturingTransport::default());
    let e = email_with_payload(
        &h.kek,
        h.tenant,
        "row-recipient@example.test",
        "password_changed",
        &payload("payload-address@example.test", "https://id.test/unused"),
        start_time(),
    );
    h.outbox.enqueue(h.tenant, &e).await.unwrap();

    assert_eq!(h.worker.run_once().await.unwrap(), 1);
    let sent = h.transport.sent();
    assert_eq!(sent[0].to, "row-recipient@example.test");
    assert!(sent[0].text.contains("payload-address@example.test"));
    assert!(!sent[0].text.contains("row-recipient@example.test"));
}
