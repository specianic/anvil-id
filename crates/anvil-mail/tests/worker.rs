//! Outbox worker semantics: send, backoff, give-up, render failures and sealed payloads.

mod support;

use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::TenantId;
use anvil_core::ports::{Clock, OutboxRepo};
use anvil_jose::Kek;
use anvil_mail::worker::{MAX_ATTEMPTS, PAYLOAD_DECRYPT_ERROR};
use anvil_mail::{EmailRenderer, OutboxWorker};
use support::{
    CapturingTransport, MemOutbox, TestClock, email_with_payload, new_email, payload, start_time,
};

const FROM: &str = "AnvilID <noreply@example.test>";

struct Harness {
    outbox: Arc<MemOutbox>,
    transport: Arc<CapturingTransport>,
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
    let outbox = Arc::new(MemOutbox::default());
    let transport = Arc::new(transport);
    let clock = Arc::new(TestClock::new(start_time()));
    let kek = Arc::new(Kek::generate());
    let worker = OutboxWorker {
        source: outbox.clone(),
        transport: transport.clone(),
        renderer: EmailRenderer::embedded(),
        clock: clock.clone(),
        from: FROM.to_owned(),
        kek: kek.clone(),
    };
    Harness {
        outbox,
        transport,
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
