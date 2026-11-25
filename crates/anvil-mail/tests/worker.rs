//! Outbox worker semantics: send, backoff, give-up and render failures.

mod support;

use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::TenantId;
use anvil_core::ports::{Clock, OutboxRepo};
use anvil_mail::worker::MAX_ATTEMPTS;
use anvil_mail::{EmailRenderer, OutboxWorker};
use support::{CapturingTransport, MemOutbox, TestClock, new_email, start_time};

const FROM: &str = "AnvilID <noreply@example.test>";

struct Harness {
    outbox: Arc<MemOutbox>,
    transport: Arc<CapturingTransport>,
    clock: Arc<TestClock>,
    worker: OutboxWorker,
}

fn harness(transport: CapturingTransport) -> Harness {
    let outbox = Arc::new(MemOutbox::default());
    let transport = Arc::new(transport);
    let clock = Arc::new(TestClock::new(start_time()));
    let worker = OutboxWorker {
        source: outbox.clone(),
        transport: transport.clone(),
        renderer: EmailRenderer::embedded(),
        clock: clock.clone(),
        from: FROM.to_owned(),
    };
    Harness {
        outbox,
        transport,
        clock,
        worker,
    }
}

#[tokio::test]
async fn sends_due_rows_and_marks_them_sent() {
    let h = harness(CapturingTransport::default());
    let tenant = TenantId::new_v7();
    let mut ids = Vec::new();
    for (to, template) in [
        ("a@example.test", "verification"),
        ("b@example.test", "recovery"),
        ("c@example.test", "password_changed"),
    ] {
        let e = new_email(to, template, "https://id.test/l?token=tok", start_time());
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
    let e = new_email("a@example.test", "recovery", link, start_time());
    h.outbox.enqueue(TenantId::new_v7(), &e).await.unwrap();

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
    let e = new_email(
        "a@example.test",
        "verification",
        "https://id.test/v",
        start_time(),
    );
    h.outbox.enqueue(TenantId::new_v7(), &e).await.unwrap();

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
    let tenant = TenantId::new_v7();
    let bad = new_email(
        "bad@example.test",
        "no_such_email",
        "https://id.test/x",
        start_time(),
    );
    h.outbox.enqueue(tenant, &bad).await.unwrap();
    for to in ["a@example.test", "b@example.test"] {
        let e = new_email(to, "verification", "https://id.test/v", start_time());
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
    let mut e = new_email(
        "a@example.test",
        "verification",
        "https://id.test/s3cret",
        start_time(),
    );
    e.payload.remove("tenant_name");
    h.outbox.enqueue(TenantId::new_v7(), &e).await.unwrap();

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
    let e = new_email(
        "a@example.test",
        "verification",
        "https://id.test/v",
        start_time(),
    );
    h.outbox.enqueue(TenantId::new_v7(), &e).await.unwrap();

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
