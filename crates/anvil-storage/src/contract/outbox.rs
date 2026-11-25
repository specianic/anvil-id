//! OutboxRepo contract.

use anvil_core::model::OutboxId;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn outbox_enqueue_claim_mark_sent(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let outbox = s.storage.outbox();
    let email = new_email("ada@example.test");
    outbox.enqueue(tenant, &email).await.expect("enqueue");

    let now = now_ms();
    let claimed = outbox.claim_due(now, 10, LEASE).await.expect("claim_due");
    assert_eq!(claimed.len(), 1);
    let got = &claimed[0];
    assert_eq!(got.id, email.id);
    assert_eq!(got.tenant_id, tenant);
    assert_eq!(got.to, email.to);
    assert_eq!(got.template, email.template);
    assert_eq!(got.payload, email.payload);
    assert_eq!(got.created_at, email.created_at);
    assert_eq!(got.expires_at, email.expires_at);
    assert_eq!(got.attempts, 1, "claiming counts an attempt");
    assert_eq!(
        got.next_attempt_at,
        now + LEASE,
        "claiming leases the email"
    );
    assert_eq!(got.sent_at, None);
    assert_eq!(got.last_error, None);

    assert!(outbox.mark_sent(email.id, now).await.expect("mark_sent"));
    assert!(
        outbox
            .claim_due(now + LEASE + Duration::seconds(1), 10, LEASE)
            .await
            .expect("claim_due")
            .is_empty(),
        "a sent email is never claimed again"
    );
    assert!(
        !outbox
            .mark_sent(OutboxId::new_v7(), now)
            .await
            .expect("mark_sent")
    );
    assert!(
        !outbox
            .mark_failed(OutboxId::new_v7(), "x", now)
            .await
            .expect("mark_failed")
    );
}

pub async fn outbox_claim_lease_skips_claimed(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let outbox = s.storage.outbox();
    let mut ids = Vec::new();
    for i in 0..3 {
        let e = new_email(&format!("u{i}@example.test"));
        outbox.enqueue(tenant, &e).await.expect("enqueue");
        ids.push(e.id);
    }
    let now = now_ms();
    let first = outbox.claim_due(now, 2, LEASE).await.expect("claim_due");
    assert_eq!(
        first.iter().map(|e| e.id).collect::<Vec<_>>(),
        ids[..2],
        "claim_due must return the oldest emails first, up to limit"
    );
    let second = outbox.claim_due(now, 10, LEASE).await.expect("claim_due");
    assert_eq!(
        second.iter().map(|e| e.id).collect::<Vec<_>>(),
        ids[2..],
        "leased emails must be skipped"
    );
    assert!(
        outbox
            .claim_due(now, 10, LEASE)
            .await
            .expect("claim_due")
            .is_empty()
    );

    let after_lease = outbox
        .claim_due(now + LEASE, 10, LEASE)
        .await
        .expect("claim_due");
    let mut got: Vec<_> = after_lease.iter().map(|e| (e.id, e.attempts)).collect();
    got.sort();
    assert_eq!(
        got,
        ids.iter().map(|id| (*id, 2)).collect::<Vec<_>>(),
        "unsent emails become due again when the lease runs out"
    );
}

pub async fn outbox_mark_failed_reschedules(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let outbox = s.storage.outbox();
    let email = new_email("ada@example.test");
    outbox.enqueue(tenant, &email).await.expect("enqueue");
    let now = now_ms();
    outbox.claim_due(now, 10, LEASE).await.expect("claim_due");
    let retry_at = now + Duration::minutes(5);
    assert!(
        outbox
            .mark_failed(email.id, "smtp unavailable", retry_at)
            .await
            .expect("mark_failed")
    );
    assert!(
        outbox
            .claim_due(now + Duration::minutes(2), 10, LEASE)
            .await
            .expect("claim_due")
            .is_empty(),
        "a failed email waits until next_attempt_at"
    );
    let retried = outbox
        .claim_due(retry_at, 10, LEASE)
        .await
        .expect("claim_due");
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].last_error.as_deref(), Some("smtp unavailable"));
    assert_eq!(retried[0].attempts, 2);
}

pub async fn outbox_expired_not_claimed(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let outbox = s.storage.outbox();
    let mut email = new_email("ada@example.test");
    email.expires_at = email.created_at + Duration::minutes(1);
    outbox.enqueue(tenant, &email).await.expect("enqueue");
    assert!(
        outbox
            .claim_due(email.expires_at, 10, LEASE)
            .await
            .expect("claim_due")
            .is_empty(),
        "an expired email must not be claimed"
    );
}
