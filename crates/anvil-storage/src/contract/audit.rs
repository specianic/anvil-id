//! AuditRepo contract: append, filtered newest-first queries with a cursor, retention.

use std::collections::BTreeSet;

use anvil_core::model::{
    AuditAction, AuditEventId, AuditOutcome, AuditQuery, NewAuditEvent, TenantId,
};
use anvil_core::ports::StorageError;
use time::{Duration, OffsetDateTime};

use super::TestStorage;
use super::fixtures::*;

fn query(limit: u32) -> AuditQuery {
    AuditQuery {
        limit,
        ..AuditQuery::default()
    }
}

/// Appends `n` events one second apart (oldest first), alternating actions and outcomes.
async fn seed_events(
    s: &TestStorage,
    tenant: TenantId,
    n: usize,
    start: OffsetDateTime,
) -> Vec<NewAuditEvent> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let (action, outcome) = if i % 2 == 0 {
            (AuditAction::LoginSucceeded, AuditOutcome::Success)
        } else {
            (AuditAction::LoginFailed, AuditOutcome::Failure)
        };
        let e = new_audit_event(
            action,
            outcome,
            &format!("actor-{}", i % 3),
            &format!("target-{}", i % 4),
            start + Duration::seconds(i as i64),
        );
        s.storage
            .audit()
            .append(tenant, &e)
            .await
            .expect("append must succeed");
        out.push(e);
    }
    out
}

fn ids(events: &[anvil_core::model::AuditEvent]) -> Vec<AuditEventId> {
    events.iter().map(|e| e.id).collect()
}

pub async fn audit_append_and_query_newest_first(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let events = seed_events(s, tenant, 3, now_ms() - Duration::minutes(1)).await;
    let page = s
        .storage
        .audit()
        .query(tenant, &query(10))
        .await
        .expect("query");
    let expected: Vec<_> = events
        .iter()
        .rev()
        .map(|e| expected_audit_event(tenant, e))
        .collect();
    assert_eq!(
        page.items, expected,
        "newest first, every field round-trips"
    );
    assert_eq!(page.next_cursor, None);

    let err = s
        .storage
        .audit()
        .append(tenant, &events[0])
        .await
        .expect_err("a duplicate id must conflict");
    assert!(matches!(err, StorageError::Conflict(_)), "{err:?}");
}

pub async fn audit_query_filters(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let start = now_ms() - Duration::hours(1);
    let events = seed_events(s, tenant, 12, start).await;
    let audit = s.storage.audit();
    let expect = |pred: &dyn Fn(&NewAuditEvent) -> bool| -> Vec<AuditEventId> {
        events
            .iter()
            .rev()
            .filter(|e| pred(e))
            .map(|e| e.id)
            .collect()
    };

    let by_action = audit
        .query(
            tenant,
            &AuditQuery {
                action: Some(AuditAction::LoginFailed),
                ..query(50)
            },
        )
        .await
        .expect("query");
    assert_eq!(
        ids(&by_action.items),
        expect(&|e| e.action == AuditAction::LoginFailed)
    );

    let by_outcome = audit
        .query(
            tenant,
            &AuditQuery {
                outcome: Some(AuditOutcome::Success),
                ..query(50)
            },
        )
        .await
        .expect("query");
    assert_eq!(
        ids(&by_outcome.items),
        expect(&|e| e.outcome == AuditOutcome::Success)
    );

    let by_actor = audit
        .query(
            tenant,
            &AuditQuery {
                actor_id: Some("actor-1".into()),
                ..query(50)
            },
        )
        .await
        .expect("query");
    assert_eq!(
        ids(&by_actor.items),
        expect(&|e| e.actor.id.as_deref() == Some("actor-1"))
    );

    let by_target = audit
        .query(
            tenant,
            &AuditQuery {
                target: Some("target-2".into()),
                ..query(50)
            },
        )
        .await
        .expect("query");
    assert_eq!(
        ids(&by_target.items),
        expect(&|e| e.target.as_deref() == Some("target-2"))
    );

    let from = start + Duration::seconds(3);
    let to = start + Duration::seconds(7);
    let window = audit
        .query(
            tenant,
            &AuditQuery {
                from: Some(from),
                to: Some(to),
                ..query(50)
            },
        )
        .await
        .expect("query");
    assert_eq!(
        ids(&window.items),
        expect(&|e| e.at >= from && e.at < to),
        "from is inclusive, to exclusive"
    );

    let combined = audit
        .query(
            tenant,
            &AuditQuery {
                action: Some(AuditAction::LoginSucceeded),
                actor_id: Some("actor-0".into()),
                ..query(50)
            },
        )
        .await
        .expect("query");
    assert_eq!(
        ids(&combined.items),
        expect(&|e| e.action == AuditAction::LoginSucceeded
            && e.actor.id.as_deref() == Some("actor-0")),
        "filters combine with AND"
    );
}

pub async fn audit_cursor_pages_without_gaps(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let events = seed_events(s, tenant, 11, now_ms() - Duration::hours(1)).await;
    let audit = s.storage.audit();
    let mut seen = Vec::new();
    let mut before = None;
    loop {
        let page = audit
            .query(tenant, &AuditQuery { before, ..query(4) })
            .await
            .expect("query");
        assert!(page.items.len() <= 4, "limit respected");
        seen.extend(ids(&page.items));
        match page.next_cursor {
            Some(c) => {
                assert_eq!(Some(c), page.items.last().map(|e| e.id.0));
                before = Some(AuditEventId(c));
            }
            None => break,
        }
    }
    let expected: Vec<_> = events.iter().rev().map(|e| e.id).collect();
    assert_eq!(seen, expected, "pages cover every event once, newest first");
    assert_eq!(seen.iter().collect::<BTreeSet<_>>().len(), seen.len());
}

pub async fn audit_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    seed_events(s, tenant, 2, now_ms()).await;
    let page = s
        .storage
        .audit()
        .query(other, &query(50))
        .await
        .expect("query");
    assert!(
        page.items.is_empty(),
        "another tenant's events are invisible"
    );
}

pub async fn audit_purge_before_deletes_only_older(s: &TestStorage) {
    let a = seed_tenant(s).await;
    let b = seed_tenant(s).await;
    let now = now_ms();
    let old_a = seed_events(s, a, 2, now - Duration::days(400)).await;
    let old_b = seed_events(s, b, 1, now - Duration::days(400)).await;
    let recent_a = seed_events(s, a, 2, now - Duration::days(1)).await;
    let cutoff = now - Duration::days(365);
    let purged = s.storage.audit().purge_before(cutoff).await.expect("purge");
    assert_eq!(
        purged,
        (old_a.len() + old_b.len()) as u64,
        "installation-wide"
    );
    let left = s.storage.audit().query(a, &query(50)).await.expect("query");
    assert_eq!(
        ids(&left.items),
        recent_a.iter().rev().map(|e| e.id).collect::<Vec<_>>()
    );
    assert!(
        s.storage
            .audit()
            .query(b, &query(50))
            .await
            .expect("query")
            .items
            .is_empty()
    );
}
