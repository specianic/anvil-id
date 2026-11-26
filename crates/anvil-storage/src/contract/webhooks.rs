//! WebhookRepo contract: endpoints (per-tenant unique names, secret rotation, disabling), the
//! enqueue inside `AuditRepo::append` (same transaction, enabled and subscribed endpoints of the
//! event's tenant only), the leased delivery queue and its completion semantics.

use std::collections::HashSet;

use anvil_core::model::{
    AuditAction, AuditOutcome, DeliveryStatus, PageRequest, TenantId, WebhookDelivery,
    WebhookDeliveryId, WebhookEndpoint, WebhookEndpointId, WebhookEndpointUpdate, WebhookEventType,
    WebhookResult,
};
use anvil_core::ports::StorageError;
use time::{Duration, OffsetDateTime};

use super::TestStorage;
use super::fixtures::*;

const ALL_DELIVERIES: PageRequest = PageRequest {
    after: None,
    limit: PageRequest::MAX_LIMIT,
};

/// Every delivery of one endpoint, newest first.
async fn all_deliveries(
    s: &TestStorage,
    tenant: TenantId,
    endpoint: WebhookEndpointId,
) -> Vec<WebhookDelivery> {
    s.storage
        .webhooks()
        .deliveries(tenant, endpoint, ALL_DELIVERIES)
        .await
        .expect("deliveries")
        .items
}

/// An endpoint with `n` test deliveries due at `now`.
async fn seed_due(s: &TestStorage, n: usize, now: OffsetDateTime) -> (TenantId, WebhookEndpoint) {
    let tenant = seed_tenant(s).await;
    let endpoint = seed_endpoint(s, tenant, &[WebhookEventType::UserCreated]).await;
    for _ in 0..n {
        s.storage
            .webhooks()
            .enqueue_test(
                tenant,
                endpoint.id,
                &webhook_event(WebhookEventType::Test),
                now,
            )
            .await
            .expect("enqueue_test")
            .expect("endpoint exists");
    }
    (tenant, endpoint)
}

/// Appends an audit event carrying `webhook` (or none) at `at`.
async fn append_with(
    s: &TestStorage,
    tenant: TenantId,
    webhook: Option<WebhookEventType>,
    at: OffsetDateTime,
) -> anvil_core::model::NewAuditEvent {
    let mut event = new_audit_event(
        AuditAction::UserCreated,
        AuditOutcome::Success,
        "actor",
        "target",
        at,
    );
    event.webhook = webhook.map(webhook_event);
    s.storage
        .audit()
        .append(tenant, &event)
        .await
        .expect("append");
    event
}

pub async fn webhook_endpoint_crud_and_name_conflict(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.webhooks();
    let mut a = new_endpoint(&[
        WebhookEventType::UserCreated,
        WebhookEventType::SessionCreated,
    ]);
    a.name = "b-hook".to_owned();
    let mut b = new_endpoint(&[WebhookEventType::UserDeleted]);
    b.name = "a-hook".to_owned();
    b.enabled = false;
    let created_a = repo.create_endpoint(tenant, &a).await.expect("create");
    assert_eq!(created_a, expected_endpoint(tenant, &a));
    let created_b = repo.create_endpoint(tenant, &b).await.expect("create");
    assert_eq!(created_b, expected_endpoint(tenant, &b));
    assert_eq!(
        repo.get_endpoint(tenant, a.id).await.expect("get"),
        Some(created_a.clone())
    );
    assert_eq!(
        repo.get_endpoint(tenant, WebhookEndpointId::new_v7())
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        repo.list_endpoints(tenant).await.expect("list"),
        vec![created_b.clone(), created_a.clone()],
        "name order"
    );

    let mut dup = new_endpoint(&[WebhookEventType::UserCreated]);
    dup.name = a.name.clone();
    assert!(matches!(
        repo.create_endpoint(tenant, &dup).await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(repo.get_endpoint(tenant, dup.id).await.expect("get"), None);
    // The same name in another tenant is fine.
    let other = seed_tenant(s).await;
    repo.create_endpoint(other, &dup)
        .await
        .expect("same name in another tenant");

    let later = a.created_at + Duration::seconds(5);
    let updated = repo
        .update_endpoint(
            tenant,
            a.id,
            &WebhookEndpointUpdate {
                name: Some("c-hook".to_owned()),
                url: Some("https://other.example.test/hook".to_owned()),
                events: Some(vec![WebhookEventType::UserUpdated]),
                enabled: Some(false),
            },
            later,
        )
        .await
        .expect("update")
        .expect("endpoint exists");
    assert_eq!(updated.name, "c-hook");
    assert_eq!(updated.url, "https://other.example.test/hook");
    assert_eq!(updated.events, vec![WebhookEventType::UserUpdated]);
    assert!(!updated.enabled);
    assert_eq!(
        updated.secret_enc, a.secret_enc,
        "update never touches the secret"
    );
    assert_eq!(updated.created_at, a.created_at);
    assert_eq!(updated.updated_at, later);
    assert_eq!(
        repo.get_endpoint(tenant, a.id).await.expect("get"),
        Some(updated.clone())
    );
    assert!(matches!(
        repo.update_endpoint(
            tenant,
            a.id,
            &WebhookEndpointUpdate {
                name: Some(b.name.clone()),
                ..WebhookEndpointUpdate::default()
            },
            later,
        )
        .await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(
        repo.update_endpoint(
            tenant,
            WebhookEndpointId::new_v7(),
            &WebhookEndpointUpdate::default(),
            later
        )
        .await
        .expect("update"),
        None
    );

    assert!(repo.delete_endpoint(tenant, a.id).await.expect("delete"));
    assert!(!repo.delete_endpoint(tenant, a.id).await.expect("delete"));
    assert_eq!(repo.get_endpoint(tenant, a.id).await.expect("get"), None);
    assert_eq!(
        repo.list_endpoints(tenant).await.expect("list"),
        vec![created_b]
    );
}

pub async fn webhook_rotate_secret_keeps_previous_with_expiry(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.webhooks();
    let endpoint = seed_endpoint(s, tenant, &[WebhookEventType::UserCreated]).await;
    let t1 = now_ms() + Duration::seconds(1);
    let expires1 = t1 + Duration::hours(24);
    let second = b"second-sealed-secret".to_vec();
    assert!(
        repo.rotate_secret(tenant, endpoint.id, &second, expires1, t1)
            .await
            .expect("rotate")
    );
    let rotated = repo
        .get_endpoint(tenant, endpoint.id)
        .await
        .expect("get")
        .expect("endpoint exists");
    assert_eq!(rotated.secret_enc, second);
    assert_eq!(
        rotated.previous_secret_enc,
        Some(endpoint.secret_enc.clone())
    );
    assert_eq!(rotated.previous_secret_expires_at, Some(expires1));
    assert_eq!(rotated.updated_at, t1);

    // A second rotation replaces the older previous secret.
    let t2 = t1 + Duration::seconds(1);
    let expires2 = t2 + Duration::hours(1);
    let third = b"third-sealed-secret".to_vec();
    assert!(
        repo.rotate_secret(tenant, endpoint.id, &third, expires2, t2)
            .await
            .expect("rotate")
    );
    let again = repo
        .get_endpoint(tenant, endpoint.id)
        .await
        .expect("get")
        .expect("endpoint exists");
    assert_eq!(again.secret_enc, third);
    assert_eq!(again.previous_secret_enc, Some(second));
    assert_eq!(again.previous_secret_expires_at, Some(expires2));

    assert!(
        !repo
            .rotate_secret(tenant, WebhookEndpointId::new_v7(), &third, expires2, t2)
            .await
            .expect("rotate")
    );
}

pub async fn webhook_disable_and_reenable_endpoint(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.webhooks();
    let endpoint = seed_endpoint(s, tenant, &[WebhookEventType::UserCreated]).await;
    let t1 = now_ms() + Duration::seconds(1);
    assert!(
        repo.disable_endpoint(tenant, endpoint.id, "gone", t1)
            .await
            .expect("disable")
    );
    let disabled = repo
        .get_endpoint(tenant, endpoint.id)
        .await
        .expect("get")
        .expect("endpoint exists");
    assert!(!disabled.enabled);
    assert_eq!(disabled.disabled_reason.as_deref(), Some("gone"));
    assert_eq!(disabled.updated_at, t1);

    let reenabled = repo
        .update_endpoint(
            tenant,
            endpoint.id,
            &WebhookEndpointUpdate {
                enabled: Some(true),
                ..WebhookEndpointUpdate::default()
            },
            t1 + Duration::seconds(1),
        )
        .await
        .expect("update")
        .expect("endpoint exists");
    assert!(reenabled.enabled);
    assert_eq!(
        reenabled.disabled_reason, None,
        "re-enabling clears the reason"
    );
    assert!(
        !repo
            .disable_endpoint(tenant, WebhookEndpointId::new_v7(), "gone", t1)
            .await
            .expect("disable")
    );
}

pub async fn webhook_append_enqueues_subscribed_endpoints(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.webhooks();
    let only_users = seed_endpoint(s, tenant, &[WebhookEventType::UserCreated]).await;
    let both = seed_endpoint(
        s,
        tenant,
        &[
            WebhookEventType::SessionCreated,
            WebhookEventType::UserCreated,
        ],
    )
    .await;
    let unsubscribed = seed_endpoint(s, tenant, &[WebhookEventType::SessionCreated]).await;
    let disabled = seed_endpoint(s, tenant, &[WebhookEventType::UserCreated]).await;
    assert!(
        repo.disable_endpoint(tenant, disabled.id, "manual", now_ms())
            .await
            .expect("disable")
    );
    let foreign = seed_endpoint(s, other, &[WebhookEventType::UserCreated]).await;

    let at = now_ms();
    let event = append_with(s, tenant, Some(WebhookEventType::UserCreated), at).await;
    let payload = event
        .webhook
        .as_ref()
        .expect("webhook")
        .payload_json
        .clone();

    for endpoint in [&only_users, &both] {
        let d = all_deliveries(s, tenant, endpoint.id).await;
        assert_eq!(d.len(), 1, "exactly one delivery per subscribed endpoint");
        let d = &d[0];
        assert_eq!(d.tenant_id, tenant);
        assert_eq!(d.endpoint_id, endpoint.id);
        assert_eq!(d.event_type, WebhookEventType::UserCreated);
        assert_eq!(d.payload_json, payload);
        assert_eq!(d.attempts, 0);
        assert_eq!(d.status, DeliveryStatus::Pending);
        assert_eq!(d.next_attempt_at, at);
        assert_eq!(d.created_at, at);
        assert_eq!(d.last_http_status, None);
        assert_eq!(d.last_error, None);
        assert_eq!(d.completed_at, None);
    }
    assert_ne!(
        all_deliveries(s, tenant, only_users.id).await[0].id,
        all_deliveries(s, tenant, both.id).await[0].id,
        "every delivery has its own id"
    );
    assert!(all_deliveries(s, tenant, unsubscribed.id).await.is_empty());
    assert!(all_deliveries(s, tenant, disabled.id).await.is_empty());
    assert!(all_deliveries(s, other, foreign.id).await.is_empty());

    // No webhook payload: nothing is enqueued, even for subscribed endpoints.
    append_with(s, tenant, None, now_ms()).await;
    assert_eq!(all_deliveries(s, tenant, only_users.id).await.len(), 1);
    assert_eq!(all_deliveries(s, tenant, both.id).await.len(), 1);

    // A rejected append (duplicate id) enqueues nothing: same transaction.
    assert!(matches!(
        s.storage.audit().append(tenant, &event).await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(all_deliveries(s, tenant, only_users.id).await.len(), 1);
}

pub async fn webhook_claim_leases_due_rows(s: &TestStorage) {
    let now = now_ms();
    let (tenant, endpoint) = seed_due(s, 2, now).await;
    let repo = s.storage.webhooks();
    // A delivery of a disabled endpoint is never claimed.
    let off = seed_endpoint(s, tenant, &[WebhookEventType::UserCreated]).await;
    repo.enqueue_test(tenant, off.id, &webhook_event(WebhookEventType::Test), now)
        .await
        .expect("enqueue_test")
        .expect("endpoint exists");
    assert!(
        repo.disable_endpoint(tenant, off.id, "manual", now)
            .await
            .expect("disable")
    );
    // Not yet due.
    repo.enqueue_test(
        tenant,
        endpoint.id,
        &webhook_event(WebhookEventType::Test),
        now + Duration::minutes(10),
    )
    .await
    .expect("enqueue_test")
    .expect("endpoint exists");

    let lease = now + Duration::seconds(60);
    let claimed = repo.claim_due(lease, now, 10).await.expect("claim");
    assert_eq!(claimed.len(), 2, "only due rows of enabled endpoints");
    for c in &claimed {
        assert_eq!(c.delivery.endpoint_id, endpoint.id);
        assert_eq!(c.delivery.next_attempt_at, lease, "leased");
        assert_eq!(c.delivery.attempts, 0, "claiming does not count an attempt");
        assert_eq!(c.endpoint.id, endpoint.id);
        assert_eq!(c.endpoint.url, endpoint.url);
        assert_eq!(c.endpoint.secret_enc, endpoint.secret_enc);
    }
    assert!(
        repo.claim_due(lease, now, 10)
            .await
            .expect("claim")
            .is_empty(),
        "leased rows are invisible until the lease ends"
    );
    let again = repo
        .claim_due(lease + Duration::seconds(60), lease, 10)
        .await
        .expect("claim");
    assert_eq!(
        again.len(),
        2,
        "an expired lease makes the rows claimable again"
    );

    let limited = repo
        .claim_due(now + Duration::hours(1), now + Duration::minutes(30), 1)
        .await
        .expect("claim");
    assert_eq!(limited.len(), 1, "limit is honoured");
}

pub async fn webhook_claim_concurrent_each_row_once(s: &TestStorage) {
    const ROWS: usize = 12;
    const CLAIMERS: usize = 8;
    let now = now_ms();
    let (tenant, endpoint) = seed_due(s, ROWS, now).await;
    let lease = now + Duration::seconds(60);
    let storage = s.storage.clone();
    let results = race(CLAIMERS, move |_| {
        let storage = storage.clone();
        async move { storage.webhooks().claim_due(lease, now, 3).await }
    })
    .await;
    let mut seen = HashSet::new();
    for r in results {
        for c in r.expect("no storage errors allowed") {
            assert!(seen.insert(c.delivery.id), "a row was claimed twice");
        }
    }
    let rest = s
        .storage
        .webhooks()
        .claim_due(lease, now, 100)
        .await
        .expect("claim");
    for c in rest {
        assert!(seen.insert(c.delivery.id), "a leased row was claimed again");
    }
    assert_eq!(seen.len(), ROWS, "every row claimed exactly once");
    assert_eq!(all_deliveries(s, tenant, endpoint.id).await.len(), ROWS);
}

pub async fn webhook_complete_semantics(s: &TestStorage) {
    let now = now_ms();
    let (tenant, endpoint) = seed_due(s, 3, now).await;
    let repo = s.storage.webhooks();
    let lease = now + Duration::seconds(60);
    let claimed = repo.claim_due(lease, now, 10).await.expect("claim");
    assert_eq!(claimed.len(), 3);
    let (delivered, retried, given_up) = (
        claimed[0].delivery.id,
        claimed[1].delivery.id,
        claimed[2].delivery.id,
    );
    let done_at = now + Duration::seconds(1);
    assert!(
        repo.complete(
            delivered,
            &WebhookResult::Delivered { http_status: 204 },
            done_at
        )
        .await
        .expect("complete")
    );
    let retry_at = now + Duration::minutes(5);
    assert!(
        repo.complete(
            retried,
            &WebhookResult::Retry {
                next_attempt_at: retry_at,
                http_status: Some(503),
                error_class: "status_5xx",
            },
            done_at,
        )
        .await
        .expect("complete")
    );
    assert!(
        repo.complete(
            given_up,
            &WebhookResult::GiveUp {
                http_status: None,
                error_class: "timeout",
            },
            done_at,
        )
        .await
        .expect("complete")
    );

    let by_id = |id: WebhookDeliveryId, all: &[WebhookDelivery]| {
        all.iter()
            .find(|d| d.id == id)
            .cloned()
            .expect("delivery listed")
    };
    let all = all_deliveries(s, tenant, endpoint.id).await;
    let d = by_id(delivered, &all);
    assert_eq!(d.status, DeliveryStatus::Delivered);
    assert_eq!(d.attempts, 1);
    assert_eq!(d.last_http_status, Some(204));
    assert_eq!(d.last_error, None);
    assert_eq!(d.completed_at, Some(done_at));
    let r = by_id(retried, &all);
    assert_eq!(r.status, DeliveryStatus::Pending);
    assert_eq!(r.attempts, 1);
    assert_eq!(r.next_attempt_at, retry_at);
    assert_eq!(r.last_http_status, Some(503));
    assert_eq!(r.last_error.as_deref(), Some("status_5xx"));
    assert_eq!(r.completed_at, None);
    let g = by_id(given_up, &all);
    assert_eq!(g.status, DeliveryStatus::Failed);
    assert_eq!(g.attempts, 1);
    assert_eq!(g.last_http_status, None);
    assert_eq!(g.last_error.as_deref(), Some("timeout"));
    assert_eq!(g.completed_at, Some(done_at));

    // Completed rows are final: never changed or claimed again.
    assert!(
        !repo
            .complete(
                delivered,
                &WebhookResult::Delivered { http_status: 200 },
                done_at
            )
            .await
            .expect("complete")
    );
    assert!(
        !repo
            .complete(
                given_up,
                &WebhookResult::Delivered { http_status: 200 },
                done_at
            )
            .await
            .expect("complete")
    );
    assert!(
        !repo
            .complete(
                WebhookDeliveryId::new_v7(),
                &WebhookResult::Delivered { http_status: 200 },
                done_at
            )
            .await
            .expect("complete")
    );
    let far = now + Duration::days(30);
    let reclaimed = repo
        .claim_due(far + Duration::seconds(60), far, 10)
        .await
        .expect("claim");
    assert_eq!(
        reclaimed.iter().map(|c| c.delivery.id).collect::<Vec<_>>(),
        vec![retried],
        "only the retried row comes back"
    );

    // 410 Gone: the delivery fails and the endpoint is disabled in the same transaction.
    assert!(
        repo.complete(
            retried,
            &WebhookResult::DisableEndpoint { http_status: 410 },
            far,
        )
        .await
        .expect("complete")
    );
    let gone = by_id(retried, &all_deliveries(s, tenant, endpoint.id).await);
    assert_eq!(gone.status, DeliveryStatus::Failed);
    assert_eq!(gone.attempts, 2);
    assert_eq!(gone.last_http_status, Some(410));
    assert_eq!(gone.last_error.as_deref(), Some("gone"));
    assert_eq!(gone.completed_at, Some(far));
    let ep = repo
        .get_endpoint(tenant, endpoint.id)
        .await
        .expect("get")
        .expect("endpoint exists");
    assert!(!ep.enabled);
    assert_eq!(ep.disabled_reason.as_deref(), Some("gone"));
}

pub async fn webhook_deliveries_listing_newest_first(s: &TestStorage) {
    let now = now_ms();
    let (tenant, endpoint) = seed_due(s, 5, now).await;
    let repo = s.storage.webhooks();
    let all = all_deliveries(s, tenant, endpoint.id).await;
    assert_eq!(all.len(), 5);
    let mut sorted = all.clone();
    sorted.sort_by_key(|d| std::cmp::Reverse(d.id.0));
    assert_eq!(all, sorted, "newest first");

    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = repo
            .deliveries(tenant, endpoint.id, PageRequest { after, limit: 2 })
            .await
            .expect("deliveries");
        assert!(page.items.len() <= 2);
        seen.extend(page.items.iter().cloned());
        match page.next_cursor {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    assert_eq!(seen, all, "pages without gaps or repeats");
    assert!(
        repo.deliveries(tenant, WebhookEndpointId::new_v7(), ALL_DELIVERIES)
            .await
            .expect("deliveries")
            .items
            .is_empty()
    );
}

pub async fn webhook_redeliver_and_enqueue_test(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.webhooks();
    // Not subscribed to `test`: a test send ignores subscriptions.
    let endpoint = seed_endpoint(s, tenant, &[WebhookEventType::UserDeleted]).await;
    let now = now_ms();
    let event = webhook_event(WebhookEventType::Test);
    let queued = repo
        .enqueue_test(tenant, endpoint.id, &event, now)
        .await
        .expect("enqueue_test")
        .expect("endpoint exists");
    assert_eq!(queued.tenant_id, tenant);
    assert_eq!(queued.endpoint_id, endpoint.id);
    assert_eq!(queued.event_type, WebhookEventType::Test);
    assert_eq!(queued.payload_json, event.payload_json);
    assert_eq!(queued.status, DeliveryStatus::Pending);
    assert_eq!(queued.attempts, 0);
    assert_eq!(queued.next_attempt_at, now);
    assert_eq!(queued.created_at, now);
    assert_eq!(
        repo.enqueue_test(tenant, WebhookEndpointId::new_v7(), &event, now)
            .await
            .expect("enqueue_test"),
        None
    );

    // Fail it for good, then redeliver: a new pending row, the original untouched.
    let claimed = repo
        .claim_due(now + Duration::seconds(60), now, 10)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert!(
        repo.complete(
            queued.id,
            &WebhookResult::GiveUp {
                http_status: Some(500),
                error_class: "status_5xx",
            },
            now,
        )
        .await
        .expect("complete")
    );
    let later = now + Duration::seconds(10);
    let again = repo
        .redeliver(tenant, queued.id, later)
        .await
        .expect("redeliver")
        .expect("delivery exists");
    assert_ne!(again.id, queued.id);
    assert_eq!(again.endpoint_id, endpoint.id);
    assert_eq!(again.event_type, queued.event_type);
    assert_eq!(again.payload_json, queued.payload_json);
    assert_eq!(again.status, DeliveryStatus::Pending);
    assert_eq!(again.attempts, 0);
    assert_eq!(again.next_attempt_at, later);
    assert_eq!(again.created_at, later);
    assert_eq!(again.completed_at, None);
    let all = all_deliveries(s, tenant, endpoint.id).await;
    assert_eq!(all.len(), 2);
    let original = all.iter().find(|d| d.id == queued.id).expect("original");
    assert_eq!(original.status, DeliveryStatus::Failed);
    assert_eq!(
        repo.redeliver(tenant, WebhookDeliveryId::new_v7(), later)
            .await
            .expect("redeliver"),
        None
    );
}

pub async fn webhook_delete_endpoint_cascades_deliveries(s: &TestStorage) {
    let now = now_ms();
    let (tenant, endpoint) = seed_due(s, 3, now).await;
    let repo = s.storage.webhooks();
    let keep = seed_endpoint(s, tenant, &[WebhookEventType::UserCreated]).await;
    repo.enqueue_test(tenant, keep.id, &webhook_event(WebhookEventType::Test), now)
        .await
        .expect("enqueue_test")
        .expect("endpoint exists");
    assert!(
        repo.delete_endpoint(tenant, endpoint.id)
            .await
            .expect("delete")
    );
    assert!(all_deliveries(s, tenant, endpoint.id).await.is_empty());
    let claimed = repo
        .claim_due(now + Duration::seconds(60), now, 10)
        .await
        .expect("claim");
    assert_eq!(
        claimed.iter().map(|c| c.endpoint.id).collect::<Vec<_>>(),
        vec![keep.id],
        "the deleted endpoint's deliveries are gone"
    );
}

pub async fn webhooks_isolated_by_tenant(s: &TestStorage) {
    let now = now_ms();
    let (tenant, endpoint) = seed_due(s, 1, now).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.webhooks();
    let delivery = all_deliveries(s, tenant, endpoint.id).await[0].clone();

    assert_eq!(
        repo.get_endpoint(other, endpoint.id).await.expect("get"),
        None
    );
    assert!(repo.list_endpoints(other).await.expect("list").is_empty());
    assert_eq!(
        repo.update_endpoint(
            other,
            endpoint.id,
            &WebhookEndpointUpdate {
                url: Some("https://attacker.example.test/".to_owned()),
                ..WebhookEndpointUpdate::default()
            },
            now,
        )
        .await
        .expect("update"),
        None
    );
    assert!(
        !repo
            .rotate_secret(other, endpoint.id, b"x", now, now)
            .await
            .expect("rotate")
    );
    assert!(
        !repo
            .disable_endpoint(other, endpoint.id, "gone", now)
            .await
            .expect("disable")
    );
    assert!(
        all_deliveries(s, other, endpoint.id).await.is_empty(),
        "another tenant cannot read the delivery log"
    );
    assert_eq!(
        repo.redeliver(other, delivery.id, now)
            .await
            .expect("redeliver"),
        None
    );
    assert_eq!(
        repo.enqueue_test(
            other,
            endpoint.id,
            &webhook_event(WebhookEventType::Test),
            now
        )
        .await
        .expect("enqueue_test"),
        None
    );
    assert!(
        !repo
            .delete_endpoint(other, endpoint.id)
            .await
            .expect("delete")
    );
    assert_eq!(
        repo.get_endpoint(tenant, endpoint.id).await.expect("get"),
        Some(endpoint)
    );
    assert_eq!(
        all_deliveries(s, tenant, delivery.endpoint_id).await,
        vec![delivery]
    );
}
