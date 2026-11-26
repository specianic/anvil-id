//! Webhooks (ADM-05) on the selected backend (`ANVILID_TEST_DB`), against a wiremock sink on
//! 127.0.0.1 reached through the development outbound policy.
//!
//! - `service_*`: the endpoint service (secret shown once and stored sealed, URL policy,
//!   rotation window, test send and redelivery audited) and the enqueue at the audit choke point
//!   (a lifecycle event enqueues exactly one delivery per enabled, subscribed endpoint; nothing
//!   for unsubscribed or disabled endpoints or failed actions).
//! - `worker_*`: the delivery worker (Standard Webhooks headers and signature, retry on the
//!   schedule with the same `webhook-id`, `Retry-After`, 410 disables, redirects are failures,
//!   give-up audited, both signatures during a rotation window, the delivery metric).

mod admin_support;
mod support;
mod webhook_support;

use std::time::Duration;

use admin_support::{API, admin_token, call};
use anvil_core::model::{
    AuditAction, AuditActor, AuditOutcome, DeliveryStatus, RequestContext, WebhookEndpointUpdate,
    WebhookEventType as W,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::audit::AuditService;
use anvil_core::service::webhook::WEBHOOK_ROTATION_GRACE;
use anvil_web::adapters::outbound::OutboundPolicy;
use anvil_web::observability::WEBHOOK_DELIVERIES_TOTAL;
use axum::http::Method;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use std::sync::Arc;
use support::TestApp;
use webhook_support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const USER_ID: &str = "0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a50";

/// Records a successful (or failed) audit event through the single audit choke point.
async fn emit(app: &'static TestApp, action: AuditAction, outcome: AuditOutcome) {
    AuditService {
        storage: app.storage_arc(),
        clock: Arc::new(AppClock(app)),
    }
    .record(
        tenant(app),
        AuditActor::admin("0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a99"),
        action,
        Some(USER_ID.to_owned()),
        outcome,
        &RequestContext::system(),
        anvil_core::model::AuditDetails::empty(),
    )
    .await
    .expect("audit record");
}

/// Creates a user through the management API (audited `user_created`).
async fn create_user(app: &TestApp) -> String {
    let token = admin_token(app, "admin:read admin:write").await;
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(&token),
        Some(json!({
            "email": "alice@example.com",
            "password": "correct horse battery staple",
            "email_verified": true,
            "claims": {"given_name": "Alice", "family_name": "Liddell"},
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let user: Value = serde_json::from_slice(&resp.body).expect("json");
    user["id"].as_str().expect("id").to_owned()
}

// ---------------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn service_create_returns_secret_once_and_stores_it_sealed() {
    let app = prod_app().await;
    let svc = service_with(app, &OutboundPolicy::default());
    let created = create(
        &svc,
        app,
        "crm",
        "https://hooks.example/in",
        &[W::UserCreated],
    )
    .await;
    let secret = created.secret.expose_secret().to_owned();
    assert!(secret.starts_with("whsec_"), "{secret}");
    // The stored row holds sealed bytes only.
    let stored = svc.get(tenant(app), created.endpoint.id).await.unwrap();
    assert_ne!(stored.secret_enc, secret.as_bytes());
    assert!(
        !stored
            .secret_enc
            .windows(secret.len())
            .any(|w| w == secret.as_bytes())
    );
    assert!(stored.previous_secret_enc.is_none());
    assert!(!format!("{stored:?}").contains(&secret));
    // The secret opens with the KEK for this endpoint only.
    let keys = svc.signing_keys(&stored).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(stored.events, vec![W::UserCreated]);
    // Duplicate names conflict.
    let dup = svc
        .create(
            tenant(app),
            input("crm", "https://hooks.example/other", &[W::UserCreated]),
            admin(),
            &RequestContext::system(),
        )
        .await;
    assert!(
        matches!(dup, Err(anvil_core::error::CoreError::Conflict(_))),
        "{dup:?}"
    );
    let events = audit(app, AuditAction::WebhookEndpointCreated).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].target.as_deref(),
        Some(created.endpoint.id.to_string().as_str())
    );
}

#[tokio::test]
async fn service_refuses_loopback_and_plain_http_in_production() {
    let app = prod_app().await;
    let svc = service_with(app, &OutboundPolicy::default());
    for url in [
        "http://127.0.0.1/hook",
        "https://127.0.0.1/hook",
        "http://hooks.example/hook",
        "https://user:pw@hooks.example/hook",
    ] {
        let err = svc
            .create(
                tenant(app),
                input("x", url, &[W::UserCreated]),
                admin(),
                &RequestContext::system(),
            )
            .await
            .expect_err(url);
        assert!(
            matches!(
                err,
                anvil_core::error::CoreError::Validation { field: "url", .. }
            ),
            "{url}: {err:?}"
        );
    }
    assert!(svc.list(tenant(app)).await.unwrap().is_empty());
    // Updates are checked by the same policy.
    let ok = create(
        &svc,
        app,
        "ok",
        "https://hooks.example/in",
        &[W::UserCreated],
    )
    .await;
    let err = svc
        .update(
            tenant(app),
            ok.endpoint.id,
            WebhookEndpointUpdate {
                url: Some("https://10.1.2.3/in".into()),
                ..WebhookEndpointUpdate::default()
            },
            admin(),
            &RequestContext::system(),
        )
        .await
        .expect_err("private literal");
    assert!(matches!(
        err,
        anvil_core::error::CoreError::Validation { field: "url", .. }
    ));
}

#[tokio::test]
async fn service_user_created_via_admin_api_enqueues_one_delivery() {
    let app = prod_app().await;
    let svc = service_with(app, &OutboundPolicy::default());
    let subscribed = create(
        &svc,
        app,
        "crm",
        "https://hooks.example/a",
        &[W::UserCreated],
    )
    .await;
    let other = create(
        &svc,
        app,
        "other",
        "https://hooks.example/b",
        &[W::SessionCreated],
    )
    .await;
    let off = create(
        &svc,
        app,
        "off",
        "https://hooks.example/c",
        &[W::UserCreated],
    )
    .await;
    svc.update(
        tenant(app),
        off.endpoint.id,
        WebhookEndpointUpdate {
            enabled: Some(false),
            ..WebhookEndpointUpdate::default()
        },
        admin(),
        &RequestContext::system(),
    )
    .await
    .unwrap();

    let user_id = create_user(app).await;

    let rows = deliveries(app, subscribed.endpoint.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_type, W::UserCreated);
    assert_eq!(rows[0].status, DeliveryStatus::Pending);
    assert_eq!(rows[0].attempts, 0);
    let payload: Value = serde_json::from_str(&rows[0].payload_json).unwrap();
    assert_eq!(payload["type"], "user.created");
    assert_eq!(payload["data"]["user_id"], user_id.as_str());
    assert_eq!(payload["data"]["tenant"], tenant(app).to_string());
    assert!(deliveries(app, other.endpoint.id).await.is_empty());
    assert!(deliveries(app, off.endpoint.id).await.is_empty());
}

#[tokio::test]
async fn service_failed_or_non_lifecycle_events_enqueue_nothing() {
    let app = prod_app().await;
    let svc = service_with(app, &OutboundPolicy::default());
    let all = [
        W::UserCreated,
        W::UserUpdated,
        W::UserDeleted,
        W::UserEmailVerified,
        W::UserEmailChanged,
        W::UserPasswordChanged,
        W::SessionCreated,
        W::SessionRevoked,
        W::SessionLoggedOut,
    ];
    let ep = create(&svc, app, "all", "https://hooks.example/a", &all).await;
    emit(app, AuditAction::LoginFailed, AuditOutcome::Failure).await;
    emit(app, AuditAction::LoginSucceeded, AuditOutcome::Failure).await;
    emit(app, AuditAction::ClientCreated, AuditOutcome::Success).await;
    assert!(deliveries(app, ep.endpoint.id).await.is_empty());
    // A successful lifecycle event does enqueue (positive control).
    emit(app, AuditAction::LoginSucceeded, AuditOutcome::Success).await;
    let rows = deliveries(app, ep.endpoint.id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, W::SessionCreated);
}

#[tokio::test]
async fn service_rotate_returns_new_secret_and_keeps_previous_for_24h() {
    let app = prod_app().await;
    let svc = service_with(app, &OutboundPolicy::default());
    let created = create(
        &svc,
        app,
        "crm",
        "https://hooks.example/a",
        &[W::UserCreated],
    )
    .await;
    let rotated = svc
        .rotate_secret(
            tenant(app),
            created.endpoint.id,
            admin(),
            &RequestContext::system(),
        )
        .await
        .unwrap();
    assert!(rotated.secret.expose_secret().starts_with("whsec_"));
    assert_ne!(
        rotated.secret.expose_secret(),
        created.secret.expose_secret()
    );
    let ep = rotated.endpoint;
    assert!(ep.previous_secret_enc.is_some());
    assert_eq!(
        ep.previous_secret_expires_at,
        Some(app.clock().now() + WEBHOOK_ROTATION_GRACE)
    );
    assert_eq!(svc.signing_keys(&ep).unwrap().len(), 2);
    app.clock().advance(Duration::from_secs(24 * 3600));
    assert_eq!(svc.signing_keys(&ep).unwrap().len(), 1);
    let events = audit(app, AuditAction::WebhookSecretRotated).await;
    assert_eq!(events.len(), 1);
    let text = format!("{:?}", events[0]);
    assert!(!text.contains(rotated.secret.expose_secret()));
    assert!(!text.contains(created.secret.expose_secret()));
}

#[tokio::test]
async fn service_test_send_and_redeliver_are_audited() {
    let app = prod_app().await;
    let svc = service_with(app, &OutboundPolicy::default());
    // Subscribed to nothing that happens here: the test event ignores subscriptions.
    let ep = create(
        &svc,
        app,
        "crm",
        "https://hooks.example/a",
        &[W::UserDeleted],
    )
    .await;
    let test = svc
        .send_test(
            tenant(app),
            ep.endpoint.id,
            admin(),
            &RequestContext::system(),
        )
        .await
        .unwrap();
    assert_eq!(test.event_type, W::Test);
    assert_eq!(test.status, DeliveryStatus::Pending);
    let payload: Value = serde_json::from_str(&test.payload_json).unwrap();
    assert_eq!(payload["type"], "test");
    assert_eq!(audit(app, AuditAction::WebhookTestSent).await.len(), 1);

    let again = svc
        .redeliver(tenant(app), test.id, admin(), &RequestContext::system())
        .await
        .unwrap();
    assert_ne!(again.id, test.id);
    assert_eq!(again.payload_json, test.payload_json);
    let events = audit(app, AuditAction::WebhookRedelivered).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].details.as_map()["delivery_id"],
        Value::from(again.id.to_string())
    );
    assert_eq!(deliveries(app, ep.endpoint.id).await.len(), 2);

    // Unknown ids are NotFound and audit nothing.
    let missing = svc
        .redeliver(
            tenant(app),
            anvil_core::model::WebhookDeliveryId::new_v7(),
            admin(),
            &RequestContext::system(),
        )
        .await;
    assert!(matches!(
        missing,
        Err(anvil_core::error::CoreError::NotFound)
    ));
    assert_eq!(audit(app, AuditAction::WebhookRedelivered).await.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn worker_delivers_signed_request_once() {
    let app = prod_app().await;
    let server = sink(200).await;
    let created = create(
        &dev_service(app),
        app,
        "crm",
        &hook_url(&server),
        &[W::UserCreated],
    )
    .await;
    let key = format!("{WEBHOOK_DELIVERIES_TOTAL}{{outcome=\"delivered\"}}");
    let before = capture::capture().value(&key);
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;

    let report = dev_worker(app).run_once().await.unwrap();
    assert_eq!((report.claimed, report.delivered), (1, 1), "{report:?}");
    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    let row = &deliveries(app, created.endpoint.id).await[0];
    assert_eq!(header(req, "webhook-id"), row.id.to_string());
    assert_eq!(
        header(req, "webhook-timestamp"),
        app.clock().now().unix_timestamp().to_string()
    );
    assert_eq!(header(req, "content-type"), "application/json");
    assert_eq!(signatures(req).len(), 1);
    assert!(verified_by(req, &created.secret), "signature verifies");
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["type"], "user.created");
    assert_eq!(row.status, DeliveryStatus::Delivered);
    assert_eq!(row.last_http_status, Some(200));
    assert_eq!(row.attempts, 1);
    assert!(capture::capture().value(&key) > before, "metric counted");

    // Nothing left: a second run claims nothing and sends nothing.
    app.clock().advance(Duration::from_secs(3600));
    assert_eq!(dev_worker(app).run_once().await.unwrap().claimed, 0);
    assert_eq!(received(&server).await.len(), 1);
}

#[tokio::test]
async fn worker_retries_5xx_on_schedule_with_same_id() {
    let app = prod_app().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(HOOK))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(HOOK))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let created = create(
        &dev_service(app),
        app,
        "crm",
        &hook_url(&server),
        &[W::UserCreated],
    )
    .await;
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;
    let worker = dev_worker(app);
    let first = app.clock().now();
    assert_eq!(worker.run_once().await.unwrap().retried, 1);
    let row = &deliveries(app, created.endpoint.id).await[0];
    assert_eq!(row.status, DeliveryStatus::Pending);
    assert_eq!(row.last_http_status, Some(500));
    assert_eq!(row.last_error.as_deref(), Some("status_5xx"));
    // Second schedule step: 5 s plus at most 10 % jitter.
    assert!(row.next_attempt_at >= first + time::Duration::seconds(5));
    assert!(row.next_attempt_at <= first + time::Duration::milliseconds(5500));
    // Not due yet.
    app.clock().advance(Duration::from_secs(4));
    assert_eq!(worker.run_once().await.unwrap().claimed, 0);
    app.clock().advance(Duration::from_secs(2));
    assert_eq!(worker.run_once().await.unwrap().delivered, 1);
    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        header(&reqs[0], "webhook-id"),
        header(&reqs[1], "webhook-id")
    );
    assert_ne!(
        header(&reqs[0], "webhook-timestamp"),
        header(&reqs[1], "webhook-timestamp"),
        "signed at send time"
    );
    assert!(verified_by(&reqs[1], &created.secret));
    let row = &deliveries(app, created.endpoint.id).await[0];
    assert_eq!((row.status, row.attempts), (DeliveryStatus::Delivered, 2));
}

#[tokio::test]
async fn worker_honours_retry_after_on_429() {
    let app = prod_app().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(HOOK))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
        .mount(&server)
        .await;
    let created = create(
        &dev_service(app),
        app,
        "crm",
        &hook_url(&server),
        &[W::UserCreated],
    )
    .await;
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;
    let start = app.clock().now();
    let worker = dev_worker(app);
    assert_eq!(worker.run_once().await.unwrap().retried, 1);
    let row = &deliveries(app, created.endpoint.id).await[0];
    assert_eq!(row.next_attempt_at, start + time::Duration::seconds(60));
    assert_eq!(row.last_error.as_deref(), Some("status_429"));
    app.clock().advance(Duration::from_secs(30));
    assert_eq!(worker.run_once().await.unwrap().claimed, 0);
    app.clock().advance(Duration::from_secs(31));
    assert_eq!(worker.run_once().await.unwrap().claimed, 1);
}

#[tokio::test]
async fn worker_410_disables_endpoint_and_audits() {
    let app = prod_app().await;
    let server = sink(410).await;
    let created = create(
        &dev_service(app),
        app,
        "crm",
        &hook_url(&server),
        &[W::UserCreated],
    )
    .await;
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;
    let worker = dev_worker(app);
    assert_eq!(worker.run_once().await.unwrap().disabled, 1);
    let row = &deliveries(app, created.endpoint.id).await[0];
    assert_eq!(row.status, DeliveryStatus::Failed);
    assert_eq!(row.last_http_status, Some(410));
    let ep = app
        .storage()
        .webhooks()
        .get_endpoint(tenant(app), created.endpoint.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!ep.enabled);
    assert_eq!(ep.disabled_reason.as_deref(), Some("gone"));
    let events = audit(app, AuditAction::WebhookEndpointDisabled).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].target.as_deref(),
        Some(created.endpoint.id.to_string().as_str())
    );
    assert_eq!(events[0].actor.kind, anvil_core::model::ActorKind::System);
    // No further attempts: new events for a disabled endpoint are not even enqueued.
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;
    app.clock().advance(Duration::from_secs(3600));
    assert_eq!(worker.run_once().await.unwrap().claimed, 0);
    assert_eq!(received(&server).await.len(), 1);
}

#[tokio::test]
async fn worker_redirect_is_a_failure_and_retried() {
    let app = prod_app().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(HOOK))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/elsewhere"))
        .mount(&server)
        .await;
    let created = create(
        &dev_service(app),
        app,
        "crm",
        &hook_url(&server),
        &[W::UserCreated],
    )
    .await;
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;
    assert_eq!(dev_worker(app).run_once().await.unwrap().retried, 1);
    let row = &deliveries(app, created.endpoint.id).await[0];
    assert_eq!(row.status, DeliveryStatus::Pending);
    assert_eq!(row.last_http_status, Some(302));
    assert_eq!(row.last_error.as_deref(), Some("redirect"));
    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].url.path(), HOOK);
}

#[tokio::test]
async fn worker_gives_up_after_schedule_and_audits() {
    let app = prod_app().await;
    let server = sink(503).await;
    let created = create(
        &dev_service(app),
        app,
        "crm",
        &hook_url(&server),
        &[W::UserCreated],
    )
    .await;
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;
    let worker = dev_worker(app);
    for attempt in 1..=10u32 {
        let report = worker.run_once().await.unwrap();
        assert_eq!(report.claimed, 1, "attempt {attempt}");
        if attempt < 10 {
            assert_eq!(report.retried, 1, "attempt {attempt}");
            assert!(
                audit(app, AuditAction::WebhookDeliveryFailed)
                    .await
                    .is_empty()
            );
        } else {
            assert_eq!(report.failed, 1);
        }
        // Past the longest step plus jitter (24 h + 10 %).
        app.clock().advance(Duration::from_secs(27 * 3600));
    }
    let row = &deliveries(app, created.endpoint.id).await[0];
    assert_eq!((row.status, row.attempts), (DeliveryStatus::Failed, 10));
    assert_eq!(row.last_error.as_deref(), Some("status_5xx"));
    assert!(row.completed_at.is_some());
    assert_eq!(worker.run_once().await.unwrap().claimed, 0);
    assert_eq!(received(&server).await.len(), 10);
    let events = audit(app, AuditAction::WebhookDeliveryFailed).await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.outcome, AuditOutcome::Failure);
    let d = e.details.as_map();
    assert_eq!(d["delivery_id"], Value::from(row.id.to_string()));
    assert_eq!(d["attempts"], Value::from(10));
    assert_eq!(d["error_class"], "status_5xx");
    assert_eq!(d["endpoint"], "crm");
}

#[tokio::test]
async fn worker_signs_with_both_secrets_during_rotation_window() {
    let app = prod_app().await;
    let server = sink(204).await;
    let svc = dev_service(app);
    let created = create(&svc, app, "crm", &hook_url(&server), &[W::UserCreated]).await;
    let rotated = svc
        .rotate_secret(
            tenant(app),
            created.endpoint.id,
            admin(),
            &RequestContext::system(),
        )
        .await
        .unwrap();
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;
    let worker = dev_worker(app);
    assert_eq!(worker.run_once().await.unwrap().delivered, 1);
    let req = &received(&server).await[0];
    let sigs = signatures(req);
    assert_eq!(sigs.len(), 2, "{sigs:?}");
    let id = header(req, "webhook-id");
    let ts: i64 = header(req, "webhook-timestamp").parse().unwrap();
    assert!(
        signs(&rotated.secret, &sigs[0], id, ts, &req.body),
        "new first"
    );
    assert!(
        signs(&created.secret, &sigs[1], id, ts, &req.body),
        "previous second"
    );

    // After the window only the new secret signs.
    app.clock().advance(Duration::from_secs(24 * 3600 + 1));
    emit(app, AuditAction::UserCreated, AuditOutcome::Success).await;
    assert_eq!(worker.run_once().await.unwrap().delivered, 1);
    let reqs = received(&server).await;
    let last = &reqs[1];
    assert_eq!(signatures(last).len(), 1);
    assert!(verified_by(last, &rotated.secret));
    assert!(!verified_by(last, &created.secret));
}
