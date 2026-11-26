//! Webhook security controls (ADM-05, QUAL-01): SSRF at create and at send, the signing secret
//! is write-only (shown once, stored sealed, never in reads, logs or audit), payloads carry ids
//! only (Q4), signatures verify and fail on tampering, redirects are never followed.

mod admin_support;
mod support;
mod webhook_support;

use admin_support::{API, admin_token, call};
use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditAction, AuditQuery, DeliveryStatus, RequestContext, WebhookEndpointUpdate,
    WebhookEventType as W,
};
use anvil_core::ports::Clock as _;
use anvil_jose::webhook::{parse_webhook_secret, signature_v1};
use anvil_web::adapters::outbound::OutboundPolicy;
use axum::http::Method;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use webhook_support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const EMAIL: &str = "alice.private@example.com";
const GIVEN: &str = "Alicewonder";
const FAMILY: &str = "Liddellson";

#[tokio::test]
async fn webhook_url_private_ip_refused_at_create() {
    let app = prod_app().await;
    let svc = service_with(app, &OutboundPolicy::default());
    for url in [
        "https://127.0.0.1/hook",
        "https://10.0.0.5/hook",
        "https://192.168.1.10/hook",
        "https://172.16.0.1/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/hook",
        "https://[::ffff:10.0.0.1]/hook",
        "https://[fd00::1]/hook",
        "https://100.64.0.1/hook",
        // Plain http is refused outside development mode.
        "http://hooks.example/hook",
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
            matches!(err, CoreError::Validation { field: "url", .. }),
            "{url}: {err:?}"
        );
    }
    assert!(
        svc.list(tenant(app)).await.unwrap().is_empty(),
        "nothing stored"
    );
    assert!(
        audit(app, AuditAction::WebhookEndpointCreated)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn webhook_send_blocked_for_private_destination() {
    let app = prod_app().await;
    let server = sink(200).await;
    let port = server.address().port();
    // A host name passes the create-time check (it is resolved at send time) ...
    let svc = service_with(app, &OutboundPolicy::default());
    let by_name = create(
        &svc,
        app,
        "by-name",
        &format!("https://localhost:{port}{HOOK}"),
        &[W::UserCreated],
    )
    .await;
    // ... and a literal that was stored before the policy changed (written behind the
    // service's back, as if an allow-list entry had been removed since).
    let literal = create(
        &svc,
        app,
        "literal",
        "https://hooks.example/in",
        &[W::UserCreated],
    )
    .await;
    app.storage()
        .webhooks()
        .update_endpoint(
            tenant(app),
            literal.endpoint.id,
            &WebhookEndpointUpdate {
                url: Some(format!("http://127.0.0.1:{port}{HOOK}")),
                ..WebhookEndpointUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .unwrap()
        .unwrap();
    AuditServiceExt::emit_user_created(app).await;

    // Production policy: localhost resolves to loopback, which the resolver drops.
    let report = worker_with(app, &OutboundPolicy::default())
        .run_once()
        .await
        .unwrap();
    assert_eq!((report.claimed, report.retried), (2, 2), "{report:?}");
    assert!(
        received(&server).await.is_empty(),
        "nothing reached loopback"
    );
    for ep in [by_name.endpoint.id, literal.endpoint.id] {
        let row = &deliveries(app, ep).await[0];
        assert_eq!(row.status, DeliveryStatus::Pending);
        assert_eq!(row.last_error.as_deref(), Some("blocked"));
        assert_eq!(row.last_http_status, None);
    }
}

/// Emits a `user_created` lifecycle event through the audit choke point.
struct AuditServiceExt;

impl AuditServiceExt {
    async fn emit_user_created(app: &'static support::TestApp) {
        anvil_core::service::audit::AuditService {
            storage: app.storage_arc(),
            clock: std::sync::Arc::new(AppClock(app)),
        }
        .record(
            tenant(app),
            admin(),
            AuditAction::UserCreated,
            Some("0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a50".into()),
            anvil_core::model::AuditOutcome::Success,
            &RequestContext::system(),
            anvil_core::model::AuditDetails::empty(),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn webhook_secret_never_returned_after_create() {
    let app = prod_app().await;
    let server = sink(200).await;
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
    let secrets = [
        created.secret.expose_secret().to_owned(),
        rotated.secret.expose_secret().to_owned(),
    ];
    AuditServiceExt::emit_user_created(app).await;
    dev_worker(app).run_once().await.unwrap();

    let ep = svc.get(tenant(app), created.endpoint.id).await.unwrap();
    let listed = svc.list(tenant(app)).await.unwrap();
    let rows = deliveries(app, ep.id).await;
    let events = app
        .storage()
        .audit()
        .query(
            tenant(app),
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    let req = &received(&server).await[0];
    let request_dump = format!("{:?} {}", req.headers, String::from_utf8_lossy(&req.body));
    for secret in &secrets {
        let key = parse_webhook_secret(secret).unwrap();
        let encoded = secret.trim_start_matches("whsec_");
        for (what, text) in [
            ("get", format!("{ep:?}")),
            ("list", format!("{listed:?}")),
            ("deliveries", format!("{rows:?}")),
            ("audit", format!("{events:?}")),
            ("request", request_dump.clone()),
        ] {
            assert!(!text.contains(encoded), "secret leaked through {what}");
        }
        for sealed in [Some(&ep.secret_enc), ep.previous_secret_enc.as_ref()]
            .into_iter()
            .flatten()
        {
            assert!(!sealed.windows(key.len()).any(|w| w == key.as_slice()));
            assert!(!sealed.windows(secret.len()).any(|w| w == secret.as_bytes()));
        }
    }
    // The audit rows for the endpoint name it, never a secret field.
    for e in audit(app, AuditAction::WebhookEndpointCreated)
        .await
        .into_iter()
        .chain(audit(app, AuditAction::WebhookSecretRotated).await)
    {
        let keys: BTreeSet<&str> = e.details.as_map().keys().map(String::as_str).collect();
        assert!(!keys.iter().any(|k| k.contains("secret")), "{keys:?}");
    }
}

#[tokio::test]
async fn webhook_payload_has_no_pii() {
    let app = prod_app().await;
    let server = sink(200).await;
    let svc = dev_service(app);
    create(
        &svc,
        app,
        "crm",
        &hook_url(&server),
        &[W::UserCreated, W::UserUpdated],
    )
    .await;
    let token = admin_token(app, "admin:read admin:write").await;
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(&token),
        Some(json!({
            "email": EMAIL,
            "password": "correct horse battery staple",
            "email_verified": true,
            "username": "alicewonder",
            "claims": {"given_name": GIVEN, "family_name": FAMILY, "phone_number": "+15550100"},
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let user: Value = serde_json::from_slice(&resp.body).unwrap();
    let id = user["id"].as_str().unwrap();
    let resp = call(
        app,
        Method::PATCH,
        &format!("{API}/tenants/default/users/{id}"),
        Some(&token),
        Some(json!({"claims": {"given_name": "Changed", "family_name": FAMILY}})),
    )
    .await;
    assert!(resp.status.is_success(), "{}", resp.text());
    dev_worker(app).run_once().await.unwrap();

    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 2);
    for req in &reqs {
        let text = String::from_utf8_lossy(&req.body).to_lowercase();
        for pii in [
            EMAIL,
            "example.com",
            "@",
            &GIVEN.to_lowercase(),
            &FAMILY.to_lowercase(),
            "changed",
            "alicewonder",
            "15550100",
            "203.0.113",
        ] {
            assert!(!text.contains(pii), "payload contains {pii:?}: {text}");
        }
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let top: BTreeSet<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(top, BTreeSet::from(["type", "timestamp", "data"]));
        let allowed = BTreeSet::from(["tenant", "user_id", "session_id", "client_id", "actor"]);
        for k in body["data"].as_object().unwrap().keys() {
            assert!(allowed.contains(k.as_str()), "unexpected data key {k}");
        }
        assert_eq!(body["data"]["user_id"], id);
    }
}

#[tokio::test]
async fn webhook_signature_verifies_and_tampered_body_fails() {
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
    AuditServiceExt::emit_user_created(app).await;
    dev_worker(app).run_once().await.unwrap();
    let req = &received(&server).await[0];
    let id = header(req, "webhook-id").to_owned();
    let ts: i64 = header(req, "webhook-timestamp").parse().unwrap();
    let sig = header(req, "webhook-signature").to_owned();
    assert!(sig.starts_with("v1,"));
    assert!(signs(&created.secret, &sig, &id, ts, &req.body));

    let key = parse_webhook_secret(created.secret.expose_secret()).unwrap();
    let mut tampered = req.body.clone();
    tampered[req.body.len() / 2] ^= 0x01;
    assert_ne!(signature_v1(&key, &id, ts, &tampered), sig, "tampered body");
    assert_ne!(
        signature_v1(&key, &id, ts + 1, &req.body),
        sig,
        "tampered timestamp"
    );
    assert_ne!(
        signature_v1(&key, "msg_other", ts, &req.body),
        sig,
        "tampered id"
    );
    let other = anvil_jose::webhook::generate_webhook_secret();
    let other_key = parse_webhook_secret(&other).unwrap();
    assert_ne!(
        signature_v1(&other_key, &id, ts, &req.body),
        sig,
        "other secret"
    );
}

#[tokio::test]
async fn webhook_redirect_not_followed() {
    let app = prod_app().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(HOOK))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/stolen"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/stolen"))
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
    AuditServiceExt::emit_user_created(app).await;
    let report = dev_worker(app).run_once().await.unwrap();
    assert_eq!((report.delivered, report.retried), (0, 1));
    let reqs = received(&server).await;
    assert_eq!(reqs.len(), 1, "the redirect target was never requested");
    assert_eq!(reqs[0].url.path(), HOOK);
    let row = &deliveries(app, created.endpoint.id).await[0];
    assert_eq!(row.status, DeliveryStatus::Pending);
    assert_eq!(row.last_error.as_deref(), Some("redirect"));
}
