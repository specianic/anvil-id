//! Helpers for the webhook tests (test code only): the app's clock as an `Arc<dyn Clock>`, the
//! webhook service and delivery worker on the test app's storage and KEK, a wiremock sink on
//! 127.0.0.1, Standard Webhooks signature verification and a capture recorder for the delivery
//! metric.

#![allow(dead_code)]

use std::sync::Arc;

use anvil_core::model::{
    AuditAction, AuditActor, AuditEvent, AuditQuery, RequestContext, TenantId, WebhookDelivery,
    WebhookEndpointId, WebhookEventType,
};
use anvil_core::ports::Clock;
use anvil_core::service::webhook::{EndpointWithSecret, NewWebhookInput, WebhookService};
use anvil_jose::webhook::{parse_webhook_secret, signature_v1};
use anvil_web::adapters::outbound::{OutboundClient, OutboundPolicy};
use anvil_web::adapters::webhook::WebhookDeliveryWorker;
use secrecy::{ExposeSecret as _, SecretString};
use time::OffsetDateTime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::support::TestApp;

/// The path every sink listens on.
pub const HOOK: &str = "/hook";

/// The app's test clock, shared with services and workers (the app is leaked for the test).
pub struct AppClock(pub &'static TestApp);

impl Clock for AppClock {
    fn now(&self) -> OffsetDateTime {
        self.0.clock().now()
    }
}

/// A leaked installed app in production mode (`https://op.test`).
pub async fn prod_app() -> &'static TestApp {
    Box::leak(Box::new(TestApp::new().await))
}

/// A leaked installed app in development mode.
pub async fn dev_app() -> &'static TestApp {
    Box::leak(Box::new(TestApp::dev().await))
}

/// The default tenant's id.
pub fn tenant(app: &TestApp) -> TenantId {
    app.default.as_ref().expect("installed").tenant.id
}

pub fn outbound(policy: &OutboundPolicy) -> Arc<OutboundClient> {
    Arc::new(OutboundClient::new(policy).expect("outbound client"))
}

/// The webhook service with `policy` as its URL check.
pub fn service_with(app: &'static TestApp, policy: &OutboundPolicy) -> WebhookService {
    WebhookService {
        storage: app.storage_arc(),
        kek: app.kek_arc(),
        clock: Arc::new(AppClock(app)),
        url_check: outbound(policy),
    }
}

/// The webhook service allowed to target the loopback sink (development policy).
pub fn dev_service(app: &'static TestApp) -> WebhookService {
    service_with(app, &OutboundPolicy::loopback_dev())
}

/// A delivery worker sending through a client with `policy`.
pub fn worker_with(app: &'static TestApp, policy: &OutboundPolicy) -> WebhookDeliveryWorker {
    WebhookDeliveryWorker::new(
        app.storage_arc(),
        Arc::new(AppClock(app)),
        app.kek_arc(),
        outbound(policy),
    )
}

/// A worker allowed to reach the loopback sink over plain http.
pub fn dev_worker(app: &'static TestApp) -> WebhookDeliveryWorker {
    worker_with(app, &OutboundPolicy::loopback_dev())
}

pub fn admin() -> AuditActor {
    AuditActor::admin("0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a99")
}

pub fn input(name: &str, url: &str, events: &[WebhookEventType]) -> NewWebhookInput {
    NewWebhookInput {
        name: name.to_owned(),
        url: url.to_owned(),
        events: events.to_vec(),
        enabled: true,
        secret: None,
    }
}

/// Creates an enabled endpoint in the default tenant.
pub async fn create(
    service: &WebhookService,
    app: &TestApp,
    name: &str,
    url: &str,
    events: &[WebhookEventType],
) -> EndpointWithSecret {
    service
        .create(
            tenant(app),
            input(name, url, events),
            admin(),
            &RequestContext::system(),
        )
        .await
        .expect("create endpoint")
}

/// A sink answering `status` on `POST /hook`.
pub async fn sink(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(HOOK))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

pub fn hook_url(server: &MockServer) -> String {
    format!("{}{HOOK}", server.uri())
}

pub async fn received(server: &MockServer) -> Vec<wiremock::Request> {
    server.received_requests().await.expect("recording on")
}

pub fn header<'a>(req: &'a wiremock::Request, name: &str) -> &'a str {
    req.headers
        .get(name)
        .unwrap_or_else(|| panic!("missing header {name}"))
        .to_str()
        .expect("ascii header")
}

/// `true` if `signature` (one `v1,…` entry) is the v1 signature of `(id, ts, body)` under the
/// `whsec_` `secret`.
pub fn signs(secret: &SecretString, signature: &str, id: &str, ts: i64, body: &[u8]) -> bool {
    let key = parse_webhook_secret(secret.expose_secret()).expect("whsec secret");
    signature_v1(&key, id, ts, body) == signature
}

/// The signature entries of a request (space-separated `webhook-signature`).
pub fn signatures(req: &wiremock::Request) -> Vec<String> {
    header(req, "webhook-signature")
        .split(' ')
        .map(str::to_owned)
        .collect()
}

/// `true` if the request carries a signature by `secret` over its exact id, timestamp and body.
pub fn verified_by(req: &wiremock::Request, secret: &SecretString) -> bool {
    let id = header(req, "webhook-id");
    let ts: i64 = header(req, "webhook-timestamp")
        .parse()
        .expect("unix seconds");
    signatures(req)
        .iter()
        .any(|s| signs(secret, s, id, ts, &req.body))
}

/// Every delivery of an endpoint, newest first.
pub async fn deliveries(app: &TestApp, endpoint: WebhookEndpointId) -> Vec<WebhookDelivery> {
    app.storage()
        .webhooks()
        .deliveries(
            tenant(app),
            endpoint,
            anvil_core::model::PageRequest {
                after: None,
                limit: 100,
            },
        )
        .await
        .expect("deliveries")
        .items
}

/// The default tenant's audit events with `action`, newest first.
pub async fn audit(app: &TestApp, action: AuditAction) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            tenant(app),
            &AuditQuery {
                action: Some(action),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

// ---------------------------------------------------------------------------------------------
// Metrics capture
// ---------------------------------------------------------------------------------------------

pub mod capture {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use metrics::{
        Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata,
        Recorder, SharedString, Unit,
    };

    #[derive(Default)]
    pub struct Series(AtomicU64);

    impl CounterFn for Series {
        fn increment(&self, value: u64) {
            self.0.fetch_add(value, Ordering::Relaxed);
        }
        fn absolute(&self, value: u64) {
            self.0.store(value, Ordering::Relaxed);
        }
    }

    impl GaugeFn for Series {
        fn increment(&self, _: f64) {}
        fn decrement(&self, _: f64) {}
        fn set(&self, _: f64) {}
    }

    impl HistogramFn for Series {
        fn record(&self, _: f64) {}
    }

    /// Every series by rendered key (`name{label="value",...}`).
    #[derive(Default)]
    pub struct Capture {
        series: Mutex<BTreeMap<String, Arc<Series>>>,
    }

    impl Capture {
        fn series(&self, key: &Key) -> Arc<Series> {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}=\"{}\"", l.key(), l.value()))
                .collect();
            let rendered = format!("{}{{{}}}", key.name(), labels.join(","));
            Arc::clone(
                self.series
                    .lock()
                    .expect("series")
                    .entry(rendered)
                    .or_default(),
            )
        }

        pub fn value(&self, key: &str) -> u64 {
            self.series
                .lock()
                .expect("series")
                .get(key)
                .map_or(0, |s| s.0.load(Ordering::Relaxed))
        }
    }

    struct Rec(&'static Capture);

    impl Recorder for Rec {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            Counter::from_arc(self.0.series(key))
        }
        fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::from_arc(self.0.series(key))
        }
        fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::from_arc(self.0.series(key))
        }
    }

    /// The capture recorder, installed globally on first use (one per test binary).
    pub fn capture() -> &'static Capture {
        static CAPTURE: OnceLock<&'static Capture> = OnceLock::new();
        CAPTURE.get_or_init(|| {
            let capture: &'static Capture = Box::leak(Box::default());
            metrics::set_global_recorder(Rec(capture)).expect("first recorder of this binary");
            capture
        })
    }
}
