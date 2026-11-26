//! Webhook delivery across workers (ADM-05, OPS-03): two `WebhookDeliveryWorker`s on one
//! storage (SQLite by default: the single writer; Postgres with `ANVILID_TEST_DB=postgres`, one
//! container per test: `FOR UPDATE SKIP LOCKED`) deliver every queued row exactly once, and a row
//! leased by a worker whose requests are still in flight is not claimed by the other worker even
//! after more than one request timeout (15 s) has passed on the clock (the lease is 45 s).
//!
//! The sink is a minimal HTTP server on 127.0.0.1 that records every `webhook-id` and can hold
//! its responses until the test releases them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anvil_core::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, DeliveryStatus, NewTenant, PageRequest,
    RequestContext, TenantId, TenantSettings, WEBHOOK_BATCH, WEBHOOK_LEASE, WEBHOOK_TIMEOUT,
    WebhookEndpointId, WebhookEventType,
};
use anvil_core::ports::{Clock, Storage};
use anvil_core::service::audit::AuditService;
use anvil_core::service::webhook::{NewWebhookInput, WebhookService};
use anvil_jose::Kek;
use anvil_web::adapters::outbound::{OutboundClient, OutboundPolicy};
use anvil_web::adapters::webhook::WebhookDeliveryWorker;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// A settable clock shared by both workers.
struct FakeClock(Mutex<OffsetDateTime>);

impl FakeClock {
    fn advance(&self, d: Duration) {
        let mut now = self.0.lock().expect("clock");
        *now += d;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock")
    }
}

/// The storage under test; keeps the Postgres container alive for the test.
struct Backend {
    storage: Arc<dyn Storage>,
    _container: Option<Box<dyn std::any::Any + Send>>,
}

async fn backend() -> Backend {
    match std::env::var("ANVILID_TEST_DB").as_deref() {
        Ok("postgres") => {
            let (container, url) = anvil_storage::postgres_container::start(100).await;
            let s =
                anvil_storage_postgres::PostgresStorage::connect(&format!("{url}/postgres"), 10)
                    .await
                    .expect("connect Postgres");
            s.migrate().await.expect("Postgres migrations");
            Backend {
                storage: Arc::new(s),
                _container: Some(Box::new(container)),
            }
        }
        Ok("sqlite") | Err(_) => {
            let s = anvil_storage_sqlite::SqliteStorage::connect("sqlite::memory:")
                .await
                .expect("in-memory SQLite");
            s.migrate().await.expect("SQLite migrations");
            Backend {
                storage: Arc::new(s),
                _container: None,
            }
        }
        Ok(other) => panic!("ANVILID_TEST_DB must be sqlite or postgres, got {other:?}"),
    }
}

/// A local sink: records each request's `webhook-id` (in arrival order) and answers 200 once
/// `release` is true.
struct Sink {
    port: u16,
    ids: Arc<Mutex<Vec<String>>>,
    release: watch::Sender<bool>,
}

impl Sink {
    async fn start(released: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sink");
        let port = listener.local_addr().expect("addr").port();
        let ids = Arc::new(Mutex::new(Vec::new()));
        let (release, rx) = watch::channel(released);
        let recorded = Arc::clone(&ids);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                let mut rx = rx.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut len = 0usize;
                    let mut id = None;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let lower = line.to_ascii_lowercase();
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        if let Some(v) = lower.strip_prefix("webhook-id:") {
                            id = Some(v.trim().to_owned());
                        }
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let mut body = vec![0; len];
                    let _ = reader.read_exact(&mut body).await;
                    recorded.lock().expect("ids").push(id.unwrap_or_default());
                    let _ = rx.wait_for(|released| *released).await;
                    let _ = reader
                        .get_mut()
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        Self { port, ids, release }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/hook", self.port)
    }

    fn ids(&self) -> Vec<String> {
        self.ids.lock().expect("ids").clone()
    }

    /// Waits until `n` requests have arrived (held or answered).
    async fn wait_for(&self, n: usize) {
        for _ in 0..500 {
            if self.ids().len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("only {} of {n} requests arrived", self.ids().len());
    }
}

struct Fixture {
    _backend: Backend,
    storage: Arc<dyn Storage>,
    clock: Arc<FakeClock>,
    kek: Arc<Kek>,
    tenant: TenantId,
    endpoint: WebhookEndpointId,
}

impl Fixture {
    async fn new(sink_url: &str) -> Self {
        let backend = backend().await;
        let storage = Arc::clone(&backend.storage);
        let start = OffsetDateTime::from_unix_timestamp(1_795_608_000).expect("time");
        let clock = Arc::new(FakeClock(Mutex::new(start)));
        let kek = Arc::new(Kek::generate());
        let tenant = storage
            .tenants()
            .create(&NewTenant {
                id: TenantId::new_v7(),
                slug: "acme".into(),
                display_name: "Acme".into(),
                host: None,
                settings: TenantSettings::default(),
                created_at: start,
            })
            .await
            .expect("tenant")
            .id;
        let service = WebhookService {
            storage: Arc::clone(&storage),
            kek: Arc::clone(&kek),
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            url_check: Arc::new(
                OutboundClient::new(&OutboundPolicy::loopback_dev()).expect("outbound"),
            ),
        };
        let endpoint = service
            .create(
                tenant,
                NewWebhookInput {
                    name: "sink".into(),
                    url: sink_url.to_owned(),
                    events: vec![WebhookEventType::UserCreated],
                    enabled: true,
                    secret: None,
                },
                AuditActor::system(),
                &RequestContext::system(),
            )
            .await
            .expect("endpoint")
            .endpoint
            .id;
        Self {
            _backend: backend,
            storage,
            clock,
            kek,
            tenant,
            endpoint,
        }
    }

    /// Records `n` `user_created` events (each enqueues one delivery in the audit transaction).
    async fn emit(&self, n: usize) {
        let audit = AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock) as Arc<dyn Clock>,
        };
        for i in 0..n {
            audit
                .record(
                    self.tenant,
                    AuditActor::system(),
                    AuditAction::UserCreated,
                    Some(format!("0192f0c2-7d6a-7b1e-9a40-5f2d1c3b{i:04x}")),
                    AuditOutcome::Success,
                    &RequestContext::system(),
                    AuditDetails::empty(),
                )
                .await
                .expect("audit");
        }
    }

    fn worker(&self) -> WebhookDeliveryWorker {
        WebhookDeliveryWorker::new(
            Arc::clone(&self.storage),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
            Arc::clone(&self.kek),
            Arc::new(OutboundClient::new(&OutboundPolicy::loopback_dev()).expect("outbound")),
        )
    }

    /// Delivery status by id.
    async fn statuses(&self) -> BTreeMap<String, DeliveryStatus> {
        self.storage
            .webhooks()
            .deliveries(
                self.tenant,
                self.endpoint,
                PageRequest {
                    after: None,
                    limit: 200,
                },
            )
            .await
            .expect("deliveries")
            .items
            .into_iter()
            .map(|d| (d.id.to_string(), d.status))
            .collect()
    }
}

/// Every id appears exactly once.
fn assert_each_once(ids: &[String], expected: &BTreeMap<String, DeliveryStatus>) {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for id in ids {
        *counts.entry(id.as_str()).or_default() += 1;
    }
    let dupes: Vec<_> = counts.iter().filter(|(_, n)| **n > 1).collect();
    assert!(dupes.is_empty(), "delivered more than once: {dupes:?}");
    let got: Vec<&str> = counts.keys().copied().collect();
    let want: Vec<&str> = expected.keys().map(String::as_str).collect();
    assert_eq!(got, want, "every delivery arrived");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_workers_deliver_each_row_exactly_once() {
    const N: usize = 3 * WEBHOOK_BATCH + 3;
    let sink = Sink::start(true).await;
    let fx = Fixture::new(&sink.url()).await;
    fx.emit(N).await;
    let (a, b) = (fx.worker(), fx.worker());
    let drain = |w: WebhookDeliveryWorker| async move {
        let mut total = 0;
        loop {
            let report = w.run_once().await.expect("run");
            total += report.delivered;
            if report.claimed == 0 {
                return total;
            }
        }
    };
    let (da, db) = tokio::join!(drain(a), drain(b));
    assert_eq!(da + db, N, "a={da} b={db}");
    let statuses = fx.statuses().await;
    assert_eq!(statuses.len(), N);
    assert!(
        statuses.values().all(|s| *s == DeliveryStatus::Delivered),
        "{statuses:?}"
    );
    assert_each_once(&sink.ids(), &statuses);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_holds_in_flight_rows_past_the_request_timeout() {
    // The scenario relies on the model's lease rule.
    let overlap = Duration::from_secs(20);
    assert!(overlap > WEBHOOK_TIMEOUT && overlap < WEBHOOK_LEASE);

    let sink = Sink::start(false).await;
    let fx = Fixture::new(&sink.url()).await;
    fx.emit(WEBHOOK_BATCH).await;
    let a = fx.worker();
    let b = fx.worker();
    let in_flight = tokio::spawn(async move { a.run_once().await.expect("worker a") });
    // Worker A has claimed the batch and every request is held at the sink.
    sink.wait_for(WEBHOOK_BATCH).await;
    fx.clock.advance(overlap);
    // A B that claimed in-flight rows would block on the held sink: bound it, so a broken
    // lease fails the test instead of hanging it.
    let report = tokio::time::timeout(Duration::from_secs(5), b.run_once())
        .await
        .expect("B claimed rows A is still sending (blocked on the held sink)")
        .expect("worker b");
    assert_eq!(report.claimed, 0, "B claimed a row A is still sending");

    sink.release.send(true).expect("release");
    let report_a = in_flight.await.expect("join");
    assert_eq!(report_a.claimed, WEBHOOK_BATCH);
    assert_eq!(report_a.delivered, WEBHOOK_BATCH);

    // After the lease would have expired nothing is claimable either: the rows are completed.
    fx.clock.advance(WEBHOOK_LEASE);
    assert_eq!(b.run_once().await.expect("worker b").claimed, 0);
    let statuses = fx.statuses().await;
    assert!(statuses.values().all(|s| *s == DeliveryStatus::Delivered));
    assert_each_once(&sink.ids(), &statuses);
}
