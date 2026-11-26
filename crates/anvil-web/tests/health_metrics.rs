//! Health endpoints and request telemetry (OPS-08): liveness and readiness aliases, readiness
//! cleared for the shutdown drain, probes outside tenant resolution and rate limiting; the
//! `/metrics` route per configuration; metric names and label hygiene (bounded class labels,
//! no email, client id, tenant, IP or query); the `http.request` span with the route template.
//!
//! Metrics are captured by a recorder installed once for this test binary (the recorder is
//! process-wide), so assertions are about presence and absence, never exact global counts.

mod support;
mod token_support;
mod ui_helpers;

use std::net::SocketAddr;
use std::sync::Arc;

use anvil_cache::limiter::{LimiterConfig, RateQuota};
use anvil_core::clock::SystemClock;
use anvil_core::model::PublicUrl;
use anvil_core::ports::Clock;
use anvil_jose::kek::Kek;
use anvil_web::adapters::argon2::Argon2Pool;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use anvil_web::observability::{MetricsEndpoint, TraceContextHook};
use anvil_web::{AppConfig, AppDeps, AppState};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use http_body_util::BodyExt;
use support::TestApp;
use tower::ServiceExt;

/// An uninstalled app plus its state (the harness does not expose the state).
async fn app_with_state(f: impl FnOnce(&mut AppConfig)) -> (AppState, Router) {
    let storage = support::Backend::from_env().storage().await;
    let mut config = AppConfig::new(PublicUrl::parse("https://op.test").expect("url"));
    f(&mut config);
    let deps = AppDeps {
        storage,
        clock: Arc::new(SystemClock) as Arc<dyn Clock>,
        hasher: Arc::new(
            Argon2Pool::new(argon2::Params::new(256, 1, 1, None).expect("params"), 1)
                .expect("argon2 pool"),
        ),
        breach: breach_checker(BreachCheckMode::Off),
        kek: Arc::new(Kek::generate()),
        domain_txt: Arc::new(support::FakeTxt::default()),
    };
    let state = AppState::new(config, deps).expect("app builds");
    let router = anvil_web::router(state.clone());
    (state, router)
}

async fn get(router: &Router, path: &str, host: &str) -> (u16, String) {
    let mut req = Request::get(path)
        .header(header::HOST, host)
        .body(Body::empty())
        .expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 40000))));
    let resp = router.clone().oneshot(req).await.expect("infallible");
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn health_liveness_aliases_answer_ok() {
    let app = TestApp::uninstalled().await;
    for path in ["/health/live", "/healthz"] {
        let resp = app.get(path).await;
        assert_eq!(resp.status, 200, "{path}");
        assert_eq!(resp.text(), "ok", "{path}");
    }
}

#[tokio::test]
async fn health_readiness_aliases_share_one_handler() {
    let app = TestApp::new().await;
    let ready = app.get("/health/ready").await;
    let readyz = app.get("/readyz").await;
    assert_eq!(ready.status, 200);
    assert_eq!(readyz.status, 200);
    assert_eq!(ready.text(), readyz.text());
}

#[tokio::test]
async fn health_readiness_turns_503_while_draining() {
    let (state, router) = app_with_state(|_| {}).await;
    for path in ["/readyz", "/health/ready"] {
        assert_eq!(get(&router, path, "op.test").await, (200, "ok".into()));
    }
    state.set_ready(false);
    for path in ["/readyz", "/health/ready"] {
        assert_eq!(
            get(&router, path, "op.test").await,
            (503, "draining".into()),
            "{path}"
        );
    }
    // Liveness is unaffected: the node still serves while it drains.
    for path in ["/healthz", "/health/live"] {
        assert_eq!(get(&router, path, "op.test").await.0, 200, "{path}");
    }
    state.set_ready(true);
    assert_eq!(get(&router, "/readyz", "op.test").await.0, 200);
}

#[tokio::test]
async fn health_probes_skip_tenant_resolution_and_rate_limits() {
    let (_, router) = app_with_state(|c| {
        c.rate_limits = LimiterConfig {
            default: RateQuota::per_second(1, 1),
            ..LimiterConfig::default()
        };
    })
    .await;
    // An unknown Host header does not make probes depend on a tenant lookup.
    for path in ["/readyz", "/health/ready", "/healthz", "/health/live"] {
        assert_eq!(
            get(&router, path, "unknown.example.test").await.0,
            200,
            "{path}"
        );
    }
    // Far above the default quota of one request per second: never limited.
    for _ in 0..20 {
        assert_eq!(get(&router, "/readyz", "op.test").await.0, 200);
    }
    // The quota is real: an ordinary page from the same address is limited.
    let mut limited = false;
    for _ in 0..5 {
        limited |= get(&router, "/.well-known/openid-configuration", "op.test")
            .await
            .0
            == 429;
    }
    assert!(
        limited,
        "the default class quota applies to ordinary routes"
    );
}

// ---------------------------------------------------------------------------------------------
// Metrics capture (test code only)
// ---------------------------------------------------------------------------------------------

mod capture {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use metrics::{
        Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata,
        Recorder, SharedString, Unit,
    };

    /// One series: a counter value, or the number of histogram observations.
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
        fn record(&self, _: f64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Every series by rendered key (`name{label="value",...}`) and every label pair seen.
    #[derive(Default)]
    pub struct Capture {
        series: Mutex<BTreeMap<String, Arc<Series>>>,
        pub labels: Mutex<Vec<(String, String)>>,
    }

    impl Capture {
        fn series(&self, key: &Key) -> Arc<Series> {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}=\"{}\"", l.key(), l.value()))
                .collect();
            {
                let mut seen = self.labels.lock().expect("labels");
                for l in key.labels() {
                    seen.push((l.key().to_owned(), l.value().to_owned()));
                }
            }
            let rendered = format!("{}{{{}}}", key.name(), labels.join(","));
            Arc::clone(
                self.series
                    .lock()
                    .expect("series")
                    .entry(rendered)
                    .or_default(),
            )
        }

        /// One `key value` line per series.
        pub fn render(&self) -> String {
            self.series
                .lock()
                .expect("series")
                .iter()
                .map(|(k, v)| format!("{k} {}\n", v.0.load(Ordering::Relaxed)))
                .collect()
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

    /// The capture recorder, installed globally on first use.
    pub fn capture() -> &'static Capture {
        static CAPTURE: OnceLock<&'static Capture> = OnceLock::new();
        CAPTURE.get_or_init(|| {
            let capture: &'static Capture = Box::leak(Box::default());
            metrics::set_global_recorder(Rec(capture)).expect("first recorder of this binary");
            capture
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Span capture (test code only)
// ---------------------------------------------------------------------------------------------

mod spans {
    //! A process-wide subscriber that records only on threads with an active [`Recording`].
    //!
    //! A scoped `set_default` subscriber is not enough here: while it is the only registered
    //! dispatcher, tracing-core computes the interest of a callsite first hit on *another* test
    //! thread from that thread's (empty) default and caches `never`, so this test's own request
    //! would then skip the event or span. A global subscriber answers `sometimes` for every
    //! callsite on every thread and decides per thread in `enabled`.

    use std::cell::RefCell;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use tracing::span::{Attributes, Id, Record};
    use tracing::subscriber::Interest;
    use tracing::{Event, Metadata, Subscriber};

    pub type Fields = BTreeMap<String, String>;

    #[derive(Default)]
    pub struct Inner {
        spans: Mutex<HashMap<u64, (&'static Metadata<'static>, Fields)>>,
        pub events: Mutex<Vec<(String, Fields)>>,
    }

    impl Inner {
        /// Every captured span named `name`, with its fields.
        pub fn spans(&self, name: &str) -> Vec<Fields> {
            self.spans
                .lock()
                .expect("spans")
                .values()
                .filter(|(m, _)| m.name() == name)
                .map(|(_, f)| f.clone())
                .collect()
        }
    }

    thread_local! {
        static ACTIVE: RefCell<Option<Arc<Inner>>> = const { RefCell::new(None) };
    }

    fn active() -> Option<Arc<Inner>> {
        ACTIVE.with(|a| a.borrow().clone())
    }

    struct Visit<'a>(&'a mut Fields);

    impl tracing::field::Visit for Visit<'_> {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    /// The global subscriber: forwards to the current thread's recording, if any.
    struct Capture {
        next: AtomicU64,
    }

    impl Subscriber for Capture {
        fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            active().is_some()
        }
        fn new_span(&self, attrs: &Attributes<'_>) -> Id {
            let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(inner) = active() {
                let mut fields = Fields::new();
                attrs.record(&mut Visit(&mut fields));
                inner
                    .spans
                    .lock()
                    .expect("spans")
                    .insert(id, (attrs.metadata(), fields));
            }
            Id::from_u64(id)
        }
        fn record(&self, span: &Id, values: &Record<'_>) {
            if let Some(inner) = active()
                && let Some((_, fields)) =
                    inner.spans.lock().expect("spans").get_mut(&span.into_u64())
            {
                values.record(&mut Visit(fields));
            }
        }
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            if let Some(inner) = active() {
                let mut fields = Fields::new();
                event.record(&mut Visit(&mut fields));
                inner
                    .events
                    .lock()
                    .expect("events")
                    .push((event.metadata().target().to_owned(), fields));
            }
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    /// Installs the global subscriber once for this test binary.
    pub fn install() {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            tracing::subscriber::set_global_default(Capture {
                next: AtomicU64::new(0),
            })
            .expect("first subscriber of this binary");
        });
    }

    /// Records spans and events on the current thread until dropped. Call [`install`] first,
    /// early enough that no callsite registration on another thread can still race with it.
    pub struct Recording(pub Arc<Inner>);

    impl Recording {
        pub fn start() -> Self {
            let inner = Arc::new(Inner::default());
            ACTIVE.with(|a| *a.borrow_mut() = Some(Arc::clone(&inner)));
            // Recompute cached interest, in case a registration raced with `install`.
            tracing::callsite::rebuild_interest_cache();
            Self(inner)
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            ACTIVE.with(|a| *a.borrow_mut() = None);
        }
    }
}

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const REQUEST: &str = "0192f0c4-7a1b-7c3d-8e9f-0123456789ab";
const PEER_IP: &str = "203.0.113.10";

/// Label names and values the metrics may carry (bounded by construction).
const LABEL_NAMES: &[&str] = &["route_class", "status_class", "outcome", "job", "grant"];

#[tokio::test]
async fn metrics_labels_are_bounded_and_free_of_identifiers() {
    let capture = capture::capture();
    let app = TestApp::new().await;
    let acme = token_support::acme(&app).await;
    ui_helpers::register(&app, "", EMAIL, PASSWORD).await;

    // A login page, a failed and a successful login.
    assert_eq!(
        app.get(&format!("/ui/login?request={REQUEST}"))
            .await
            .status,
        200
    );
    let failed = ui_helpers::submit_form(
        &app,
        &format!("/ui/login?request={REQUEST}"),
        &[("identifier", EMAIL), ("password", "not the password")],
    )
    .await;
    assert_ne!(failed.status, 303, "a wrong password does not sign in");
    let ok = ui_helpers::submit_form(
        &app,
        &format!("/ui/login?request={REQUEST}"),
        &[("identifier", EMAIL), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(ok.status, 303, "{}", ok.text());

    // A token request and an authorize call carrying a login hint, in another tenant.
    let rp = token_support::register(
        &app,
        token_support::default_tenant(&app),
        token_support::cc_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let token =
        token_support::token(&app, &rp.auth(), &[("grant_type", "client_credentials")]).await;
    assert_eq!(token.status, 200, "{}", token.text());
    let acme_rp = token_support::register(
        &app,
        acme.id,
        token_support::web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let authorize = format!(
        "/t/acme/authorize?client_id={}&response_type=code&scope=openid&login_hint={EMAIL}",
        acme_rp.id()
    );
    let _ = app.get(&authorize).await;

    let rendered = capture.render();
    assert!(
        rendered.contains("anvil_http_requests_total{"),
        "{rendered}"
    );
    assert!(
        rendered.contains("anvil_http_request_duration_seconds{"),
        "{rendered}"
    );
    assert!(
        capture.value("anvil_auth_attempts_total{outcome=\"failure\"}") >= 1,
        "{rendered}"
    );
    assert!(
        capture.value("anvil_auth_attempts_total{outcome=\"success\"}") >= 1,
        "{rendered}"
    );
    assert!(
        capture.value("anvil_http_requests_total{route_class=\"token\",status_class=\"2xx\"}") >= 1,
        "{rendered}"
    );
    assert!(
        capture.value("anvil_http_requests_total{route_class=\"auth\",status_class=\"3xx\"}") >= 1,
        "{rendered}"
    );

    for forbidden in [
        EMAIL,
        "alice",
        rp.id(),
        acme_rp.id(),
        "acme",
        PEER_IP,
        "/authorize?",
        "login_hint",
        "/t/",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "{forbidden} in metrics:\n{rendered}"
        );
    }
    for (name, value) in capture.labels.lock().expect("labels").iter() {
        assert!(LABEL_NAMES.contains(&name.as_str()), "label {name}={value}");
        assert!(
            value.len() <= 32
                && value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "unbounded-looking label value {name}={value}"
        );
    }
}

/// Requests to `router` from the default peer.
async fn get_path(router: &Router, path: &str) -> (u16, String) {
    get(router, path, "op.test").await
}

#[tokio::test]
async fn metrics_route_follows_the_configuration() {
    // Neither metrics_listen nor metrics_on_main_port reaches the web layer: no route.
    let (_, router) = app_with_state(|_| {}).await;
    assert_eq!(get_path(&router, "/metrics").await.0, 404);

    // metrics_on_main_port: served outside tenant resolution and rate limiting.
    let (_, router) = app_with_state(|c| {
        c.metrics = Some(MetricsEndpoint::new(|| {
            "# TYPE anvil_http_requests_total counter\n".to_owned()
        }));
        c.rate_limits = LimiterConfig {
            default: RateQuota::per_second(1, 1),
            ..LimiterConfig::default()
        };
    })
    .await;
    for _ in 0..10 {
        let (status, body) = get(&router, "/metrics", "unknown.example.test").await;
        assert_eq!(status, 200);
        assert!(body.contains("anvil_http_requests_total"), "{body}");
    }
    // Only at the root: a tenant path is not the metrics route.
    assert_eq!(get_path(&router, "/t/default/metrics").await.0, 404);
}

#[tokio::test]
async fn request_span_carries_the_route_template_not_the_uri() {
    spans::install();
    let app = TestApp::new().await;
    token_support::acme(&app).await;
    // The request runs on this thread (current-thread runtime), so it is what gets recorded.
    let recording = spans::Recording::start();
    let inner = Arc::clone(&recording.0);
    let resp = app
        .get(&format!(
            "/t/acme/authorize?login_hint={EMAIL}&client_id=unknown-client&state=s3cr3t-state"
        ))
        .await;
    drop(recording);

    let spans = inner.spans("http.request");
    let span = spans
        .iter()
        .find(|f| f.get("route").map(String::as_str) == Some("/authorize"))
        .unwrap_or_else(|| panic!("no http.request span for /authorize: {spans:?}"));
    assert_eq!(
        span.get("tenant").map(String::as_str),
        Some("acme"),
        "{span:?}"
    );
    assert_eq!(
        span.get("status").map(String::as_str),
        Some(resp.status.as_str()),
        "{span:?}"
    );
    assert!(span.contains_key("latency_ms"), "{span:?}");
    assert!(span.contains_key("method"), "{span:?}");

    let events = inner.events.lock().expect("events");
    let access: Vec<_> = events
        .iter()
        .filter(|(target, _)| target == anvil_web::observability::ACCESS_LOG_TARGET)
        .collect();
    assert!(!access.is_empty(), "no access log line");
    let everything = format!("{spans:?} {access:?}");
    for forbidden in [
        EMAIL,
        "login_hint",
        "s3cr3t-state",
        "unknown-client",
        "?",
        PEER_IP,
    ] {
        assert!(
            !everything.contains(forbidden),
            "{forbidden} in telemetry: {everything}"
        );
    }
}

#[tokio::test]
async fn trace_context_is_continued_only_from_trusted_proxies() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let calls = Arc::new(AtomicUsize::new(0));
    let hook = {
        let calls = Arc::clone(&calls);
        TraceContextHook::new(move |headers, _| {
            assert!(headers.contains_key("traceparent"));
            calls.fetch_add(1, Ordering::SeqCst);
        })
    };
    let traced = |router: Router, peer: [u8; 4]| async move {
        let mut req = Request::get("/healthz")
            .header(header::HOST, "op.test")
            .header(
                "traceparent",
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            )
            .body(Body::empty())
            .expect("request");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((peer, 40000))));
        router.oneshot(req).await.expect("infallible").status()
    };

    // Production default: no trusted proxies, so nobody can choose our trace ids.
    let (_, router) = app_with_state({
        let hook = hook.clone();
        |c| c.trace_context = Some(hook)
    })
    .await;
    assert_eq!(traced(router, [203, 0, 113, 10]).await, 200);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "untrusted peer was honoured"
    );

    // A trusted proxy's trace context is continued; other peers are still ignored.
    let (_, router) = app_with_state(|c| {
        c.trusted_proxies.cidrs = vec!["10.0.0.0/8".parse().expect("cidr")];
        c.trace_context = Some(hook);
    })
    .await;
    assert_eq!(traced(router.clone(), [203, 0, 113, 10]).await, 200);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "untrusted peer was honoured"
    );
    assert_eq!(traced(router, [10, 1, 2, 3]).await, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "trusted proxy was ignored");
}
