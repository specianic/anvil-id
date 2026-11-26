//! The limiter contract suite (`src/limiter/contract.rs`) against every backend, plus the
//! Redis backend's own guarantees (shared budget, hashed key names, failure policy).
//!
//! - `in_process::*` runs on every `cargo test`.
//! - Every Redis-backed test has `redis` in its name and is `#[ignore]`d: it needs Docker
//!   (testcontainers) and runs with `just test-redis` (`ANVILID_TEST_REDIS=1 ... --include-ignored`),
//!   locally and in CI, like `just test-pg`. `redis_connect_*` needs no server and always runs.

#[path = "../src/limiter/contract.rs"]
mod contract;

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anvil_cache::limiter::{
    BREAKER_COOL_DOWN, BackendHealth, Backoff, Decision, FailureMode, InProcessLimiter, KeyHasher,
    LimitKey, LimiterConfig, RateLimiter, RedisInitError, RedisLimiter, RouteClass, canonical,
};
use anvil_core::model::TenantId;
use metrics::{Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, SharedString, Unit};
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

use contract::{FakeClock, TestLimiter, gcra_config, ip, limiter_contract_tests, loose, strict};

// --- in-process backend ----------------------------------------------------------------------

async fn in_process_limiter(config: LimiterConfig, clock: Arc<FakeClock>) -> TestLimiter {
    TestLimiter {
        limiter: Arc::new(InProcessLimiter::new(config, clock)),
        _guard: Box::new(()),
    }
}

limiter_contract_tests!(in_process, crate::in_process_limiter);

// --- Redis backend ---------------------------------------------------------------------------

/// A deterministic stand-in for the binary's HMAC (test code only): four SipHash lanes.
fn test_hasher() -> KeyHasher {
    Arc::new(|bytes: &[u8]| {
        let mut out = [0u8; 32];
        for (lane, chunk) in out.chunks_mut(8).enumerate() {
            let mut h = DefaultHasher::new();
            (lane, b"anvil-cache-test", bytes).hash(&mut h);
            chunk.copy_from_slice(&h.finish().to_be_bytes());
        }
        out
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct RedisServer {
    container: ContainerAsync<Redis>,
    url: String,
}

async fn redis_server() -> RedisServer {
    assert_eq!(
        std::env::var("ANVILID_TEST_REDIS").as_deref(),
        Ok("1"),
        "Redis tests run through `just test-redis` (ANVILID_TEST_REDIS=1, Docker)"
    );
    let container = Redis::default()
        .with_tag("7.2-alpine")
        .start()
        .await
        .expect("start Redis container (Docker)");
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("container port");
    RedisServer {
        container,
        url: format!("redis://{host}:{port}"),
    }
}

async fn connect(
    server: &RedisServer,
    config: LimiterConfig,
    clock: Arc<FakeClock>,
    failure: FailureMode,
) -> RedisLimiter {
    RedisLimiter::connect(&server.url, config, clock, test_hasher(), failure)
        .await
        .expect("connect to Redis")
}

async fn redis_limiter(config: LimiterConfig, clock: Arc<FakeClock>) -> TestLimiter {
    let server = redis_server().await;
    let limiter = connect(&server, config, clock, FailureMode::Closed).await;
    TestLimiter {
        limiter: Arc::new(limiter),
        _guard: Box::new(server),
    }
}

limiter_contract_tests!(
    redis_backend,
    crate::redis_limiter,
    #[ignore = "needs Docker: run with `just test-redis`"]
);

// --- metrics capture (test-local recorder) ---------------------------------------------------

#[derive(Default)]
struct CapturedCounter(AtomicU64);

impl CounterFn for CapturedCounter {
    fn increment(&self, value: u64) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }
    fn absolute(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

/// Counters by `name{label=value,...}` (labels sorted).
#[derive(Default)]
struct Capture(Mutex<BTreeMap<String, Arc<CapturedCounter>>>);

impl Capture {
    fn get(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
        let mut labels: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        labels.sort();
        let id = format!("{name}{{{}}}", labels.join(","));
        self.0
            .lock()
            .unwrap()
            .get(&id)
            .map_or(0, |c| c.0.load(Ordering::Relaxed))
    }

    fn errors(&self, operation: &str, reason: &str) -> u64 {
        self.get(
            "anvil_ratelimit_backend_errors_total",
            &[("operation", operation), ("reason", reason)],
        )
    }
}

impl metrics::Recorder for Capture {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        let mut labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        labels.sort();
        let id = format!("{}{{{}}}", key.name(), labels.join(","));
        let counter = self.0.lock().unwrap().entry(id).or_default().clone();
        Counter::from_arc(counter)
    }

    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }

    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

fn health_log() -> (
    Arc<Mutex<Vec<BackendHealth>>>,
    anvil_cache::limiter::HealthObserver,
) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    (log, Arc::new(move |h| sink.lock().unwrap().push(h)))
}

// --- Redis-specific guarantees ---------------------------------------------------------------

#[tokio::test]
async fn redis_connect_fails_fast_when_unreachable() {
    let started = Instant::now();
    // Port 1 (tcpmux) is not a Redis server on any CI runner or dev host.
    let err = RedisLimiter::connect(
        "redis://:hunter2@127.0.0.1:1/0",
        LimiterConfig::default(),
        FakeClock::new(),
        test_hasher(),
        FailureMode::Closed,
    )
    .await
    .err()
    .expect("connect must fail");
    assert!(matches!(err, RedisInitError::Unreachable(_)), "{err:?}");
    assert!(!err.to_string().contains("hunter2"), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    let err = RedisLimiter::connect(
        "http://:hunter2@127.0.0.1/",
        LimiterConfig::default(),
        FakeClock::new(),
        test_hasher(),
        FailureMode::Closed,
    )
    .await
    .err()
    .expect("invalid URL must fail");
    assert_eq!(err, RedisInitError::InvalidUrl);
    assert!(!err.to_string().contains("hunter2"), "{err}");
}

#[tokio::test]
#[ignore = "needs Docker: run with `just test-redis`"]
async fn redis_instances_share_one_budget() {
    let server = redis_server().await;
    let clock = FakeClock::new();
    let a = connect(&server, gcra_config(), clock.clone(), FailureMode::Closed).await;
    let b = connect(&server, gcra_config(), clock.clone(), FailureMode::Closed).await;

    // Token burst 3, requests alternating between two nodes: 3 allowed in total, not 6.
    let key = ip(1);
    let mut allowed = 0;
    for i in 0..6 {
        let node: &dyn RateLimiter = if i % 2 == 0 { &a } else { &b };
        if node.check(RouteClass::Token, &key).await == Decision::Allow {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 3);

    // Brute-force state is shared too: failures on one node lock the key on the other.
    let tenant = TenantId::new_v7();
    for _ in 0..6 {
        a.record_failure(&strict(tenant, 1)).await;
    }
    assert_eq!(
        b.backoff(&strict(tenant, 1)).await,
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        b.brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), true)
            .await,
        Decision::Deny {
            retry_after: Duration::from_secs(1)
        }
    );
    b.record_success(&strict(tenant, 1)).await;
    assert_eq!(a.backoff(&strict(tenant, 1)).await, None);
}

#[tokio::test]
#[ignore = "needs Docker: run with `just test-redis`"]
async fn redis_key_names_are_hashed() {
    let server = redis_server().await;
    let clock = FakeClock::new();
    let l = connect(&server, gcra_config(), clock, FailureMode::Closed).await;
    let tenant = TenantId::new_v7();
    let ident = [0xab_u8; 32];
    let ident_ip = LimitKey::IdentIp {
        tenant,
        ident,
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)),
    };
    let client = LimitKey::Client {
        tenant,
        client_id: "very-secret-client".into(),
    };
    l.check(RouteClass::Token, &ip(77)).await;
    l.check(RouteClass::Token, &client).await;
    l.check(RouteClass::Auth, &ident_ip).await;
    l.record_failure(&ident_ip).await;
    l.record_failure(&LimitKey::Identifier { tenant, ident })
        .await;

    let client_conn = redis::Client::open(server.url.as_str()).unwrap();
    let mut conn = client_conn
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("*")
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(keys.len(), 5, "{keys:?}");
    let classes = ["auth", "token", "token_client", "admin", "default", "bf"];
    for k in &keys {
        let rest = k.strip_prefix("anvil:rl:").unwrap_or_else(|| panic!("{k}"));
        let (class, digest) = rest.split_once(':').unwrap_or_else(|| panic!("{k}"));
        assert!(classes.contains(&class), "{k}");
        assert_eq!(digest.len(), 64, "{k}");
        assert!(
            digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "{k}"
        );
        assert!(
            !k.contains("192.0.2") && !k.contains("very-secret-client"),
            "{k}"
        );
        assert!(!k.contains(&hex(&ident)), "{k}");
    }
    // The digest is the injected hasher over the canonical key.
    let expected = format!(
        "anvil:rl:token:{}",
        hex(&test_hasher()(&canonical(&ip(77))))
    );
    assert!(keys.contains(&expected), "{keys:?}");
}

#[tokio::test]
#[ignore = "needs Docker: run with `just test-redis`"]
async fn redis_outage_auth_and_gate_fail_closed_breaker_skips_then_recovers() {
    let capture = Capture::default();
    let _recorder = metrics::set_default_local_recorder(&capture);
    let server = redis_server().await;
    let clock = FakeClock::new();
    let (log, observer) = health_log();
    let l = connect(&server, gcra_config(), clock.clone(), FailureMode::Closed)
        .await
        .with_health_observer(observer);
    let witness = connect(&server, gcra_config(), clock.clone(), FailureMode::Closed).await;
    let tenant = TenantId::new_v7();
    assert_eq!(l.check(RouteClass::Auth, &ip(1)).await, Decision::Allow);

    server.container.pause().await.expect("pause Redis");

    // First call: Redis times out -> the auth class fails closed for the cool-down.
    let d = l.check(RouteClass::Auth, &ip(2)).await;
    assert_eq!(
        d,
        Decision::Deny {
            retry_after: BREAKER_COOL_DOWN
        }
    );
    assert_eq!(capture.errors("check", "error"), 1);
    assert_eq!(*log.lock().unwrap(), vec![BackendHealth::Degraded]);

    // Within the cool-down Redis is not touched at all (breaker), and still fails closed.
    clock.advance(Duration::from_secs(1));
    let started = Instant::now();
    assert_eq!(
        l.check(RouteClass::Auth, &ip(3)).await,
        Decision::Deny {
            retry_after: BREAKER_COOL_DOWN - Duration::from_secs(1)
        }
    );
    assert!(matches!(
        l.brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), true)
            .await,
        Decision::Deny { .. }
    ));
    assert!(
        started.elapsed() < Duration::from_millis(40),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(capture.errors("check", "error"), 1);
    assert_eq!(capture.errors("check", "breaker_open"), 1);
    assert_eq!(capture.errors("brute_force_gate", "breaker_open"), 1);

    // Non-auth classes use the embedded in-process limiter (token burst 3, then its denial).
    for _ in 0..3 {
        assert_eq!(l.check(RouteClass::Token, &ip(4)).await, Decision::Allow);
    }
    assert_eq!(
        l.check(RouteClass::Token, &ip(4)).await,
        Decision::Deny {
            retry_after: Duration::from_secs(10)
        }
    );
    // Backoff bookkeeping continues locally.
    assert_eq!(
        l.record_failure(&strict(tenant, 2)).await,
        Backoff {
            failures: 1,
            locked_for: None
        }
    );
    assert_eq!(capture.errors("check", "breaker_open"), 5);
    assert_eq!(capture.errors("record_failure", "breaker_open"), 1);
    assert_eq!(log.lock().unwrap().len(), 1, "one report per state change");

    // Recovery: after the cool-down one probe reaches Redis again.
    server.container.unpause().await.expect("unpause Redis");
    clock.advance(BREAKER_COOL_DOWN);
    let key = ip(5);
    for _ in 0..2 {
        assert_eq!(l.check(RouteClass::Auth, &key).await, Decision::Allow);
    }
    assert_eq!(
        *log.lock().unwrap(),
        vec![BackendHealth::Degraded, BackendHealth::Healthy]
    );
    // The decisions are shared again: another node sees the exhausted budget.
    assert!(matches!(
        witness.check(RouteClass::Auth, &key).await,
        Decision::Deny { .. }
    ));
    assert_eq!(capture.errors("check", "error"), 1);
}

#[tokio::test]
#[ignore = "needs Docker: run with `just test-redis`"]
async fn redis_outage_local_mode_uses_the_in_process_limiter() {
    let capture = Capture::default();
    let _recorder = metrics::set_default_local_recorder(&capture);
    let server = redis_server().await;
    let clock = FakeClock::new();
    let l = connect(&server, gcra_config(), clock.clone(), FailureMode::Local).await;
    let tenant = TenantId::new_v7();

    server.container.pause().await.expect("pause Redis");

    // Auth: the in-process decision (burst 2, then retry after one 10 s interval).
    assert_eq!(l.check(RouteClass::Auth, &ip(1)).await, Decision::Allow);
    assert_eq!(l.check(RouteClass::Auth, &ip(1)).await, Decision::Allow);
    assert_eq!(
        l.check(RouteClass::Auth, &ip(1)).await,
        Decision::Deny {
            retry_after: Duration::from_secs(10)
        }
    );
    // Gate: in-process too, including locks from failures recorded during the outage.
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), true)
            .await,
        Decision::Allow
    );
    for _ in 0..6 {
        l.record_failure(&strict(tenant, 1)).await;
    }
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), true)
            .await,
        Decision::Deny {
            retry_after: Duration::from_secs(1)
        }
    );
    assert_eq!(capture.errors("check", "error"), 1);
    assert!(capture.errors("record_failure", "breaker_open") >= 6);

    server.container.unpause().await.expect("unpause Redis");
}
