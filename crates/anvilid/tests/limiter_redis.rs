//! The shared Redis rate limiter, end to end through the binary (OPS-03): `anvilid serve` nodes
//! on one Postgres database and one Redis share the token-class budget of a client, and a Redis
//! outage follows `rate_limit_redis_failure` (Q8): login POSTs fail closed (429 with
//! `Retry-After`) in `closed` mode and use per-node limits in `local` mode, `/token` keeps issuing
//! tokens, and `anvil_ratelimit_backend_errors_total` counts the fallbacks. Shared limiting
//! resumes after the breaker cool-down.
//!
//! Every test has `redis` in its name and is `#[ignore]`d: they need Docker (Redis and Postgres
//! containers) and run with `just test-redis` (`ANVILID_TEST_REDIS=1 ... --include-ignored`). A
//! run without `ANVILID_TEST_REDIS=1` fails loudly instead of skipping. An unreachable Redis at
//! startup is covered without Docker by `config_phase5::redis_url_unreachable_fails_startup_explicitly`.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anvil_cache::limiter::BREAKER_COOL_DOWN;
use anvil_core::model::SYSTEM_TENANT_SLUG;
use anvil_core::ports::Storage;
use anvil_core::service::bootstrap::build_mgmt_client;
use anvil_jose::Kek;
use anvil_storage_postgres::PostgresStorage;
use secrecy::ExposeSecret;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use time::OffsetDateTime;

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
/// Per-client token budget of every node in these tests (burst = rate).
const TOKEN_CLIENT_BURST: usize = 3;
/// Requests sent for one client, alternating between two nodes: per-node limits would allow
/// `2 * TOKEN_CLIENT_BURST` of them.
const BUDGET_REQUESTS: usize = 2 * TOKEN_CLIENT_BURST + 2;

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Redis and Postgres containers for one test. Dropping it removes both.
struct Backends {
    redis: ContainerAsync<Redis>,
    _postgres: ContainerAsync<Postgres>,
    redis_url: String,
    database_url: String,
    kek: String,
}

async fn backends() -> Backends {
    assert_eq!(
        std::env::var("ANVILID_TEST_REDIS").as_deref(),
        Ok("1"),
        "Redis tests run through `just test-redis` (ANVILID_TEST_REDIS=1, Docker)"
    );
    let redis = Redis::default()
        .with_tag("7.2-alpine")
        .start()
        .await
        .expect("start Redis container (Docker)");
    let host = redis.get_host().await.expect("container host");
    let port = redis
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("container port");
    let (postgres, server_url) = anvil_storage::postgres_container::start(100).await;
    Backends {
        redis,
        _postgres: postgres,
        redis_url: format!("redis://{host}:{port}"),
        database_url: format!("{server_url}/postgres"),
        // Generated per run; never a fixed key.
        kek: Kek::generate().to_base64().expose_secret().to_owned(),
    }
}

/// One `anvilid serve` process; killed on drop. Logs go to a file so a chatty server can never
/// block on a full pipe.
struct Node {
    child: Child,
    port: u16,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn spawn(backends: &Backends, failure_mode: &str) -> Node {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = free_port();
        let log = dir.path().join("anvilid.log");
        let mut cmd = Command::new(BIN);
        cmd.arg("serve")
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--public-url")
            .arg(format!("http://127.0.0.1:{port}"))
            .arg("--data-dir")
            .arg(dir.path())
            .arg("--database-url")
            .arg(&backends.database_url)
            .arg("--breach-check")
            .arg("off")
            .arg("--metrics-on-main-port")
            .current_dir(dir.path())
            .env_clear()
            .env("ANVILID_KEK", &backends.kek)
            .env("ANVILID_REDIS_URL", &backends.redis_url)
            .env("ANVILID_RATE_LIMIT_REDIS_FAILURE", failure_mode)
            .env(
                "ANVILID_RATE_LIMIT_TOKEN_CLIENT_PER_SECOND",
                TOKEN_CLIENT_BURST.to_string(),
            )
            .stdin(Stdio::null())
            .stdout(File::create(&log).expect("log file"))
            .stderr(File::create(dir.path().join("anvilid.err")).expect("log file"));
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        let mut node = Node {
            child: cmd.spawn().expect("spawn anvilid"),
            port,
            log,
            _dir: dir,
        };
        node.wait_healthy();
        node
    }

    fn logs(&self) -> String {
        let dir = self.log.parent().expect("log dir");
        let out = std::fs::read_to_string(&self.log).unwrap_or_default();
        let err = std::fs::read_to_string(dir.join("anvilid.err")).unwrap_or_default();
        format!("{out}{err}")
    }

    fn wait_healthy(&mut self) {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                panic!("anvilid exited early with {status}: {}", self.logs());
            }
            if healthz_ok(self.port) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "anvilid did not become healthy: {}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

/// `GET /healthz` answers 200 (plain blocking HTTP/1.1; no runtime needed).
fn healthz_ok(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    if write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .is_err()
    {
        return false;
    }
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    raw.lines().next().is_some_and(|l| l.contains(" 200 "))
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}

/// `POST /token` (client_credentials) for an unknown client: 401 while the budget lasts, 429
/// after. Returns the status.
async fn token_for_unknown_client(node: &Node, client_id: &str) -> reqwest::StatusCode {
    http()
        .post(node.url("/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=client_credentials&client_id={client_id}&client_secret=wrong"
        ))
        .send()
        .await
        .expect("POST /token")
        .status()
}

/// Sends [`BUDGET_REQUESTS`] token requests for `client_id`, alternating between `a` and `b`,
/// and returns how many were not rate limited.
async fn allowed_across(a: &Node, b: &Node, client_id: &str) -> usize {
    let mut allowed = 0;
    for i in 0..BUDGET_REQUESTS {
        let node = if i % 2 == 0 { a } else { b };
        let status = token_for_unknown_client(node, client_id).await;
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            continue;
        }
        assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "unknown client");
        allowed += 1;
    }
    allowed
}

/// One shared budget: exactly the burst (one more at most, refilled while the requests ran),
/// never the per-node total.
fn assert_shared_budget(allowed: usize) {
    assert!(
        (TOKEN_CLIENT_BURST..=TOKEN_CLIENT_BURST + 1).contains(&allowed),
        "{allowed} of {BUDGET_REQUESTS} requests allowed across two nodes; one shared budget \
         allows {TOKEN_CLIENT_BURST}, per-node budgets {}",
        2 * TOKEN_CLIENT_BURST
    );
}

/// `POST /ui/login` with an empty body: the rate-limit layer decides before the handler, so
/// the status is 429 or whatever the handler answers to an invalid form.
async fn login_post(node: &Node) -> reqwest::Response {
    http()
        .post(node.url("/ui/login"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .expect("POST /ui/login")
}

/// Creates a client_credentials client in the system tenant; returns (client_id, secret).
async fn create_client(database_url: &str) -> (String, String) {
    let storage = PostgresStorage::connect(database_url, 2)
        .await
        .expect("connect to Postgres");
    let system = storage
        .tenants()
        .get_by_slug(SYSTEM_TENANT_SLUG)
        .await
        .expect("tenant lookup")
        .expect("installed");
    let (client, secret) = build_mgmt_client(OffsetDateTime::now_utc());
    storage
        .clients()
        .create(system.id, &client)
        .await
        .expect("create client");
    (client.client_id, secret.expose_secret().to_owned())
}

async fn client_credentials_token(node: &Node, client: &(String, String)) -> reqwest::StatusCode {
    http()
        .post(node.url(&format!("/t/{SYSTEM_TENANT_SLUG}/token")))
        .basic_auth(&client.0, Some(&client.1))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials")
        .send()
        .await
        .expect("POST /token")
        .status()
}

/// Sum of `anvil_ratelimit_backend_errors_total` over all label sets (0 when absent).
async fn backend_errors(node: &Node) -> f64 {
    let body = http()
        .get(node.url("/metrics"))
        .send()
        .await
        .expect("GET /metrics")
        .text()
        .await
        .expect("metrics body");
    body.lines()
        .filter(|l| l.starts_with("anvil_ratelimit_backend_errors_total"))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker: run with `just test-redis`"]
async fn redis_two_nodes_share_one_client_token_budget() {
    let backends = backends().await;
    let a = Node::spawn(&backends, "closed");
    let b = Node::spawn(&backends, "closed");
    let allowed = allowed_across(&a, &b, "shared-budget-client").await;
    assert_shared_budget(allowed);
    let errors = backend_errors(&a).await + backend_errors(&b).await;
    assert!(
        errors == 0.0,
        "no backend errors while Redis is healthy: {errors}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker: run with `just test-redis`"]
async fn redis_outage_login_fails_closed_or_local_token_keeps_issuing_then_recovers() {
    let backends = backends().await;
    let closed = Node::spawn(&backends, "closed");
    let local = Node::spawn(&backends, "local");
    let client = create_client(&backends.database_url).await;
    for node in [&closed, &local] {
        assert_eq!(
            client_credentials_token(node, &client).await,
            reqwest::StatusCode::OK
        );
        assert_ne!(
            login_post(node).await.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "healthy Redis: a first login POST is not limited"
        );
    }
    let errors_before = backend_errors(&closed).await + backend_errors(&local).await;

    // Outage: Redis stops answering (paused, so every call times out).
    backends.redis.pause().await.expect("pause Redis");

    // closed: login POST fails closed with Retry-After (the rest of the breaker cool-down).
    let resp = login_post(&closed).await;
    assert_eq!(resp.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = resp
        .headers()
        .get("retry-after")
        .expect("Retry-After on the fail-closed 429")
        .to_str()
        .expect("ascii")
        .parse()
        .expect("whole seconds");
    assert!(
        (1..=BREAKER_COOL_DOWN.as_secs()).contains(&retry_after),
        "Retry-After {retry_after}"
    );
    // local: per-node limits, so the first login POST passes the limiter.
    assert_ne!(
        login_post(&local).await.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "local mode uses the per-node limiter"
    );
    // /token keeps issuing on both nodes (token class falls back to per-node limits).
    for node in [&closed, &local] {
        assert_eq!(
            client_credentials_token(node, &client).await,
            reqwest::StatusCode::OK,
            "/token must keep issuing during a Redis outage"
        );
    }
    let errors_during = backend_errors(&closed).await + backend_errors(&local).await;
    assert!(
        errors_during > errors_before,
        "anvil_ratelimit_backend_errors_total must increment ({errors_before} -> {errors_during})"
    );

    // Recovery: after the breaker cool-down one probe reaches Redis and limits are shared again.
    backends.redis.unpause().await.expect("unpause Redis");
    tokio::time::sleep(BREAKER_COOL_DOWN + Duration::from_secs(1)).await;
    // The first call after the cool-down probes Redis and closes the breaker.
    let _ = token_for_unknown_client(&closed, "probe-client").await;
    let _ = token_for_unknown_client(&local, "probe-client").await;
    assert_ne!(
        login_post(&closed).await.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "closed mode stops failing closed once Redis is back"
    );
    let allowed = allowed_across(&closed, &local, "after-recovery-client").await;
    assert_shared_budget(allowed);
    let logs = closed.logs();
    assert!(
        logs.contains("rate-limit backend (Redis) unavailable"),
        "degraded state is logged: {logs}"
    );
    assert!(
        logs.contains("rate-limit backend (Redis) reachable again"),
        "recovery is logged: {logs}"
    );
    assert!(
        !logs.contains(&backends.redis_url),
        "the Redis URL is never logged"
    );
}
