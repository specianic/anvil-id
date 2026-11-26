---
phase: 05-release-0-4-operate-it
plan: 05
subsystem: config, observability, operations
tags: [config, health, readiness, drain, prometheus, metrics, opentelemetry, otlp, tracing, pool, jobs, limiter, qual-05]

requires:
  - phase: 05-01
    provides: metrics, metrics-exporter-prometheus, opentelemetry(+sdk, otlp), tracing-opentelemetry dependencies
provides:
  - "Eight installation config keys (redis_url, rate_limit_redis_failure, metrics_listen, metrics_on_main_port, otel_endpoint, otel_service_name, shutdown_drain, database_max_connections)"
  - "/readyz alias of /health/ready; AppState readiness flag; drain on SIGTERM"
  - "anvil_web::observability: request span/log/metrics layer, metric names + owners, metrics_router, TraceContextHook"
  - "anvilid telemetry.rs: init_tracing + OTLP + TelemetryGuard, Prometheus recorder, upkeep"
  - "jobs::BackgroundWorker + spawn_workers; Started.workers"
  - "limiter::build_limiter -> AppState::new_with_limiter (single construction site)"
  - "AppState::unknown_hosts() (05-18) and AppState::cimd_fetch_permits() (05-15)"
  - "scripts/measure-idle.sh QUAL-05 gate (VmRSS < 102400 kB)"
affects: [05-08, 05-09, 05-12, 05-14, 05-15, 05-16, 05-18, 05-26, 05-27]

tech-stack:
  added: []
  patterns:
    - "Request telemetry from response extensions: route_layer hands the MatchedPath back, the post-resolution layer hands tenant + route class back, the outer layer records span/log/metrics"
    - "Metric labels are bounded classes only (route_class, status_class, outcome, job, grant); tenant slug only in spans/logs"
    - "Process-wide recorder installed only when metrics are exposed; tests use with_local_recorder (anvilid) or a capture recorder per test binary (anvil-web)"
    - "Continuous workers implement BackgroundWorker and start through jobs::spawn_workers"

key-files:
  created:
    - crates/anvil-web/src/observability.rs
    - crates/anvilid/src/telemetry.rs
    - crates/anvilid/src/limiter.rs
    - crates/anvilid/tests/config_phase5.rs
    - crates/anvil-web/tests/health_metrics.rs
  modified:
    - crates/anvilid/src/{config,main,server,startup,storage,jobs}.rs
    - crates/anvilid/tests/serve.rs
    - crates/anvil-web/src/{config,state,lib,health}.rs
    - crates/anvil-web/src/layers/ratelimit.rs
    - scripts/measure-idle.sh

key-decisions:
  - "Health and /metrics routes moved to the outer router (outside tenant resolution and rate limiting); /t/{slug}/health/* no longer exists"
  - "AppConfig.metrics is a render callback (MetricsEndpoint), not PrometheusHandle: anvil-web has no exporter dependency and manifests are 05-01's"
  - "otel_endpoint is a base URL; /v1/traces is appended unless present"
  - "traceparent is continued only when the TCP peer is in trusted_proxies, through an AppConfig.trace_context hook supplied by the binary (anvil-web has no OpenTelemetry dependency)"
  - "anvil_jobs_runs_total outcomes are ran / lease_held / lease_error: PeriodicJob::run returns () and tests implement the trait, so the job result is not observable without a trait change"
  - "The outbox worker also moved onto BackgroundWorker (one worker abstraction), not only the logout worker"
  - "The rate-limited log line no longer carries the client IP"

requirements-completed: []

duration: ~27min
completed: 2026-11-26
---

# Phase 5 Plan 05: Config and observability plumbing Summary

**Health/readiness with drain on SIGTERM, Prometheus metrics on a separate listener or the main port, OTLP/HTTP traces flushed at shutdown, one request span/log/metrics layer that records route templates and bounded class labels only, a configurable Postgres pool, one BackgroundWorker abstraction, one limiter construction site, and an idle-memory gate.**

## Performance

- **Duration:** about 27 min (02:44Z to 03:12Z)
- **Tasks:** 3/3
- **Files:** 5 created, 13 modified

## Config keys

| Key | Env | Flag | Default | Validation |
| --- | --- | ---- | ------- | ---------- |
| `redis_url` (secret) | `ANVILID_REDIS_URL` | none (env/file only) | unset | `redis://` or `rediss://` with a host; never echoed; userinfo redacted in `config show`. Set: `serve` fails with "redis_url is not supported yet" (TRANSITIONAL(05-16)) before the database opens |
| `rate_limit_redis_failure` | `ANVILID_RATE_LIMIT_REDIS_FAILURE` | `--rate-limit-redis-failure` | `closed` | `closed` or `local` (`Config.redis_failure: RedisFailure`) |
| `metrics_listen` | `ANVILID_METRICS_LISTEN` | `--metrics-listen` | unset | socket address, must differ from `listen` |
| `metrics_on_main_port` | `ANVILID_METRICS_ON_MAIN_PORT` | `--metrics-on-main-port` | false | bool; warning that /metrics is reachable on the main listener |
| `otel_endpoint` | `ANVILID_OTEL_ENDPOINT` | `--otel-endpoint` | unset | absolute http(s) URL; userinfo redacted in `config show` and in `Debug` (`CredentialUrl`) |
| `otel_service_name` | `ANVILID_OTEL_SERVICE_NAME` | `--otel-service-name` | `anvilid` | 1..255 printable chars |
| `shutdown_drain` | `ANVILID_SHUTDOWN_DRAIN` | `--shutdown-drain` | `0s` | `10s`, `500ms`, `1m`, `2h`, or plain seconds (TOML integer too); at most 1 h |
| `database_max_connections` | `ANVILID_DATABASE_MAX_CONNECTIONS` | `--database-max-connections` | 10 | 1..=1000; passed to `PostgresStorage::connect`, SQLite ignores it |

`storage::open_storage(url, migrations, max_connections)`: all three callers pass `cfg.database_max_connections`.

## Health and drain

- `/health/live` and `/healthz` serve liveness. `/health/ready` and `/readyz` use one `ready` handler: 503 `draining` when `AppState::is_ready()` is false, otherwise the storage check (503 `unavailable` if it fails).
- All of these are on the outer router, so they skip tenant resolution and rate limiting. `/readyz` and `/metrics` were also added to the ratelimit EXEMPT list.
- On SIGTERM or ctrl-c, serve calls `state.set_ready(false)`, logs "readiness is 503; draining before shutdown", sleeps `shutdown_drain`, and then flips the existing stop channel (graceful server shutdown, then the jobs).

## Metrics (anvil_web::observability)

| Name | Labels | Owner |
| ---- | ------ | ----- |
| `anvil_http_requests_total` | route_class, status_class | `observe` (this plan) |
| `anvil_http_request_duration_seconds` (histogram, buckets 1 ms to 5 s) | route_class | `observe` (this plan) |
| `anvil_ratelimit_rejections_total` | route_class | `layers/ratelimit.rs` layer + `guard_attempt` (this plan) |
| `anvil_auth_attempts_total` | outcome (success/failure) | `record_attempt` (this plan) |
| `anvil_jobs_runs_total` | job, outcome (ran/lease_held/lease_error) | `jobs.rs` `LeaseRunner::run_once` (this plan) |
| `anvil_tokens_issued_total` / `anvil_refresh_reuse_total` | grant / none | 05-12 |
| `anvil_webhook_deliveries_total` | outcome | 05-14 |
| `anvil_ratelimit_backend_errors_total` | none | 05-08 |

- Constants, `METRIC_NAMES`, `DURATION_BUCKETS`, `describe_metrics()`, `class_label()`, `status_class()` and `record_request()` are public. `anvil_db_pool_connections` is dropped.
- route_class takes one of these values: auth, token, admin, default, health, metrics, console, assets.
- The span is `http.request` with fields `method`, `route` (MatchedPath template or `unmatched`), `tenant` (slug), `status`, `latency_ms` and `request_id`. `request_id` is the generated UUID, or a client-sent id only if it contains nothing but id characters. The access log line uses target `anvil_web::access` and has the same fields. TraceLayer is gone.
- `/metrics`: `metrics_router(MetricsEndpoint)` serves GET /metrics and nothing else. With `metrics_listen` it runs on its own plain-HTTP listener (`server::run_metrics`). With `metrics_on_main_port` it is merged into the main router through `AppConfig.metrics`. When neither is set the route returns 404, and no recorder is installed.
- `telemetry::install_metrics()` (`PrometheusBuilder::new().set_buckets_for_metric(..).install_recorder()` plus descriptions) runs once, and `telemetry::upkeep` runs every 5 s until shutdown.

## Traces

- `telemetry::init_tracing(format, Option<OtelConfig>) -> TelemetryGuard` replaces the one in main.rs. The fmt and AuditStdout layers are unchanged. When `otel_endpoint` is set it adds the `tracing_opentelemetry` layer, which uses the OTLP/HTTP protobuf batch exporter and its own blocking client (not OutboundClient). The resource carries `service.name` and `service.version`. The OTel layer uses the same RUST_LOG filter and never exports `audit` events.
- When `otel_endpoint` is unset, no OTel layer is installed. Exporter build errors are generic, so the endpoint is never echoed.
- `TelemetryGuard::shutdown()` (`provider.shutdown()`) runs in `spawn_blocking` at the end of serve.
- `traceparent`: observe calls `AppConfig.trace_context` (`TraceContextHook`) only when the ConnectInfo peer passes `trusted_proxies.is_trusted`. The binary's hook uses `TraceContextPropagator` and `set_parent`.

## BackgroundWorker API (jobs.rs)

```rust
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
pub trait BackgroundWorker: Send {
    fn name(&self) -> &'static str;
    fn run(self: Box<Self>, stop: BoxFuture) -> BoxFuture;
}
pub fn spawn_workers(jobs: &mut JoinSet<()>, workers: Vec<Box<dyn BackgroundWorker>>, shutdown: &watch::Receiver<bool>);
```
- Implemented for `LogoutDeliveryWorker` (`backchannel_logout`) and `OutboxWorker` (`outbox`). `spawn_logout_worker` was removed.
- `startup::Started` now has `state: AppState` and `workers: Vec<Box<dyn BackgroundWorker>>`; the logout worker is pushed there. 05-14 pushes its webhook worker in startup.rs.
- `startup::start(cfg, Observability { metrics, trace_context })`.

## Limiter hook

- `limiter::build_limiter(cfg, clock, &kek) -> anyhow::Result<Arc<dyn RateLimiter>>` returns `InProcessLimiter` when `redis_url` is unset and bails with TRANSITIONAL(05-16) otherwise. Startup calls it right after the KEK is loaded and before storage opens, then calls `AppState::new_with_limiter`. `AppState::new` (tests) delegates.
- `grep InProcessLimiter::new` outside tests finds only anvilid/src/limiter.rs and state.rs (`AppState::new`).

## AppState pre-declared handles

- `pub(crate) fn unknown_hosts(&self) -> &moka::sync::Cache<String, ()>`: capacity 10,000, TTL `AppConfig.unknown_host_ttl` (default 5 s, `DEFAULT_UNKNOWN_HOST_TTL`). For 05-18.
- `pub(crate) fn cimd_fetch_permits(&self) -> Arc<Semaphore>`: 16 permits (`CIMD_FETCH_PERMITS`). For 05-15.
- Both are built in `new_with_limiter` and marked `#[allow(dead_code, reason = ...)]` until their owners use them.
- New AppConfig fields (owned here): `unknown_host_ttl`, `metrics: Option<MetricsEndpoint>`, `trace_context: Option<TraceContextHook>`.

## Task Commits

1. **Task 1: config keys, pool, health/readiness drain, BackgroundWorker, limiter hook, AppState handles:** `a8d9895`
2. **Task 2: request layer, metrics recorder, /metrics:** `1f01b4f`
3. **Task 3: OTLP traces, shutdown flush, trusted-proxy traceparent, idle gate:** `35e9706`

## Verification run

- `cargo test -p anvilid --test config_phase5`: 8 passed. The tests cover:
  - defaults
  - every key from env and from the file, and every non-secret key from a flag winning over env
  - redis_url being rejected as a flag
  - redaction of credentials in Redis and OTel URLs
  - 12 invalid values, each failing with the key named and nothing echoed
  - serve refusing redis_url before the database file exists
- `cargo test -p anvilid --test serve`: 10 passed. New tests:
  - SIGTERM with a 2 s drain: /readyz and /health/ready return 503 `draining` at once, /healthz and discovery are still served, and the process exits 0 after the drain.
  - metrics_listen: the listener serves only /metrics, including `_bucket` lines and no address, and the main port returns 404 for it.
  - metrics_on_main_port.
  - otel_endpoint pointing at a local wiremock collector: it receives `application/x-protobuf` on /v1/traces after shutdown, carrying `service.name`, the service name, `http.request` and `/authorize`, and without the login hint, `login_hint` or 127.0.0.1.
- `cargo test -p anvilid` (all targets): 91 passed.
- `cargo test -p anvilid --bin anvilid telemetry`: 6 passed. They cover:
  - histogram buckets with class labels only
  - job runs counted
  - the metrics listener serving only /metrics
  - in-memory exporter: service.name and service.version, no audit events
  - traceparent continuation (trace and parent ids)
  - traces_url
- `cargo test -p anvil-web --test health_metrics`: 8 passed. They cover:
  - health aliases
  - the readiness flag
  - probes with an unknown Host and far above the quota
  - the label hygiene test after login GET, failed login, successful login, client_credentials token and `/t/acme/authorize?login_hint=alice@example.com`: no email, client ids, `acme`, peer IP, `/authorize?`, `login_hint` or `/t/`, label names restricted to the known set, auth_attempts failure and success both counted
  - the /metrics route per configuration
  - the span test: route `/authorize`, tenant `acme`, status, latency_ms, no query/email/state/client_id/IP, access log present
  - the negative test that untrusted peers' traceparent is ignored
- `cargo test -p anvil-web` (all targets, SQLite): 890 passed, 0 failed.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean. The only remaining warnings are manifest `unused dependency` notes for crates later plans use.
- `rustfmt --edition 2024` on every touched file.
- `bash -n scripts/measure-idle.sh`, plus a run against the debug binary: VmRSS 85,660 kB, below the limit, exit 0.

## Not run

- Postgres variants (Docker): the pool size is passed to `PostgresStorage::connect` but not exercised against a live Postgres here. CI runs those.
- `cargo check --manifest-path fuzz/Cargo.toml` (it needs a separate target dir; skipped to keep disk use low; this plan adds no fuzz-visible struct literals).
- shellcheck (not installed). The over-limit branch of measure-idle.sh was not exercised with a real >100 MB process.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Security] No client IP in the rate-limited log line**
- `layers/ratelimit.rs` logged `ip = %ip.0` at info. It now logs only the class. The task requires that no client IPs appear in operational telemetry.

**2. [Rule 2 - Security] Client-sent request ids filtered**
- SetRequestIdLayer keeps a client-supplied `x-request-id`. The span records it only if it is at most 64 characters drawn from `[A-Za-z0-9._-]`, so an arbitrary client string is not copied into spans.

**3. [Rule 3 - Blocking] AppConfig.metrics is a render callback**
- The plan says `metrics: Option<PrometheusHandle>`. anvil-web has no `metrics-exporter-prometheus` dependency, and Cargo manifests belong to 05-01, so it is `Option<MetricsEndpoint>` (an `Arc<dyn Fn() -> String>`) built from the handle by `telemetry::endpoint`.

**4. [Rule 3 - Blocking] traceparent hook in AppConfig**
- anvil-web has no OpenTelemetry dependency. The trusted-proxy check lives in anvil-web's `observe`, and the extraction lives in the binary's hook (`AppConfig.trace_context`).

**5. [Rule 3 - Blocking] Span test with a hand-written subscriber; Prometheus `_bucket` assertion in anvilid**
- anvil-web has neither tracing-subscriber nor the exporter as dev-deps. So `health_metrics.rs` uses a minimal capture `Subscriber` and a capture `Recorder`. The `_bucket` rendering is asserted in `telemetry.rs` unit tests and in serve.rs against the real exporter.

**6. [Rule 3 - Blocking] `--lib` verify commands**
- anvilid has no library target. The plan's `cargo test -p anvilid --lib ...` commands were run as `--bin anvilid`.

**7. [Rule 1 - Correctness] Probes moved outside tenant resolution**
- Health routes were inside the tenant-routed service, so `/readyz` would have depended on a default-tenant and host lookup. They are now on the outer router with `/metrics`.

### Notes
- `jobs_runs_total` outcome semantics differ (ran/lease_held/lease_error). See key-decisions.
- `Config.redis_failure` carries `#[allow(dead_code)]` until 05-16 reads it.
- Logged for 05-27 in deferred-items.md: ARCHITECTURE §2/§15 still say OTel is behind a feature, and OPERATIONS needs the otel_endpoint semantics, the traceparent policy, the metrics listener, the drain and the pool size.

## Self-Check: PASSED
