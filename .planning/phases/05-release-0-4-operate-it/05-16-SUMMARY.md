---
phase: 05-release-0-4-operate-it
plan: 16
subsystem: rate-limiting, startup
tags: [redis, rate-limit, hmac, failure-mode, concurrent-start, postgres, ops-03]

requires:
  - phase: 05-release-0-4-operate-it
    provides: "05-05: build_limiter hook, redis_url / rate_limit_redis_failure config; 05-08: RedisLimiter, FailureMode, KeyHasher, HealthObserver; 05-06/05-07: storage for Phase 5"
provides:
  - "redis_url -> RedisLimiter selection in the one construction site (crates/anvilid/src/limiter.rs); TRANSITIONAL(05-16) removed"
  - "Key-name hasher: HMAC-SHA-256 under Kek::derive_key(\"anvilid/ratelimit-key/v1\")"
  - "Backend health logged once per change (warn Degraded / info Healthy)"
  - "Key generation tolerates a concurrent winner only when the winner's active key exists"
  - "race_fake::RaceFake (test-only storage that loses every first-start race), shared by core tests"
  - "crates/anvilid/tests/concurrent_start.rs (3 nodes, one empty Postgres) and crates/anvilid/tests/limiter_redis.rs (Docker)"
affects: [05-25, 05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "HMAC-SHA-256 in the binary through rustls' aws-lc-rs TLS 1.3 SHA-256 suite (Hkdf::hmac_sign), so anvilid needs no new crypto dependency"
    - "Multi-node binary tests: real `anvilid serve` processes on one Postgres, logs to files (never a full pipe)"

key-files:
  created:
    - crates/anvilid/tests/limiter_redis.rs
    - crates/anvilid/tests/concurrent_start.rs
  modified:
    - crates/anvilid/src/limiter.rs
    - crates/anvil-core/src/service/bootstrap.rs
    - crates/anvil-core/src/service/key_rotation.rs
    - crates/anvilid/tests/config_phase5.rs

key-decisions:
  - "HMAC comes from rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256's hkdf_provider.hmac_sign (aws-lc HMAC-SHA-256). anvilid has no direct aws-lc-rs/hmac dependency and Cargo manifests belong to 05-01; anvil-jose is not this plan's file. Pinned by an RFC 4231 test-case-2 vector"
  - "Startup error for an unreachable or invalid Redis is `redis_url: <RedisInitError>`; RedisInitError never contains the URL, and the test checks neither password nor host is echoed"
  - "Selected backend is logged once at startup (`backend = in-process|redis`, `failure_mode`), never the URL"
  - "Core: the existing ensures already handled the race (SetupRepo::install -> AlreadyInstalled, console client Conflict -> re-read, active-key Conflict -> false). The one behaviour change: a Conflict on inserting an Active key now re-reads `keys().active`; only an existing winner key counts as success, otherwise the Conflict is returned (no hidden errors, no retries). Losers never audit"
  - "concurrent_start returns immediately unless ANVILID_TEST_DB=postgres (SQLite allows one server per data dir), so it runs in `just test-pg` without an #[ignore]"
  - "limiter_redis simulates the outage with container pause/unpause (every call times out), as 05-08 does; it uses a Postgres container too because nodes must share tenant ids to share client budgets"

requirements-completed: [OPS-03]

duration: ~70min
completed: 2026-11-26
---

# Phase 5 Plan 16: Shared Redis limiter wiring and concurrent first start Summary

**`redis_url` now selects the shared RedisLimiter. Redis key names are HMAC-SHA-256 under a key derived from the KEK. `rate_limit_redis_failure` maps to the fail-closed or local mode, and state changes are logged. Three `anvilid serve` nodes started together on one empty Postgres all come up: one installs, the others treat the winner's unique violations as success, and only the winner audits.**

## Performance

- **Duration:** ~70 min
- **Completed:** 2026-11-26
- **Tasks:** 2
- **Files:** 2 created, 4 modified

## Accomplishments

- `limiter::build_limiter` is still the only selection site. It returns `InProcessLimiter` when `redis_url` is unset. When it is set, it calls `RedisLimiter::connect(url, cfg.rate_limits, clock, hasher, mode).await?.with_health_observer(..)`. No handler knows which backend runs: `grep RedisLimiter` outside anvil-cache and tests finds only `crates/anvilid/src/limiter.rs`.
- Hasher: `kek.derive_key("anvilid/ratelimit-key/v1")` is derived once at startup and captured in the closure.
- Modes: `RedisFailure::Closed` maps to `FailureMode::Closed` (the default) and `RedisFailure::Local` maps to `FailureMode::Local`.
- The health observer logs `warn!` "rate-limit backend (Redis) unavailable..." and `info!` "...reachable again...".
- If a Conflict on the active-key insert has no winner behind it, `KeyRotationService::generate` returns the Conflict instead of `Ok(false)`.
- concurrent_start proves the following on 3 nodes started together on an empty Postgres:
  - all three become healthy;
  - exactly one `Setup URL:` line is printed;
  - tenants are exactly `default` and `system`;
  - the console client exists, with exactly one `client_created` audit event;
  - each tenant has exactly one active key per alg;
  - all nodes still serve afterwards.

## Task Commits

1. **Task 1: limiter backend selection and failure-mode tests:** `2d7a6e7` (feat)
2. **Task 2: concurrency-safe startup reconciliation:** `0c290ff` (feat)
3. Deferred item for the config.rs owner: `7c2aedf` (docs)

## Failure-mode test names (security map)

| Check | Test | Runs |
|-------|------|------|
| Unreachable Redis fails startup, names `redis_url`, no password/host echoed | `limiter::tests::unreachable_redis_url_fails_startup_naming_the_key_without_echoing_it` (anvilid bin) | plain `cargo test` |
| Same, through `anvilid serve`, before the database opens | `config_phase5::redis_url_unreachable_fails_startup_explicitly` | plain `cargo test` |
| Mode mapping, `closed` default | `limiter::tests::failure_modes_map_one_to_one` | plain `cargo test` |
| Key names are HMAC-SHA-256 under the derived key (RFC 4231 vector; KEK-separated) | `limiter::tests::hmac_sha256_matches_rfc_4231_test_case_2`, `limiter::tests::key_hasher_is_hmac_under_the_derived_ratelimit_key` | plain `cargo test` |
| Two nodes share one client token budget | `limiter_redis::redis_two_nodes_share_one_client_token_budget` | `just test-redis` (Docker) |
| Outage: login POST 429 + Retry-After (closed); not limited (local); `/token` 200 on both; `anvil_ratelimit_backend_errors_total` increments; degraded/recovered logged, URL never logged; shared limiting after the cool-down | `limiter_redis::redis_outage_login_fails_closed_or_local_token_keeps_issuing_then_recovers` | `just test-redis` (Docker) |
| Concurrent winner's active key = success, no audit | `service::key_rotation::tests::ensure_tenant_treats_a_concurrent_winners_active_key_as_success` | plain `cargo test` |
| Conflict without an active key is an error (not hidden) | `service::key_rotation::tests::ensure_tenant_conflict_without_an_active_key_is_an_error` | plain `cargo test` |
| Console client Conflict re-reads the winner's row, no audit / Conflict without row is an error | `service::bootstrap::tests::console_client_conflict_rereads_the_winners_row_and_does_not_audit`, `..._conflict_without_a_row_is_an_error` | plain `cargo test` |
| Install loser: AlreadyInstalled, no setup URL | `service::bootstrap::tests::concurrent_install_loser_gets_already_installed_and_no_setup_url` | plain `cargo test` |
| 3-node concurrent first start | `concurrent_start::three_nodes_start_together_on_an_empty_postgres` | `just test-pg` |

## Verification

- `cargo test -p anvilid --bin anvilid`: 46 passed. The plan's `--lib` does not apply because anvilid has no library target; the unit tests run under `--bin anvilid`.
- `cargo test -p anvil-core --lib -- service::bootstrap service::key_rotation`: 26 passed, including the 6 new race tests.
- `cargo test -p anvilid --test config_phase5 redis`: 3 passed.
- `concurrent_start` ran against a local PostgreSQL 14 cluster through a temporary, reverted patch to the database URL. It passed 5 times in a row, each on a freshly created database. The cluster was stopped and deleted afterwards.
- `cargo clippy -p anvilid --tests` and `cargo clippy -p anvil-core --tests`: no warnings in this plan's files.
- `limiter_redis` compiles; its 2 tests are `#[ignore]`d.

## Not run locally

- `limiter_redis` (both tests) was not run. It needs Docker for the Redis and Postgres containers, and no local redis-server is available. It runs in the CI `just test-redis` job.
- `concurrent_start` against the Postgres 18 container was not run, because Docker is unavailable. It runs in CI `just test-pg`. It did pass against local PG14.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] HMAC without a new dependency**
- **Issue:** anvilid has no `hmac` or `aws-lc-rs` dependency. Cargo manifests have a single owner (05-01), and anvil-jose has no generic HMAC helper and is not this plan's file.
- **Fix:** HMAC-SHA-256 from rustls' aws-lc-rs provider (`Tls13CipherSuite::hkdf_provider.hmac_sign`). It is pinned to RFC 4231 test case 2.
- **Files:** crates/anvilid/src/limiter.rs. **Commit:** 2d7a6e7

**2. [Rule 3 - Blocking] Forced extra file: crates/anvilid/tests/config_phase5.rs**
- **Issue:** `redis_url_fails_startup_explicitly` asserted the removed TRANSITIONAL message.
- **Fix:** Renamed it to `redis_url_unreachable_fails_startup_explicitly`. It now points at `127.0.0.1:1` and asserts `redis_url: ` and `unreachable`, with no password echoed and no database file created.
- **Commit:** 2d7a6e7

**3. [Rule 2 - Correctness] Key-generation Conflict re-read**
- **Issue:** A Conflict on an Active insert was always treated as a lost race, even when no active key existed (for example, a duplicate kid). That could hide a real error.
- **Fix:** Re-read `active()`. A winner's key means success; no key means the Conflict is returned.
- **Commit:** 0c290ff

**Process note:** Both tasks are `tdd="true"`, but tests and code went into one commit per task instead of separate RED/GREEN commits. The core change has a test that fails on the old code (`ensure_tenant_conflict_without_an_active_key_is_an_error`). The other race tests pin behaviour that already existed.

### Deferred

- The `config.rs` module doc still says `redis_url` is "not supported until 05-16", and `Config.redis_failure` still has a stale `#[allow(dead_code)]`. Both are recorded in deferred-items.md for the owner of `config.rs`.

## Next Phase Readiness

- 05-25 (load test) and 05-27 (docs) can rely on the following behaviour:
  - `ANVILID_REDIS_URL` selects the shared limiter;
  - `ANVILID_RATE_LIMIT_REDIS_FAILURE` is `closed` (default) or `local`;
  - startup fails if Redis is unreachable;
  - logs carry `backend`/`failure_mode` at startup and one line per health change;
  - the metric is `anvil_ratelimit_backend_errors_total{operation,reason}`.
- Several nodes can share one Postgres from an empty database.

## Self-Check: PASSED

All created files exist; commits 2d7a6e7, 0c290ff and 7c2aedf are in the log.
