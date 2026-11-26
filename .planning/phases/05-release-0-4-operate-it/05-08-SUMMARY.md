---
phase: 05-release-0-4-operate-it
plan: 08
subsystem: rate-limiting
tags: [redis, rate-limit, gcra, lua, circuit-breaker, contract-tests, testcontainers]

requires:
  - phase: 05-release-0-4-operate-it
    provides: "05-01: redis 1.8.3, metrics, testcontainers-modules[redis] edges on anvil-cache"
provides:
  - RedisLimiter, a second backend of the one anvil_cache::limiter::RateLimiter trait
  - Limiter contract suite (limiter_contract_tests!) run against InProcessLimiter and RedisLimiter
  - FailureMode { Closed, Local }, KeyHasher, HealthObserver, BREAKER_COOL_DOWN public API for 05-16
  - "`just test-redis` recipe (in `just ci` and the CI postgres job)"
affects: [05-16, 05-25, 05-27]

tech-stack:
  added: []
  patterns:
    - "Backend contract suite as test code included with #[path] (no test doubles in the library)"
    - "Redis Lua scripts take now from the core clock, write numbers with %.0f (no %.14g rounding)"
    - "Redis-backed tests: `redis` in the name, #[ignore], run by `just test-redis` with ANVILID_TEST_REDIS=1"

key-files:
  created:
    - crates/anvil-cache/src/limiter/redis.rs
    - crates/anvil-cache/src/limiter/breaker.rs
    - crates/anvil-cache/src/limiter/contract.rs
    - crates/anvil-cache/src/limiter/scripts/gcra.lua
    - crates/anvil-cache/src/limiter/scripts/backoff.lua
    - crates/anvil-cache/tests/limiter_contract.rs
  modified:
    - crates/anvil-cache/src/limiter/mod.rs
    - crates/anvil-cache/src/lib.rs
    - justfile
    - .github/workflows/ci.yml

key-decisions:
  - "Key hasher API: `KeyHasher = Arc<dyn Fn(&[u8]) -> [u8; 32] + Send + Sync>` over `anvil_cache::limiter::canonical(&LimitKey)`; 05-16 supplies HMAC-SHA-256 under Kek::derive_key(\"anvilid/ratelimit-key/v1\"). anvil-cache gets no crypto dependency"
  - "contract.rs is test code: not a module of the library; tests/limiter_contract.rs includes it with #[path]. No `contract` cargo feature, because Cargo manifests belong to 05-01 and CLAUDE.md keeps test doubles (FakeClock) out of production builds"
  - "Logging without a tracing dependency: RedisLimiter::with_health_observer(Arc<dyn Fn(BackendHealth)>) is called once per healthy/degraded change. 05-16 wires it to tracing"
  - "Fail closed = Decision::Deny { retry_after: rest of the 5 s breaker cool-down } (planner decision, one Decision shape)"
  - "Only Auth check and brute_force_gate fail closed. backoff/record_failure/record_success fall back to the embedded InProcessLimiter in both modes, so failures keep being counted during an outage. record_success also clears the local entry"
  - "Redis-backed tests are #[ignore]d and need ANVILID_TEST_REDIS=1. `just test-redis` runs `cargo test --workspace --tests --locked -- redis --include-ignored`. The plan's command had no --include-ignored, which ignored tests need"
  - "The error counter has labels operation (check/backoff/record_failure/record_success/brute_force_gate) and reason (error/breaker_open). The test asserts reason=breaker_open, which proves the breaker skipped Redis without adding a test hook"
  - "Redis test image is pinned to tag 7.2-alpine; the testcontainers-modules default is 5.0"

patterns-established:
  - "limiter_contract_tests!(module, factory, #[attrs]...): one test list, applied per backend"

requirements-completed: []

duration: ~50min
completed: 2026-11-26
---

# Phase 5 Plan 08: Redis limiter backend and limiter contract suite Summary

**RedisLimiter is a second backend of the one RateLimiter trait. It runs GCRA and the backoff/gate logic as one Lua script per operation, with `now` taken from the core clock. Key names are hashed. A 5 s circuit breaker sits in front of Redis, and on an outage the auth class fails closed while other classes fall back to an embedded in-process limiter. One contract suite pins both backends to governor's exact semantics.**

## Performance

- **Duration:** about 50 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Files:** 10 (6 created, 4 modified)

## Accomplishments

### Task 1: limiter contract suite (commit a7a3d5f)
- `src/limiter/contract.rs` (test code, included via `#[path]`) contains `FakeClock`, `TestLimiter`, the `limiter_contract_tests!` macro and 20 generic tests.
- **Pinned GCRA semantics (governor 0.10):** `tat` defaults to `now`, `tau = T * (b - 1)`, a request is allowed iff `now >= tat - tau`, then `tat = max(tat, now) + T`. So exactly `b` requests pass, request `b + 1` gets `retry_after == T` exactly, and a denial consumes nothing. The research's "off-by-one" question is settled: the tolerance is `T*(b-1)`, not `T*b`.
- Contract test names:
  - GCRA: `gcra_burst_is_exact_then_denied_for_one_interval`, `gcra_partial_refill_is_exact`, `gcra_idle_time_never_exceeds_the_burst`, `gcra_denial_does_not_consume_quota`, `gcra_keys_are_isolated`, `gcra_route_classes_are_independent`, `gcra_token_client_keys_use_the_client_quota`, `gcra_disabled_allows_everything`.
  - Backoff: `backoff_free_attempts_then_doubling_lock_capped`, `backoff_reports_remaining_lock_window`, `backoff_success_clears_the_key`, `backoff_forgotten_after_twice_the_cap_idle`, `backoff_keys_are_isolated_by_tier_and_tenant`, `backoff_loose_tier_is_counted_but_never_locked`.
  - Gate: `gate_allows_a_clean_key`, `gate_denies_while_the_strict_key_is_locked`, `gate_loose_tier_requires_captcha_or_delay`, `gate_loose_window_restarts_after_an_hour`, `gate_strict_lock_takes_precedence_over_captcha`, `gate_and_backoff_are_off_when_disabled`.
- They run as `in_process::*` (always) and `redis_backend::*` (Docker).

### Task 2: RedisLimiter (commit 9db091c)
- `RedisLimiter::connect(url, LimiterConfig, Arc<dyn Clock>, KeyHasher, FailureMode) -> Result<Self, RedisInitError>`. It probes with a plain connection and `PING` (500 ms timeouts), so an unreachable server fails startup, and only then builds the `ConnectionManager` (50 ms response timeout, 500 ms connect timeout). `RedisInitError` never echoes the URL, which may carry a password.
- `gcra.lua` follows governor exactly. Expiry is `ceil((tat-now)/1ms) + 1 s`, which only bounds memory.
- `backoff.lua` uses ops `fail | get | clear | gate`. Each trait method is exactly one invocation. Idle expiry (`2*cap`) is checked against the passed `now`, and PEXPIRE only bounds memory.
- All numbers are written with `%.0f`, because Lua's `%.14g` would round microsecond timestamps.
- Key names are `anvil:rl:{auth|token|token_client|admin|default|bf}:{64 hex}`, built from `KeyHasher(canonical(key))`. `canonical` is a tagged, fixed-width, length-prefixed encoding, and a unit test checks that it is unambiguous.
- **Failure policy:** `breaker.rs` opens for `BREAKER_COOL_DOWN` = 5 s after an error, then lets a single half-open probe through. An abandoned probe is replaced after another cool-down. While the breaker is open:
  - `Auth` check and `brute_force_gate` deny with `retry_after` = the rest of the cool-down (`Closed`), or use the in-process decision (`Local`).
  - Token, Admin and Default checks, `backoff`, `record_failure` and `record_success` use the embedded `InProcessLimiter` (same config and clock).
  - Every fallback increments `anvil_ratelimit_backend_errors_total{operation,reason}`.
  - `HealthObserver` gets `Degraded`/`Healthy` once per change.
- Recipes: `test-redis` was added and is part of `ci:`. CI runs `just test-redis` in the `tests (postgres)` matrix job after `just test-pg`.

## Failure-mode tests (for the 05-25 security map)

All in `crates/anvil-cache/tests/limiter_contract.rs`:
- `redis_outage_auth_and_gate_fail_closed_breaker_skips_then_recovers`, run with Docker pause on the container:
  - The Auth check gives `Deny{5 s}` and the counter shows `error` = 1 and `Degraded`.
  - Within the cool-down, Auth and the gate deny with `reason=breaker_open` (under 40 ms, no new `error`), so Redis was not touched.
  - Token falls back to in-process burst 3 and then `Deny{10 s}`.
  - After unpause and the cool-down, Redis is used again: `Healthy`, and a second node sees the shared budget.
- `redis_outage_local_mode_uses_the_in_process_limiter`: in Local mode, Auth and the gate follow the in-process decisions.
- `redis_connect_fails_fast_when_unreachable`: connecting fails in under 5 s, there is no password in the error, and an invalid URL is refused. This test needs no server and runs in plain `cargo test`.
- `redis_instances_share_one_budget`: two instances on one Redis allow 3 requests in total, not 6, and share backoff/gate state.
- `redis_key_names_are_hashed`: KEYS shows only `anvil:rl:{class}:{64 hex}`, with no IP, client id or identifier hex, and the digest equals the hasher over the canonical key.
- Unit tests: `limiter::breaker::tests::*` (4) and `limiter::redis::tests::*` (4).

## Task Commits

1. **Task 1: limiter contract suite, in-process instance:** `a7a3d5f` (test)
2. **Task 2: Redis backend, breaker, scripts, test-redis recipe and CI step:** `9db091c` (feat)

## Verification run

- `cargo test -p anvil-cache`: 8 unit, 20 `limiter`, 21 `limiter_contract` (20 in-process plus the connect test) passed; 24 Redis tests ignored.
- `cargo clippy -p anvil-cache --all-targets -- -D warnings`: clean. The first attempt hit another plan's in-progress `anvil-core` `result_large_err`; it was clean on the retry.
- `cargo doc -p anvil-cache --no-deps`: no warnings.
- `grep -rn "if .*redis" crates/anvil-web/src`: empty, so there is no second limiter path in handlers.
- `ANVILID_TEST_REDIS=1 cargo test -p anvil-cache --tests -- redis --list`: 29 tests are selected by the recipe filter.
- Lua logic was checked without Redis. A throwaway harness (Lua 5.4 with an in-memory `redis.call` mock, since deleted) replayed these contract sequences against both scripts: GCRA burst, partial refill, backoff doubling and cap, the `2*cap` idle forget, the loose threshold, gate precedence, and clear. It also asserted that no stored number used exponent notation. All passed.

## Could not run locally

- **Docker is down and no redis-server/valkey-server binary is installed**, so `just test-redis` (the 20 `redis_backend::*` contract tests and the 4 Docker-backed `redis_*` tests) has not run. CI runs it in the `tests (postgres)` job. The real-Redis risks are the Redis 5.1 Lua dialect (the harness ran Lua 5.4) and the redis-rs behaviour under Docker pause (the response timeout should surface as an error, and the manager should keep working after unpause).

## Deviations from Plan

### Design adjustments (within plan latitude, recorded)

**1. [Rule 3 - Blocking] The contract suite is not behind a `contract` cargo feature.**
- **Issue:** Adding a feature means editing `crates/anvil-cache/Cargo.toml`, which belongs to 05-01. Compiling a FakeClock into the library would break the CLAUDE.md rule that test doubles live in test code.
- **Fix:** The suite stays at the planned path, `src/limiter/contract.rs`, but is not declared in the library. The test crate includes it with `#[path]`.

**2. [Rule 3 - Blocking] State-change logging goes through an observer callback.**
- **Issue:** anvil-cache has no `tracing` dependency, and its manifest belongs to 05-01.
- **Fix:** `with_health_observer` (once per change). The metric is emitted in anvil-cache. **05-16 must pass an observer that logs**, e.g. `warn!` on Degraded and `info!` on Healthy.

**3. `just test-redis` adds `--include-ignored`.**
- **Why:** Redis tests are `#[ignore]`d, so plain `cargo test` never needs Docker, matching the plan's "not part of plain cargo test". `--include-ignored` is required for them to run under the recipe. A Redis test run without `ANVILID_TEST_REDIS=1` fails loudly instead of skipping.

**Total deviations:** 3 recorded adjustments (2 forced by single-owner manifest rules), no scope creep.

## Next Phase Readiness

05-16 wires the backend: `RedisLimiter::connect(url, cfg.rate_limits, clock, hasher, mode).await?.with_health_observer(..)`.
- The hasher is `Arc::new(move |b| hmac_sha256(&kek.derive_key("anvilid/ratelimit-key/v1"), b))`.
- The mode maps `rate_limit_redis_failure`: `closed` -> `FailureMode::Closed`, `local` -> `FailureMode::Local`.
- Then remove the TRANSITIONAL(05-16) refusal in `crates/anvilid/src/limiter.rs`.
- Name any anvilid Redis test with `redis` and mark it `#[ignore]`.

## Self-Check: PASSED

All 6 created files exist; commits a7a3d5f and 9db091c are in the log.
