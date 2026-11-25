---
phase: 03-release-0-2-secure-by-default
plan: 07
subsystem: rate-limiting
tags: [rate-limit, governor, gcra, moka, brute-force, backoff, captcha]
requires:
  - phase: 03-01
    provides: "governor 0.10.4 and moka 0.12.16 declared in anvil-cache"
provides:
  - "anvil_cache::limiter: RateLimiter trait (check, backoff, record_failure, record_success, brute_force_gate) and InProcessLimiter"
  - "RouteClass, LimitKey, Decision, Backoff contract types; LimiterConfig + RateQuota with documented defaults"
affects: [03-13, 03-20]
tech-stack:
  added: []
  patterns:
    - "governor driven by the anvil_core Clock via a CoreClock adapter (Instant = Nanos since a fixed origin)"
    - "Clock-based idle expiry on top of moka TTI so expiry semantics are deterministic under a fake clock"
key-files:
  created:
    - crates/anvil-cache/src/limiter/mod.rs
    - crates/anvil-cache/src/limiter/types.rs
    - crates/anvil-cache/src/limiter/config.rs
    - crates/anvil-cache/src/limiter/gcra.rs
    - crates/anvil-cache/src/limiter/backoff.rs
    - crates/anvil-cache/tests/limiter.rs
  modified:
    - crates/anvil-cache/src/lib.rs
decisions:
  - "governor clock adapter is feasible: CoreClock implements governor::clock::Clock with Instant = Nanos (elapsed since the clock value at construction, saturating at 0 if the wall clock steps back); no FakeRelativeClock fallback needed"
  - "Token class has two buckets: per-IP/other keys use `token` (50/s burst 50), LimitKey::Client uses `token_client` (100/s burst 100)"
  - "RateQuota is {count, period, burst} (not per_second only) so auth can be 10/min burst 5"
  - "Lock schedule: failure n > free_attempts locks base*2^(n-free-1) capped at cap (6th = 1 s, matching the behaviour spec; the interface comment's 2^(n-free) was off by one)"
  - "The loose tier (LimitKey::Identifier) is counted in a fixed 1 h window and never progressively locked, so nobody can lock an account out from arbitrary IPs; over threshold -> RequireCaptcha if available else Deny{min(base*2, cap)}"
  - "enabled = false switches the whole limiter off (check/gate Allow, failures not recorded, backoff None)"
  - "Housekeeping: from check(), at most once per 60 s (CAS on last run), governor retain_recent + shrink_to_fit on every bucket and moka run_pending_tasks; InProcessLimiter::tracked_keys(class) exposes the GCRA key count for metrics"
metrics:
  duration: 15min
  completed: 2026-11-25
  tasks: 2
  files: 7
---

# Phase 3 Plan 07: The single rate limiter Summary

anvil-cache now has the codebase's one rate limiter: a `RateLimiter` trait and `InProcessLimiter` combining governor GCRA per route class with a moka progressive-backoff store and a two-tier brute-force gate. Time comes entirely from the injected `anvil_core` clock, so every test runs deterministically on a fake clock and nothing sleeps.

## Default quotas

| Setting | Default |
| ------- | ------- |
| auth | 10/min, burst 5 (per key, normally per IP) |
| token (IP / other keys) | 50/s, burst 50 |
| token (LimitKey::Client) | 100/s, burst 100 |
| admin | 20/s, burst 20 |
| default | 50/s, burst 50 |
| free_attempts | 5 |
| base / cap | 1 s / 15 min (entries forgotten after 2*cap = 30 min without failures) |
| loose_threshold_per_hour | 50 |
| max_tracked_keys (backoff store) | 100 000 |

## Clock adapter

`gcra::CoreClock` wraps `Arc<dyn anvil_core::ports::Clock>` and implements `governor::clock::Clock` with `Instant = governor::nanos::Nanos`: it reports the nanoseconds elapsed since the clock's value when the limiter was built, saturating at zero. governor 0.10.4's bounds (`Reference` on `Nanos`, no `Clone` requirement on the limiter) allowed this directly, so the `FakeRelativeClock` fallback from the plan was not needed. `retry_after` is `NotUntil::wait_time_from(adapter.now())`.

## Tasks

| Task | Name | Commits |
| ---- | ---- | ------- |
| 1 | Limiter types, config and route-class GCRA (TDD) | ac7a9e5 (RED), 99e257e (GREEN) |
| 2 | Progressive backoff and two-tier brute-force gate (TDD) | 280534f (RED), a152ce3 (GREEN) |

## Verification

- `cargo test -p anvil-cache`: 20 tests pass (8 GCRA, 12 backoff/gate/trait object)
- `cargo clippy -p anvil-cache --all-targets -- -D warnings`: clean
- `scripts/check-deps.sh`: dependency rules OK (anvil-cache depends only on anvil-core, no storage crates)

## Deviations from Plan

### Design clarifications (within the plan's scope)

**1. Off-by-one in the interface's lock formula.** The must-have says `min(base·2^(n−free), cap)`, but the behaviour spec says the 6th failure locks 1 s. Followed the behaviour (exponent `n−free−1`), which is what the tests assert.

**2. The loose tier is never locked.** The plan says the loose tier escalates to CAPTCHA or a delay. Calling `record_failure` on a `LimitKey::Identifier` only counts it in the hourly window, so a stream of failures from many IPs cannot lock the real account owner out. `Backoff.failures` for such a key is the count in the current window.

**3. Token split.** The default "token 50/s per IP + 100/s per client" is implemented as a second bucket that `RouteClass::Token` uses for `LimitKey::Client` keys.

No other deviations. No auto-fixes needed.

## Deferred Issues

- cargo flags `tokio` as an unused normal dependency of anvil-cache. This was already the case before this plan, and `crates/anvil-cache/Cargo.toml` is outside this plan's files. Leave it if 03-13 needs async primitives here; otherwise drop it later.

## Self-Check: PASSED
