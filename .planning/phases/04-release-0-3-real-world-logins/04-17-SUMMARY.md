---
phase: 04-release-0-3-real-world-logins
plan: 17
subsystem: oidc-logout
tags: [oidc, backchannel-logout, worker, lease, ssrf, outbound, audit, jobs]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-02 OutboundClient + read_capped + AppState::logout_wake; 04-04/04-05 claim_due_deliveries/complete_delivery + enqueue-on-revoke; 04-08 logout_token_claims/classify_delivery/next_attempt; 04-13 LogoutService + /logout waking the worker"
provides:
  - "service::logout: LogoutService::prepare_delivery(&KeyService, &PublicUrl, &LogoutDelivery, now) -> PreparedDelivery { uri, logout_token: SecretString }; sign_logout_token; canonical_issuer; LOGOUT_TOKEN_TYP"
  - "anvil_web::adapters::backchannel: LogoutDeliveryWorker::{new, run_once, run}, RunReport, BATCH_SIZE (20), POLL_INTERVAL (10 s), CLAIM_LEASE (2 min)"
  - "anvil_web::router(AppState) next to app(config, deps)"
  - "anvilid: Started.logout_worker, jobs::spawn_logout_worker (every node, stopped by the shutdown watch)"
affects: [04-23, 04-gate]

tech-stack:
  added: []
  patterns:
    - "Rows of one claimed batch are attempted concurrently (JoinSet), so a batch takes about one request timeout, well inside the 2-minute row lease"
    - "Binary integration test seeds the running server's SQLite file through the storage ports and drives the rest over HTTP"

key-files:
  created:
    - crates/anvil-web/tests/backchannel.rs
    - crates/anvilid/tests/backchannel_worker.rs
  modified:
    - crates/anvil-core/src/service/logout.rs
    - crates/anvil-web/src/adapters/backchannel.rs
    - crates/anvil-web/src/lib.rs
    - crates/anvilid/src/startup.rs
    - crates/anvilid/src/jobs.rs
    - crates/anvilid/src/main.rs

key-decisions:
  - "prepare_delivery takes the KeyService and PublicUrl as arguments instead of new LogoutService fields, so the 04-13 constructor in anvil-web stays unchanged"
  - "The issuer of a logout token is the tenant's canonical issuer (custom host, public URL for default, else /t/{slug}), like admin_issuer_of: the worker has no request host"
  - "The destination is the client's current backchannel_logout_uri, not the URI stored at enqueue time; a deleted client/tenant or a removed URI gives up (reason client_removed)"
  - "A retry that would be scheduled at or after created_at + 24 h is turned into a give-up (reason expired): claims require give_up_at > now, so such a row would otherwise disappear without audit"
  - "OutboundError::InvalidUrl (e.g. plain http outside development mode) counts as Blocked; TooLarge counts as Network; the response body never changes the status decision"
  - "A token that cannot be prepared for a server-side reason (missing key for the client's alg, storage error) retries with the normal backoff and is logged; it is never sent with another alg"
  - "Audit of a give-up: system actor, target = delivery id, details {client_id, attempts (including this one), reason in status|blocked|network|timeout|expired|client_removed|internal}; no token, no URI"

requirements-completed: []

duration: about 2 h (one session interruption; waits for other wave-4 plans to compile)
completed: 2026-11-25
---

# Phase 4 Plan 17: Back-Channel Logout Delivery Worker Summary

**Queued back-channel logout deliveries are now delivered. A worker runs on every node and claims due rows with a 2-minute lease. For each row it signs a fresh logout token (`typ: logout+jwt`, the client's ID-token alg, claims exactly iss/aud/iat/exp/jti/sub/sid/events, no nonce) and POSTs only `logout_token` as a form body through the single SSRF-guarded outbound client. Results are classified with the 04-08 decision table. Give-ups are audited as `backchannel_logout_failed`. `/logout` wakes the worker through `AppState::logout_wake`; otherwise it polls every 10 s. With this, discovery's `backchannel_logout_supported` claim is true.**

`requirements-completed` is empty on purpose. OIDC-12 still needs the conformance run (04-23), and per the shared rules no checkbox was ticked.

## Delivery behaviour

| Situation | Result |
|---|---|
| RP answers 200 or 204 | `delivered_at` set; the row is never claimed again |
| RP answers 400, another 4xx, 201/202/3xx | given up after this attempt; audit `reason: status` |
| destination blocked by the outbound policy, or URL refused before connecting (e.g. plain http outside development mode) | given up, nothing sent; `reason: blocked` |
| 5xx, network error, timeout | retry at `now + min(10 s * 2^attempts, 1 h)` |
| retry would land at or after `created_at + 24 h` | given up now; `reason: expired` (such a row would otherwise never be claimed again and vanish without audit) |
| client or tenant deleted, or URI removed | given up; `reason: client_removed` |
| token cannot be prepared (missing key for the client's alg, storage error) | logged, retried with backoff (`reason: internal` if it reaches the deadline); never signed with another alg |

The audit row has a system actor and `target` = delivery id. Its details are `{client_id, attempts, reason}`. No token or URI appears in audit or logs. The response body is read (capped at 64 KiB) and discarded.

## Verification

- `cargo test -p anvil-core --lib service::logout`: 5 passed (incl. exact claim set + typ via `sign_logout_token`, canonical issuer)
- `cargo test -p anvil-web --lib adapters::backchannel`: 2 passed (outcome mapping, reasons)
- `cargo test -p anvil-web --test backchannel` (SQLite): 8 passed: spec token verified against the tenant JWKS; body has only `logout_token`; content type; query string kept; `sid` = the ID token's `sid`; ES256 client alg; 400; 500 backoff (10 s, 20 s) + deadline give-up; blocked; removed URI; `revoke_all_for_user` + `UserRepo::delete` deliver; the wake delivers with a 1 h poll
- `cargo test -p anvilid --test backchannel_worker`: 1 passed. The real binary on SQLite; three logouts over HTTP (`/token` then `/logout?id_token_hint=`) each reach a local RP within 2.5 s, against a 10 s poll interval
- Regression: `anvilid --test jobs --test serve`, `anvil-web --test logout --test security_logout --test security_ssrf`: all pass; clippy on anvil-core, anvil-web and anvilid (all targets) is clean

## Not run

- `ANVILID_TEST_DB=postgres cargo test -p anvil-web --test backchannel`: Docker is unavailable or intermittent (shared rule). Left for CI. Postgres claims use `FOR UPDATE SKIP LOCKED` (04-05). The multi-node no-double-delivery guarantee rests on that, and these tests do not exercise it separately.
- The conformance back-channel modules (04-23).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `anvil_web::router(state)` and a main.rs call site**
- **Issue:** `anvil_web::app()` built the `AppState` internally, so the binary could not reach `logout_wake()`/`outbound_arc()`. `jobs::spawn` is called from `main.rs`, which is not in files_modified.
- **Fix:** `app()` now delegates to a new `pub fn router(state: AppState) -> Router`, and the routes are unchanged. `startup.rs` builds the state, the worker and the router. `main.rs` gets one line, `jobs::spawn_logout_worker(&mut jobs, started.logout_worker, &stop_rx)`.
- **Files outside files_modified:** `crates/anvil-web/src/lib.rs`, `crates/anvilid/src/main.rs`
- **Commit:** 9c02a5d

**2. [Rule 2 - Missing critical] Deadline give-ups were silent**
- **Issue:** Claims require `give_up_at > now`, and `classify_delivery`'s expiry branch can only fire at the same instant. A row that kept failing would stop being claimed and disappear on purge with no `backchannel_logout_failed` audit, which contradicts the must-have "give-ups are audited".
- **Fix:** In the worker, a `Retry` whose `next_attempt_at >= created_at + 24 h` becomes a `GiveUp` with reason `expired`. The internal-error path does the same.
- **Commit:** cb84919

**3. [Rule 3] `prepare_delivery` signature**
- The plan's `prepare_delivery(&LogoutDelivery, now)` needs the KEK and the public URL. Both are passed as arguments (`&KeyService`, `&PublicUrl`) rather than added as new `LogoutService` fields, so 04-13's struct literal in anvil-web keeps compiling.

### Notes

- The delivery goes to the client's current `backchannel_logout_uri`, not to the URI captured at enqueue.
- `canonical_issuer` (core) does the same job as anvil-web's private `admin_issuer_of`. That file belongs to another plan, so it was left alone. A later cleanup could make `admin_issuer_of` delegate to `canonical_issuer`. Doc conflict to raise: a tenant with a custom host gets its host issuer in logout tokens, even if the user signed in through `/t/{slug}`.
- `UserRepo::delete` enqueues on the storage wall clock, as its port doc says. The anvil-web test advances the test clock to the wall clock before running the worker.
- The binary's wake test is probabilistic in principle: it needs three deliveries within 2.5 s of each logout. That rules out a lucky poll tick for all three (about 0.3 %).

## Commits

- b5c9ae7 feat(04-17): logout token preparation and back-channel delivery worker
- 9c02a5d feat(04-17): run the back-channel logout worker on every node
- cb84919 test(04-17): back-channel logout delivery and binary wake tests

## Self-Check: PASSED
