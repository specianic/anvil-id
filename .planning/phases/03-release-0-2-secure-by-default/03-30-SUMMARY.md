---
phase: 03-release-0-2-secure-by-default
plan: 30
subsystem: auth
tags: [recovery, outbox, mail-worker, audit, tests, gap-closure]
requires:
  - phase: 03-12
    provides: sign-in audit events, RecoveryNotice-capable complete_recovery call site
  - phase: 03-14
    provides: account_security tests
  - phase: 03-15
    provides: password_changed template contract (check::variables) and tenant templates
provides:
  - password_changed notice enqueued atomically with the recovery password change
  - outbox worker fills a missing `email` template variable from the row recipient
  - account_security green again on SQLite and Postgres
affects: [03-26]
tech-stack:
  added: []
  patterns:
    - "Notices sealed before the recipient is known omit `email`; the worker supplies it from the outbox row (never overriding a payload value)"
key-files:
  created: []
  modified:
    - crates/anvil-web/tests/account_security.rs
    - crates/anvil-mail/src/worker.rs
    - crates/anvil-mail/tests/worker.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-web/tests/flow_recovery.rs
key-decisions:
  - "Worker fills `email` from the outbox row recipient only when the opened payload lacks it (orchestrator option (a)); templates and check::variables(PasswordChanged) unchanged"
  - "account_security ignores only user_registered / login_succeeded / login_failed (sign-in helper events); every other action is still asserted exactly"
requirements-completed: []
duration: 15min
completed: 2026-11-25
---

# Phase 3 Plan 30: Wave-3 test fixes and in-transaction password-changed notice Summary

**The recovery password_changed notice now goes into the outbox inside the recovery transaction. Its sealed payload has no `email`, and the outbox worker fills that variable from the row's recipient. account_security passes again now that sign-in records audit events.**

## Performance

- **Duration:** about 15 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- `FlowService` `CompleteRecovery` builds a sealed `password_changed` `RecoveryNotice` before the transaction and calls `complete_recovery(.., Some(&notice))`. The separate enqueue that ran after the transaction is gone, so a password change can no longer commit without its notice.
- `OutboxWorker::deliver` opens the payload and then calls `fill_recipient`, which inserts the row's `to` as `email` only when that key is missing. A unit test and two worker integration tests cover both cases: a missing `email` is filled, and a payload `email` is never overridden.
- `flow_recovery` runs the production `OutboxWorker` (with a capturing transport) over the app's storage and KEK. A valid token produces exactly one notice whose rendered text and HTML name the recipient. Reusing the consumed token adds no second notice, and an invalid token enqueues none (the existing test). Passes on SQLite and Postgres.
- In `account_security`, `audit_actions` and the admin-remove test filter out the sign-in helper events. Each test still asserts its own events exactly. 12/12 pass on both backends.

## Task Commits

1. **Task 1: account_security audit assertions and clippy cleanups**: `ee06e0c` (fix)
2. **Task 2: password-changed notice inside the recovery transaction**: `77e2503` (test, RED), `540bc4d` (feat, GREEN)

## Decisions Made

- Option (a) from the 03-12 deferral: the worker supplies `email`. This needs no template or contract change, and the recipient is already stored on the outbox row, so no new data is exposed.
- The filter in account_security lists exactly the three sign-in actions, so any unexpected account event still fails the tests.

## Deviations from Plan

None. The plan executed as written. `security_ratelimit.rs` already passed clippy (`cargo clippy -p anvil-web --all-targets -D warnings` was clean), so it was not changed.

## Issues Encountered

- During the run, another parallel plan had an uncommitted change to `crates/anvil-core/src/flow/consent.rs` that broke the workspace build in the main checkout. I ran workspace clippy and tests in a temporary worktree at HEAD (`target/wt-03-30`, with its own target dir) and removed both afterwards.
- `take_emails` claims rows with a 1 h lease. The flow_recovery test advances the clock past the lease before running the worker, and filters the delivered mails to the password_changed subject because the earlier verification email also becomes due again.

## Next Phase Readiness

- Verification: `cargo test --workspace --no-fail-fast` at HEAD: 67 test binaries, 0 failures (one earlier run had Postgres testcontainer start timeouts under parallel load; 14/14 passed on rerun). Workspace clippy `-D warnings` clean.
- The 03-12 deferred items (password_changed notice, account_security audit assertions) are closed.

---
*Phase: 03-release-0-2-secure-by-default*
*Completed: 2026-11-25*

## Self-Check: PASSED

- FOUND: 03-30-SUMMARY.md and all 5 modified files
- FOUND commits: ee06e0c, 77e2503, 540bc4d
