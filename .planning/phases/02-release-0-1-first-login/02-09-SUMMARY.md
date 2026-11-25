---
phase: 02-release-0-1-first-login
plan: 09
subsystem: core-flows-and-sessions
tags: [anvil-core, flow-engine, login, registration, recovery, verification, csrf, sessions]
requires:
  - phase: 02-01
    provides: anvil_jose::encoding (random_token, secret_hash, ct_eq)
  - phase: 02-02
    provides: ports (UserRepo, SessionRepo, FlowRepo, OutboxRepo, PasswordHasher, BreachChecker), model, policy, FormDescription
provides:
  - "flow::engine: FlowState (serde-tagged), FlowInput, Effect, Failure, FlowEnv, transition, on_failure, current_form, message_text, CSRF_PLACEHOLDER"
  - "flow::{login, registration, verification, recovery, setup}: pure state machines"
  - "service::session: SessionService::{create, current, revoke}, NewSessionCookie, session_expiry, next_idle_expiry"
  - "service::flow: FlowService::{start, submit}, FlowContext, StartedFlow, FlowOutcome (incl. Restarted), check_binding, password_login_result, bind_form"
affects: [02-15, anvil-web]
tech-stack:
  added: []
  patterns:
    - "Plan effects, fail over: transition() plans an ordered effect list; the service runs it; the first user-visible Failure goes to on_failure(state, pending, failure) which returns the form"
    - "Engine forms carry a relative action and CSRF_PLACEHOLDER; bind_form() makes them flow-specific"
key-files:
  created: []
  modified:
    - crates/anvil-core/src/flow/engine.rs
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/flow/registration.rs
    - crates/anvil-core/src/flow/verification.rs
    - crates/anvil-core/src/flow/recovery.rs
    - crates/anvil-core/src/flow/setup.rs
    - crates/anvil-core/src/service/session.rs
    - crates/anvil-core/src/service/flow.rs
key-decisions:
  - "Flow execution style: transition plans effects; executor runs them in order; first Failure -> on_failure(state, failed+remaining effects) -> form. Failures never trigger more I/O"
  - "transition/on_failure take a FlowEnv (registration mode, require_verified_email, password policy) built per request from the tenant"
  - "FlowOutcome gains Restarted(StartedFlow): an expired or unknown flow starts a fresh flow of the same kind whose form shows flow.expired (the handler must set the new flow cookie)"
  - "require_verified_email is honoured: login of an unverified user fails with login.email_not_verified (only after a correct password); registration shows registration.check_email instead of signing in"
  - "password_changed notice is enqueued via OutboxRepo::enqueue right after complete_recovery, because the recipient is only known once the token is consumed"
  - "Extra message keys: email.invalid, recovery.done, registration.check_email, login.email_not_verified, flow.invalid_input"
requirements-completed: []
requirements-addressed: [AUTH-01, AUTH-02, AUTH-03]  # core logic done; HTTP-level proof on both backends in 02-15
duration: 25min
completed: 2026-11-25
---

# Phase 2 Plan 09: Self-service flow engine, FlowService and SessionService Summary

**Login, registration, email verification, recovery and the setup form now exist as pure state machines. FlowService executes their effects through the ports, binding each flow to a hashed cookie and CSRF token. SessionService issues rotating 14 d / 12 h browser sessions.**

## Performance

- **Duration:** about 25 min
- **Completed:** 2026-11-25
- **Tasks:** 2/2
- **Files modified:** 8

## Accomplishments

- **Engine** (`flow/engine.rs`): `FlowState` round-trips through serde_json and never holds a token or password. `FlowInput` and `Effect` have manual `Debug` impls that redact passwords and tokens. Passwords inside effects are `SecretString`. Every form id is one of the six theme ids, and every form carries a CSRF placeholder that the service replaces.
- **Login:** every credential failure renders exactly one message, `login.invalid_credentials`. The identifier is echoed and the password never is.
- **Registration:** `Disabled` and `InviteOnly` render `registration.disabled`. Policy and email errors are field errors. A valid submission runs CheckBreach, then CreateUser together with the verification email in one `UserRepo::create` call, then CreateSession.
- **Verification and recovery:** tokens travel only in hidden fields and are consumed only on POST. A recovery policy violation hands the token back unconsumed. A recovery request always gives `recovery.sent`.
- **FlowService:**
  - `check_binding` compares both hashes in constant time and always compares both.
  - VerifyPassword uses the dummy-hash path (`verify(None, …)`) for unknown users, blocked users and users without a password, and rehashes on `needs_rehash`.
  - A `Conflict` from `UserRepo::create` becomes `registration.email_taken`.
  - `complete_recovery` is followed by the `password_changed` notice.
  - `Overloaded` becomes `service.overloaded`.
  - Setup returns `SetupSubmitted` and does not call BootstrapService.
- **SessionService:** session tokens are stored only as hashes. The previous session is revoked on login. `current()` pushes the idle expiry forward, capped at the absolute expiry.
- 39 tests in `flow::`, `service::flow` and `service::session`. All 191 anvil-core tests pass and clippy `--all-targets -D warnings` is clean.

## Task Commits

1. **Task 1: Pure state machines** - `f73d7f8` (feat)
2. **Task 2: SessionService and FlowService** - `7604d0f` (feat)

TDD tasks were committed once per task, with the tests in the same module. There were no separate RED commits.

## Decisions Made

See the key-decisions list in the frontmatter. The execution style is documented at the top of `flow/engine.rs`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `transition` takes a `FlowEnv` parameter**
- **Issue:** The interface sketch had `transition(state, input)`. The registration mode and password policy are tenant and configuration inputs. Putting them in the stored state would let them go stale.
- **Fix:** `transition(state, input, &FlowEnv)`, which matches RESEARCH Pattern 2 (`ctx`).

**2. [Rule 3 - Blocking] `FlowOutcome::Restarted(StartedFlow)` added**
- **Issue:** The plan says to render `flow.expired` on a restarted flow. A restarted flow has a new cookie that the handler must set, and `Render(FormDescription)` cannot carry it.
- **Fix:** Added a dedicated variant.

**3. [Rule 1 - Correctness] The password_changed notice is enqueued separately**
- **Issue:** `UserRepo::complete_recovery(…, notice: Option<&NewEmail>)` needs the recipient before the call. Which user a token belongs to is only known once the token is consumed, and no port can peek at a self-service token.
- **Fix:** Call `complete_recovery(…, None)`, then `OutboxRepo::enqueue(notice)` to the returned user's email. A crash between the two steps loses only the informational notice. The password change and the revocation stay atomic.
- **Follow-up (raise, not done):** Either let the port fill `to` from the token's email, or add a token peek. This touches the port, which is another plan's file.

**4. [Rule 2 - Correctness] `require_verified_email` honoured**
- **Issue:** The tenant setting would otherwise do nothing, which amounts to a silent stub.
- **Fix:** Login and registration behave as described in the key decisions.

**5. [Process] `cargo fmt -p anvil-core` reformatted other plans' in-progress files**
- Running fmt once over the whole crate also touched other wave-2 plans' service files, with whitespace changes only. I did not stage or commit them. After that I ran `rustfmt` only on my own files.

## Issues Encountered

- `cargo test -p anvil-core` failed once because 02-08's in-progress `token.rs` was mid-change. A retry after a wait was green.

## Next Phase Readiness

- 02-15 (handlers) needs to:
  - map POST bodies to `FlowInput`;
  - map `Forbidden` to the `csrf` error page;
  - set the flow cookie from `StartedFlow`, including after `Restarted`;
  - answer `SignedIn` with a 303 redirect to the authorize continuation;
  - call `BootstrapService::complete_setup` on `SetupSubmitted`;
  - render `Render` forms with status 400 when they carry an error message.

## Self-Check: PASSED

- All 8 files exist; commits f73d7f8 and 7604d0f are in the log.
