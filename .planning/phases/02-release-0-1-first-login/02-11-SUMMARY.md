---
phase: 02-release-0-1-first-login
plan: 11
subsystem: mail
tags: [email, smtp, lettre, minijinja, outbox, backoff]
requires:
  - phase: 02-01
    provides: lettre/minijinja/rust-embed workspace deps (no ring)
  - phase: 02-02
    provides: OutboxRepo port (claim_due/mark_sent/mark_failed), OutboxEmail model, Clock
  - phase: 02-03
    provides: themes/default/emails templates and payload-key contract
provides:
  - "anvil_mail::EmailRenderer (embedded + theme-dir override, strict undefined)"
  - "anvil_mail::MailTransport port, OutgoingMail, SmtpTransport::from_url"
  - "anvil_mail::OutboxWorker::{run_once, run}, OutboxAccess, StorageOutbox"
affects: [02-18 binary wiring (start worker only when SMTP configured), 02-20 Playwright + Mailpit]
tech-stack:
  added: []
  patterns:
    - "Worker depends on a narrow OutboxAccess trait, not the whole Storage"
    - "Error text from render/send never includes payload, body or links"
key-files:
  created:
    - crates/anvil-mail/src/render.rs
    - crates/anvil-mail/src/transport.rs
    - crates/anvil-mail/src/worker.rs
    - crates/anvil-mail/tests/worker.rs
    - crates/anvil-mail/tests/support/mod.rs
  modified:
    - crates/anvil-mail/src/lib.rs
key-decisions:
  - "Email subject = first line of the .txt template; an optional 'Subject:' prefix is stripped (the shipped templates have no prefix)"
  - "Strict undefined in email templates: a missing payload key fails the row instead of sending a blank link"
  - "Render errors are reported as template:line + error kind only, never minijinja's full display"
  - "SmtpTransport errors never echo the URL (credentials); construction needs a Tokio runtime (lettre pool)"
  - "OutgoingMail.from empty -> transport default sender; the worker always sets it"
  - "Backoff computed from the post-claim attempts count; failed rows are also capped at expires_at"
patterns-established:
  - "Test doubles for mail (CapturingTransport, TestClock, MemOutbox) live only under crates/anvil-mail/tests/support"
requirements-completed: [AUTH-02, AUTH-03]
duration: 25min
completed: 2026-11-25
---

# Phase 2 Plan 11: Email Delivery (Renderer, SMTP Transport, Outbox Worker) Summary

**Outbox worker that renders embedded theme emails with minijinja (strict, HTML auto-escaped) and sends them via lettre SMTP over rustls/aws-lc-rs, with 2-minute claim leases, 30 s to 1 h exponential backoff and give-up after 8 attempts.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- `EmailRenderer` renders verification, recovery, invitation and password_changed from the embedded `themes/default/emails`. An operator theme dir overrides individual files and the rest fall back to the embedded defaults. Template names are restricted to `[a-z0-9_]`, which confines theme-dir lookups.
- `SmtpTransport::from_url` accepts smtp:// and smtps:// only, sends multipart/alternative and sets a 30 s timeout. `cargo tree -p anvil-mail -e normal -i ring` is empty.
- `OutboxWorker` claims rows, renders and sends them, then marks them sent. Each failure is recorded per row, so the batch keeps going. `run` polls every 2 s when idle and stops on shutdown.
- 13 unit tests and 6 integration tests. They cover sending, the 30 s backoff (nothing sent at 29 s, sent at 30 s), doubling up to the give-up at 8 attempts, render failures, a missing payload key, no leaked links or bodies, and run/shutdown.

## Task Commits

1. **Task 1: Renderer and SMTP transport** - `7733489` (feat)
2. **Task 2: Outbox worker with backoff, capturing-transport tests** - `c5e5020` (feat)

## Files Created/Modified
- `crates/anvil-mail/src/lib.rs` - module wiring and `MailError`
- `crates/anvil-mail/src/render.rs` - `EmailRenderer`
- `crates/anvil-mail/src/transport.rs` - `MailTransport`, `OutgoingMail` (Debug: to + subject only), `SmtpTransport`
- `crates/anvil-mail/src/worker.rs` - `OutboxWorker`, `OutboxAccess`, `StorageOutbox`, `backoff`
- `crates/anvil-mail/tests/support/mod.rs` - `CapturingTransport`, `TestClock`, `MemOutbox`
- `crates/anvil-mail/tests/worker.rs` - worker semantics tests

## Decisions Made
See key-decisions in the frontmatter. In particular, the interface asked for a "Subject: ..." first line, but the shipped templates (02-03) use a bare subject line. The renderer accepts both, so the templates were left as they are.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] lettre pooled transport needs a Tokio runtime at construction**
- **Found during:** Task 1
- **Fix:** Tests that build `SmtpTransport` use `#[tokio::test]`. The requirement is documented on `from_url`.
- **Commit:** 7733489

**2. [Rule 3 - Blocking] Verification ran in a clean worktree**
- **Issue:** A parallel plan had uncommitted, non-compiling edits in `anvil-core` (flow engine), so `cargo test -p anvil-mail` in the shared tree could not build.
- **Fix:** Tests, clippy and the ring check ran in a temporary `git worktree` at HEAD with the anvil-mail files overlaid. Clippy was scoped with `--no-deps` (see Deferred Issues).

## Deferred Issues
- `crates/anvil-core/src/service/client_auth.rs:87` fails `clippy::manual_is_multiple_of` under `-D warnings` at HEAD. This is outside anvil-mail's scope and was not fixed.
- The `StorageOutbox` path against real backends is not tested here. As the plan intends, it is covered end to end by 02-20 (Playwright + Mailpit).

## Next Phase Readiness
- 02-18 can build `OutboxWorker { source: Arc::new(StorageOutbox(storage)), transport: Arc::new(SmtpTransport::from_url(url, from)?), renderer, clock, from }`. It should spawn `worker.run(shutdown)` only when SMTP is configured.

---
*Phase: 02-release-0-1-first-login*
*Completed: 2026-11-25*

## Self-Check: PASSED
