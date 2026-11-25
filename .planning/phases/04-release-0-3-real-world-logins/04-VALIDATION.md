---
phase: 4
slug: release-0-3-real-world-logins
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-11-25
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> The authoritative requirement → test map is in 04-RESEARCH.md § Validation Architecture
> ("Phase Requirements → Test Map" and "Wave 0 Gaps"). The planner copies each row into task
> `<automated>` verify blocks.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust test harness (tokio::test, proptest, insta, wiremock mock IdPs, testcontainers); Playwright for e2e (AnvilID-as-upstream + Node mock IdP); OpenID conformance suite (Docker) incl. RP-Initiated and Back-Channel Logout plans |
| **Config file** | Existing workspace, justfile, tests/e2e, tests/conformance; Wave 0 adds mock-IdP fixtures and conformance logout config |
| **Quick run command** | `cargo test -p <crate-touched>` |
| **Full suite command** | `cargo test --workspace` (SQLite + Postgres) && `tests/e2e/run.sh sqlite` && `tests/e2e/run.sh postgres` && `tests/conformance/run.sh all` && `scripts/check-security-tests.sh` |
| **Estimated runtime** | ~900 seconds (full) |

---

## Sampling Rate

- **After every task commit:** quick run for the touched crate + clippy
- **After every plan wave:** `cargo test --workspace` on SQLite and Postgres
- **Before `/gsd:verify-work`:** full suite incl. Playwright and all conformance plans green in CI
- **Max feedback latency:** 120 seconds (quick run)

---

## Per-Task Verification Map

See 04-RESEARCH.md § Validation Architecture → Phase Requirements → Test Map. Every phase requirement ID has at
least one automated command there; Task IDs are assigned by the planner.

---

## Wave 0 Requirements

See 04-RESEARCH.md § Validation Architecture → Wave 0 Gaps.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real Google/Apple/Microsoft/GitHub sign-in | AUTH-07 | User decision: no provider secrets in CI | docs manual real-provider checklist, run by the owner before release |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
