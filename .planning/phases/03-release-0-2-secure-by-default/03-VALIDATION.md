---
phase: 3
slug: release-0-2-secure-by-default
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-11-25
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> The authoritative requirement → test map is in 03-RESEARCH.md § Validation Architecture
> ("Phase Requirements → Test Map" and "Wave 0 Gaps"). The planner copies each row into task
> `<automated>` verify blocks.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust test harness (tokio::test, proptest, insta, testcontainers); Playwright for e2e; OpenID conformance suite (Docker) |
| **Config file** | Workspace + justfile from Phase 1; Wave 0 adds e2e/conformance configs listed in research |
| **Quick run command** | `cargo test -p <crate-touched>` |
| **Full suite command** | `cargo test --workspace (both DBs) && admin-ui typecheck+build && npx playwright test && conformance Basic+Config+FormPost && upgrade test` |
| **Estimated runtime** | ~600 seconds (full, incl. Postgres + e2e) |

---

## Sampling Rate

- **After every task commit:** quick run for the touched crate + clippy
- **After every plan wave:** `cargo test --workspace` on SQLite and Postgres
- **Before `/gsd:verify-work`:** full suite incl. Playwright and conformance plans green
- **Max feedback latency:** 120 seconds (quick run)

---

## Per-Task Verification Map

See 03-RESEARCH.md § Validation Architecture → Phase Requirements → Test Map. Every phase
requirement ID has at least one automated command there; Task IDs are assigned by the planner.

---

## Wave 0 Requirements

See 03-RESEARCH.md § Validation Architecture → Wave 0 Gaps.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| (none expected) | — | — | All phase behaviors have automated verification |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
