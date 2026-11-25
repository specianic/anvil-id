---
phase: 3
slug: release-0-2-secure-by-default
status: draft
nyquist_compliant: true
wave_0_complete: false
planned: 2026-11-25
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

Source of truth for commands: each plan's `<verify><automated>` blocks. Summary by requirement:

| Req | Plans | Key automated checks |
|-----|-------|----------------------|
| OIDC-10 | 03-18 | `cargo test -p anvil-web --test security_introspect_revoke` (both DBs) |
| OIDC-11 | 03-01, 03-10, 03-18 | `cargo test -p anvil-jose`; `cargo test -p anvil-web --test id_token_alg --test discovery` |
| SEC-02 | 03-10, 03-24 | `cargo test -p anvil-core key_rotation`; `--test jwks_rotation`; `cargo test -p anvilid --test jobs --test keys_cli` |
| OIDC-13 | 03-17, 03-21, 03-27 | `--test consent --test account_apps`; `playwright consent.spec.ts` |
| OIDC-15 | 03-18 | `--test access_token_format` |
| OIDC-25 | 03-11, 03-28 | `--test response_mode`; `tests/conformance/run.sh formpost` |
| AUTH-04 | 03-09, 03-12, 03-14, 03-20, 03-26 | `--test passkey_adapter --test account_security --test flow_passkey`; `playwright passkey.spec.ts` |
| AUTH-05 | 03-01, 03-02 (contract concurrency), 03-12, 03-14, 03-20, 03-26 | `cargo test -p anvil-storage-* --test contract`; `--test flow_mfa`; `playwright totp.spec.ts` |
| AUTH-09 / SEC-05 | 03-07, 03-13, 03-20 | `cargo test -p anvil-cache`; `--test security_ratelimit --test captcha --test security_bruteforce` |
| AUTH-10 | 03-19, 03-23, 03-27 | `--test sessions --test admin_api_v02`; `playwright sessions.spec.ts` |
| OPS-06 | 03-08, 03-24 | `--test client_ip` (incl. proptest); `cargo test -p anvilid --test config_phase3` |
| UI-02 | 03-04, 03-27 | `playwright a11y.spec.ts nojs.spec.ts keyboard.spec.ts` |
| UI-07 | 03-15, 03-23, 03-25 | `cargo test -p anvil-mail`; `--test admin_api_v02`; `playwright console.spec.ts` |
| ADM-04 | 03-02, 03-12, 03-21, 03-23, 03-25 | `--test admin_audit --test admin_api_v02`; AuditService unit test (no secrets in mirror) |
| OPS-04 | 03-05, 03-06, 03-16, 03-29 | `cargo test -p anvil-storage-{sqlite,postgres} --test upgrade`; `scripts/check-migrations.sh --self-test` |

Wave 0 gaps (research) → owning plans: webauthn/axe fixtures, TOTP helper, nojs project (03-04); upgrade fixtures + check-migrations
(03-16); Form Post conformance config (03-28); Node 22 in CI (03-03, 03-04); SMTP sink (in-test sink in 03-15, Mailpit in e2e).
Global e2e setup already exists from 02-20 (`tests/e2e/run.sh`).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| (none expected) | — | — | All phase behaviors have automated verification |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [ ] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
