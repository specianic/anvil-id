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
- **Wave 1 gate:** plan 04-01's targeted commands only — `cargo build --workspace --all-targets --locked`, `cargo test -p anvil-core --lib`,
  `cargo test -p anvil-jose --lib -- email_code pem`, `cargo test -p anvil-web --test openapi_drift`, `cargo test -p anvil-web --test shell`,
  `cargo test -p anvil-storage-sqlite --test contract -- tenants setup outbox audit`, `cargo deny check`, `scripts/check-deps.sh` — plus
  04-02's and 04-03's own task commands. `cargo test --workspace` is NOT a wave-1 gate: the new contract tests deliberately fail with
  `StorageError::Unsupported` against the TRANSITIONAL(04-04)/(04-05) backend shims until wave 2.
- **After wave 2 and every later wave:** `cargo test --workspace` on SQLite and Postgres. One documented exception until wave 3:
  the two tests that exercise default templates for the three new email kinds — `cargo test -p anvil-mail --test templates`
  (`every_kind_accepts_a_template_using_all_its_variables`) and the email-template list assertion in `cargo test -p anvil-web --test
  admin_api_v02` — stay red as TRANSITIONAL(04-15) and are skipped by name in the wave-2 run; 04-15 (wave 3) makes them green and
  from wave 3 on the full workspace gate has no exceptions.
- **Before `/gsd:verify-work`:** full suite incl. Playwright and all conformance plans green in CI
- **Max feedback latency:** 120 seconds (quick run)

---

## Per-Task Verification Map

Source map: 04-RESEARCH.md § Validation Architecture. Plan assignment (every task in every plan carries an `<automated>` verify):

| Requirement | Plans (task-level automated commands in each plan) |
|-------------|-----------------------------------------------------|
| OIDC-12 | 04-08 (`cargo test -p anvil-core --lib -- oauth::logout`), 04-13 (`--test logout --test security_logout`), 04-17 (`--test backchannel`, anvilid `--test backchannel_worker`), 04-04/05 contract `logout`, 04-10/04-23 (`tests/conformance/run.sh logout|backchannel|all`), 04-28 (`specs/logout.spec.ts`) |
| OIDC-14 | 04-16 (`--test authorize_step_up`), 04-20 (`--test authorize_prompt`), 04-24 (login_hint on email form), 04-28 (`specs/prompt.spec.ts`) |
| OIDC-16 | 04-08 (`oauth::resource`), 04-12 (`--test resource_indicators`) |
| AUTH-06 | 04-01 (`cargo test -p anvil-jose --lib -- email_code`), 04-24 (`--test flow_email_code --test security_email_code`), 04-29 (`specs/email-code.spec.ts`) |
| AUTH-07 | 04-01 (`cargo test -p anvil-jose --lib -- pem`, the single PEM helper for Apple keys), 04-02 (`--test security_ssrf`), 04-07 (`upstream`, incl. `apple_client_secret_claims` audience), 04-14 (`--test upstream_adapter`), 04-21 (`--test upstream_login`), 04-26 (`--test upstream_{google,microsoft,apple,github,oauth2}`), 04-27 (`specs/social.spec.ts`), manual: docs/social-login-checklist.md (04-33 checkpoint) |
| AUTH-08 | 04-08 (`policy::mfa`), 04-16 (`--test flow_mfa_policy --test authorize_step_up`), 04-28 (`specs/mfa-policy.spec.ts`) |
| AUTH-11 | 04-07 (`upstream::linking`), 04-21 (`--test security_linking`), 04-25 (`--test account_linked`), 04-27 (`specs/linking.spec.ts`) |
| AUTH-13 | 04-01/04/05 contract `complete_email_change`, 04-15 (`--test account_profile`), 04-25, 04-29 (`specs/account.spec.ts`) |
| UI-03 | 04-09 (`policy::branding`), 04-18 (`--test theme --test security_theme --test admin_branding`), 04-22 (console build), 04-29 (`specs/theme.spec.ts`) |
| UI-04 | 04-06 (`--test i18n`), 04-30 (`--test i18n_catalogs`, `specs/i18n.spec.ts`) |
| SEC-03 | 04-04/05 (`--test plaintext`), 04-11 (`--test admin_connections --test security_admin_v03`) |
| QUAL-01 gate | 04-32 (`scripts/check-security-tests.sh` + `--self-test`, `just ci`, all workflows green) |

---

## Wave 0 Requirements

Wave 0 gaps (04-RESEARCH.md) are owned by: contract suite files -> 04-01; anvil-web test support (MockProvider) -> 04-14
(`tests/upstream_support/mod.rs`); `tests/e2e/lib/mock-idp.ts` + AnvilID-as-upstream helpers + sample RP logout/back-channel -> 04-03;
conformance logout/backchannel selections, CA/leaf, nginx mount, browser tasks -> 04-10 (setup.sh metadata in 04-23);
security-test map entries -> 04-32; Fluent deps + `cargo deny` -> 04-01.

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
