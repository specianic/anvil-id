---
phase: 7
slug: release-1-0-certification
status: planned
nyquist_compliant: true
wave_0_complete: false
created: 2026-11-26
---

# Phase 7 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test`: unit tests (KATs in-file), the storage contract via `storage_contract_tests!` (SQLite always; Postgres via testcontainers in CI or a throwaway local PG14 cluster), HTTP integration in `crates/anvil-web/tests`, binary/CLI tests in `crates/anvilid/tests`, proptest; Playwright e2e (`tests/e2e`); OpenID conformance (`tests/conformance/run.sh all`); cargo-fuzz (`fuzz/`). New in Phase 7: mdBook 0.5.4 build + `scripts/check-docs-site.sh` (07-07), the in-repo OpenAPI breaking-change test `api_compat.rs` (07-21) |
| **Config file** | `justfile`, `tests/e2e/playwright.config.ts`, `scripts/check-security-tests.sh`, `scripts/check-migrations.sh`, `fuzz/Cargo.toml`, `book.toml` (new, 07-07) |
| **Quick run command** | `cargo test -p <crate> --lib <module>` or `cargo test -p <crate> --test <file>` (the per-task commands below) |
| **Full suite command** | `just ci` + `tests/e2e/run.sh sqlite` (CI also runs postgres) + `tests/conformance/run.sh all` (CI) + mdBook build + `scripts/check-docs-site.sh` |
| **Estimated runtime** | Per-task commands: about 5-60 s each (crate-scoped). `just ci`: minutes. e2e and conformance: CI workflows |

---

## Sampling Rate

- **After every task commit:** run that task's `<automated>` command (crate- and file-scoped; Postgres only when Docker or local PG14 is available, otherwise state "CI").
- **After every plan wave:** `cargo test --workspace --locked` + `scripts/check-migrations.sh`; `just ci` at the end of waves 3, 5 and 7.
- **Before `/gsd:verify-work`:** the 07-23 gate: `just ci` green, every workflow green on the gate commit (ci, e2e sqlite + postgres, conformance with unchanged expected files, fuzz incl. `password_hash_parse`, docs, release-build, deploy, load).
- **Max feedback latency:** one task's crate-scoped tests (under about 60 s); full workspace per wave.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 7-01-01 | 01 | 1 | ADM-08 | lint/graph | `cargo build --workspace --all-targets --locked && just fuzz-check && cargo deny --locked check && just deps` + cargo-tree checks | ✅ | ⬜ pending |
| 7-01-02 | 01 | 1 | ADM-08 | unit (KAT) | `cargo test -p anvil-web --lib adapters::password` | ❌ W1 creates | ⬜ pending |
| 7-01-03 | 01 | 1 | ADM-08 | owner checkpoint | n/a: crypto exception approval | n/a | ⬜ pending |
| 7-02-01 | 02 | 1 | ADM-08 | unit + proptest | `cargo test -p anvil-core --lib policy::password_import` | ❌ W1 creates | ⬜ pending |
| 7-02-02 | 02 | 1 | ADM-08 | unit + fuzz build | `cargo test -p anvil-core --lib policy::password_import && just fuzz-check` | ❌ W1 creates | ⬜ pending |
| 7-03-01 | 03 | 1 | OIDC-18, UI-05, AGT-03, ADM-08, ADM-09 | unit | `cargo test -p anvil-core --lib model:: service::admin_scope service::role policy::webhook_event` (incl. `role_escalation_users_write_cannot_grant_export`) | ✅ extend | ⬜ pending |
| 7-03-02 | 03 | 1 | same | full + contract + console | `cargo test --workspace --locked && cargo test -p anvil-storage-sqlite --test contract client_new_fields && just console-check` (audit page action keys) | ✅ extend | ⬜ pending |
| 7-04-01 | 04 | 1 | OIDC-18, UI-05, ADM-08, ADM-09 | unit + integration | `cargo test -p anvil-web --lib layers::ratelimit && cargo test -p anvil-web --test skeleton_v10` | ❌ W1 creates | ⬜ pending |
| 7-04-02 | 04 | 1 | same | binary | `cargo test -p anvilid --test users_import_skeleton --test users_export_skeleton` | ❌ W1 creates | ⬜ pending |
| 7-05-01 | 05 | 1 | UI-05 | unit + integration | `cargo test -p anvil-web --lib ui::flow_driver` + login/bruteforce/captcha/HRD tests | ✅ extend | ⬜ pending |
| 7-05-02 | 05 | 1 | UI-05 | regression + grep | `cargo test -p anvil-web --locked` + single-call-site grep | ✅ | ⬜ pending |
| 7-06-01 | 06 | 1 | SEC-08 | lint (grep) | SECURITY.md / scope / threat-model greps + no-email grep | ❌ W1 creates | ⬜ pending |
| 7-06-02 | 06 | 1 | SEC-08 | owner checkpoint | n/a: enable private vulnerability reporting | n/a | ⬜ pending |
| 7-07-01 | 07 | 1 | QUAL-03 | script self-test + build | `scripts/check-docs-site.sh --self-test` + no `](../` links in docs/*.md + scratch mdBook build + check | ❌ W1 creates | ⬜ pending |
| 7-07-02 | 07 | 1 | QUAL-03 | workflow lint | YAML parse + greps on docs.yml | ❌ W1 creates | ⬜ pending |
| 7-08-01 | 08 | 2 | OIDC-18, ADM-08, ADM-09, QUAL-03 | preflight + build | 06-26 SUMMARY exists, newest migrations SQLite 0009 / Postgres 0007, then `cargo build --workspace --all-targets --locked` | ✅ | ⬜ pending |
| 7-08-02 | 08 | 2 | same | contract | `cargo test -p anvil-storage-sqlite --test contract && scripts/check-migrations.sh && just sqlx-check crate=crates/anvil-storage-sqlite` | ❌ W2 creates par/password_profiles | ⬜ pending |
| 7-08-03 | 08 | 2 | QUAL-03 | upgrade | `cargo test -p anvil-storage-sqlite --test upgrade` | ✅ extend | ⬜ pending |
| 7-09-01 | 09 | 2 | ADM-08 | unit | `cargo test -p anvil-web --lib adapters::password adapters::argon2` | ✅ extend | ⬜ pending |
| 7-09-02 | 09 | 2 | ADM-08 | regression | `cargo test -p anvil-web -p anvilid --locked` | ✅ | ⬜ pending |
| 7-10-01 | 10 | 2 | UI-05 | unit | `cargo test -p anvil-web --lib layers::cors layers::csrf api_flows` | ✅ extend | ⬜ pending |
| 7-10-02 | 10 | 2 | UI-05 | integration (security) + drift | `cargo test -p anvil-web --test headless_flows --test security_headless --test openapi_flows_drift` | ❌ W2 creates | ⬜ pending |
| 7-10-03 | 10 | 2 | UI-05 | e2e | tsc; then, if Docker or local Mailpit is available, `tests/e2e/run.sh sqlite specs/headless.spec.ts` (no fallback), else CI | ❌ W2 creates | ⬜ pending |
| 7-11-01 | 11 | 3 | OIDC-18, ADM-08, ADM-09, QUAL-03 | preflight + contract (PG) | 06-26 SUMMARY exists; if `docker info` or `ANVILID_PG_LOCAL=1`: `cargo test -p anvil-storage-postgres --test contract` (no fallback), else CI | ✅ extend | ⬜ pending |
| 7-11-02 | 11 | 3 | QUAL-03 | upgrade (PG) | if a database is available: `cargo test -p anvil-storage-postgres --test upgrade` (no fallback), else CI | ✅ extend | ⬜ pending |
| 7-12-01 | 12 | 3 | OIDC-18, UI-05, AGT-03 | unit + integration (security) | `cargo test -p anvil-web --test security_registration --test security_cimd --test registration_dcr` | ✅ extend | ⬜ pending |
| 7-12-02 | 12 | 3 | same | integration + binary + drift | `cargo test -p anvil-web --test admin_client_fields_v10 --test openapi_drift && cargo test -p anvilid --test tenant_config` | ❌ W3 creates | ⬜ pending |
| 7-13-01 | 13 | 3 | OIDC-18 | unit | `cargo test -p anvil-core --lib oauth::par service::par oauth::authorize_request service::authorize` | ❌ W3 creates | ⬜ pending |
| 7-13-02 | 13 | 3 | OIDC-18 | integration (security) | `cargo test -p anvil-web --test par --test security_par --test discovery` | ❌ W3 creates | ⬜ pending |
| 7-14-01 | 14 | 3 | ADM-08 | unit | `cargo test -p anvil-core --lib service::user_import service::hash_profile` | ❌ W3 creates | ⬜ pending |
| 7-14-02 | 14 | 3 | ADM-08 | integration | `cargo test -p anvil-web --test import_login` | ❌ W3 creates | ⬜ pending |
| 7-14-03 | 14 | 3 | ADM-08 | binary | `cargo test -p anvilid --test users_import_cli` | ❌ W3 creates | ⬜ pending |
| 7-15-01 | 15 | 3 | ADM-09 | integration (security) | `cargo test -p anvil-web --test export_redaction` | ❌ W3 creates | ⬜ pending |
| 7-15-02 | 15 | 3 | ADM-09 | binary | `cargo test -p anvilid --test users_export_cli` | ❌ W3 creates | ⬜ pending |
| 7-16-01 | 16 | 4 | AGT-03 | unit | `cargo test -p anvil-core --lib flow::consent service::consent` | ✅ extend | ⬜ pending |
| 7-16-02 | 16 | 4 | AGT-03 | integration + i18n + e2e | `cargo test -p anvil-web --test consent_agent --test i18n_catalogs` + consent-agent.spec.ts | ❌ W4 creates | ⬜ pending |
| 7-17-01 | 17 | 4 | ADM-08, ADM-09 | integration (security) | `cargo test -p anvil-web --test admin_user_import --test security_import --test security_body_limit` | ❌ W4 creates | ⬜ pending |
| 7-17-02 | 17 | 4 | ADM-09 | integration (security) + drift | `cargo test -p anvil-web --test admin_user_export --test security_export --test openapi_drift` | ❌ W4 creates | ⬜ pending |
| 7-18-01 | 18 | 4 | UI-05 | unit + regression | `cargo test -p anvil-core --lib service::flow service::authorize && cargo test -p anvil-web --lib ui::flow_driver` | ✅ extend | ⬜ pending |
| 7-18-02 | 18 | 4 | UI-05 | integration (security) | `cargo test -p anvil-web --test headless_native --test security_headless --test openapi_flows_drift` | ❌ W4 creates | ⬜ pending |
| 7-19-01 | 19 | 4 | OIDC-23 | script lint + conformance | `bash -n tests/conformance/setup.sh` + workflow parse; if Docker is available, `tests/conformance/run.sh all` (no fallback), else CI | ✅ extend | ⬜ pending |
| 7-19-02 | 19 | 4 | OIDC-23 | doc lint | greps on docs/CERTIFICATION.md (no fees, plan names present) | ❌ W4 creates | ⬜ pending |
| 7-20-01 | 20 | 5 | ADM-08, ADM-09, OIDC-18, AGT-03, UI-05 | console check + build | `just console-check && (cd admin-ui && npm run build)` | ✅ extend | ⬜ pending |
| 7-20-02 | 20 | 5 | same | e2e | if Docker or local Mailpit is available, `tests/e2e/run.sh sqlite specs/console-users-import.spec.ts specs/console-clients-v10.spec.ts` (no fallback), else CI | ❌ W5 creates | ⬜ pending |
| 7-21-01 | 21 | 5 | QUAL-03 | compat test + unit | `cargo test -p anvil-web --test api_compat && cargo test -p anvil-core --lib model::config_doc` | ❌ W5 creates | ⬜ pending |
| 7-21-02 | 21 | 5 | QUAL-03 | doc lint | greps on COMPATIBILITY.md and UPGRADING.md | ❌ W5 creates | ⬜ pending |
| 7-22-01 | 22 | 6 | QUAL-03, ADM-08 | owner checkpoint | n/a: vendor list for migration guides (Q12) | n/a | ⬜ pending |
| 7-22-02 | 22 | 6 | QUAL-03, ADM-08 | doc lint | greps on INSTALL, guides, migration pages | ❌ W6 creates | ⬜ pending |
| 7-22-03 | 22 | 6 | QUAL-03, SEC-08 | site build + check | `scripts/check-docs-site.sh --self-test` + scratch mdBook build + check | ✅ extend | ⬜ pending |
| 7-23-01 | 23 | 7 | all | gate | `scripts/check-security-tests.sh (+ --self-test) && scripts/check-migrations.sh && cargo test --workspace --locked` + version/pin/tick greps | ✅ extend | ⬜ pending |
| 7-23-02 | 23 | 7 | all | owner checkpoint | n/a: push + rc tag authorization | n/a | ⬜ pending |
| 7-23-03 | 23 | 7 | all | CI + tag precondition | every workflow `success` for HEAD (`gh run list ...`); before the rc tag, three Phase 6 tags or a recorded `Q9 waiver:` | ✅ | ⬜ pending |
| 7-24-01 | 24 | 8 | OIDC-23 | CI evidence | conformance run `success` for the gate commit (`gh run list --commit`) | ✅ | ⬜ pending |
| 7-24-02 | 24 | 8 | OIDC-23 | owner checkpoint | n/a: hosted-suite runs + certification submission | n/a | ⬜ pending |
| 7-25-01 | 25 | 8 | SEC-08 | owner checkpoint | n/a: commission external review | n/a | ⬜ pending |
| 7-25-02 | 25 | 8 | SEC-08 | owner checkpoint | n/a: review completed, findings tracked privately | n/a | ⬜ pending |
| 7-26-01 | 26 | 9 | SEC-08 | owner checkpoint | n/a: real-IdP SAML interop checklist | n/a | ⬜ pending |
| 7-26-02 | 26 | 9 | SEC-08 | owner checkpoint | n/a: SAML flag + chrono decision | n/a | ⬜ pending |
| 7-27-01 | 27 | 10 | all | owner checkpoint | n/a: 1.0.0 sign-off | n/a | ⬜ pending |
| 7-27-02 | 27 | 10 | all | release gate | v0.3.0/v0.4.0/v1.0.0-beta.1 present or `Q9 waiver:` recorded; version/pin/tick greps; every workflow `success` for HEAD | ✅ | ⬜ pending |
| 7-27-03 | 27 | 10 | all | release verify | `gh release view v1.0.0` (not prerelease, assets) + STATE record | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

Review gap plans (07-28 onward) are created by `/gsd:plan-phase 7 --gaps` once private findings exist (07-25) or the owner
requests a SAML/chrono change (07-26). Each fix adds a named negative test to the security map. Their public text stays
generic until 1.0 ships.

---

## Wave 0 Requirements

Phase 7 has no separate Wave 0. The test scaffolding is created inside the wave-1/wave-2 plans that own each area, and
every task carries its own `<automated>` command:

- [ ] `crates/anvil-storage/src/contract/{par,password_profiles}.rs` + `users.rs`/`clients.rs`/`grants.rs` extensions (CAS rehash, PAR single winner): 07-08
- [ ] Upgrade fixtures `tests/fixtures/release_1_0_beta1.sql` (SQLite 07-08, Postgres 07-11) and the 0.4/beta.1 → final tests
- [ ] Test support: `tests/par_support` (07-13), `tests/headless_support` (07-10); the dispatcher in `tests/support` and `tests/ui_helpers` (07-09)
- [ ] Fuzz target `password_hash_parse` (07-02)
- [ ] `tests/e2e/specs/{headless,consent-agent,console-users-import,console-clients-v10}.spec.ts` + the SPA fixture (07-10, 07-16, 07-20)
- [ ] `scripts/check-docs-site.sh` + `.github/workflows/docs.yml` (07-07); `crates/anvil-web/tests/api_compat.rs` (07-21)
- [ ] `scripts/check-security-tests.sh` entries for every Phase 7 control (07-23, the map's only Phase 7 editor)
- [ ] Tool installs: mdBook 0.5.4 (scratch `cargo install --root` locally; pinned in CI). No oasdiff (decision Q13)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Legacy-hash crypto exception approved | ADM-08 | Owner policy decision (Q1) | 07-01 Task 3 checkpoint |
| Private vulnerability reporting enabled | SEC-08 | Only repo owners/admins can enable it | 07-06 Task 2; verified with `gh api .../private-vulnerability-reporting` when the token allows |
| Vendor list for migration guides | ADM-08 | Owner decision (Q12); public-repo rule | 07-22 Task 1 |
| Push and rc tag | all | Owner authorization | 07-23 Task 2 |
| OpenID certification filed | OIDC-23 | Needs the hosted suite, a public deployment, OIDF membership/waiver and a signed declaration | 07-24 Task 2 (runbook docs/CERTIFICATION.md) |
| External security review completed, findings fixed | SEC-08 | Third-party engagement; findings private until fixed | 07-25 Tasks 1-2, then review gap plans with their own automated tests |
| Real-IdP SAML interop and flag decision; chrono review | SEC-08 (Phase 6 carry-over) | Real IdP accounts; owner decision | 07-26 Tasks 1-2 |
| 1.0.0 publish and Pages | all | Irreversible public release; Pages enablement is an owner setting | 07-27 Task 1 |

Everything else has automated verification. The headless SPA, consent-agent and console journeys are Playwright specs;
they run locally without Docker where possible and are authoritative in CI (both backends).

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or are owner checkpoints
- [x] Sampling continuity: no 3 consecutive auto tasks without automated verify (the only consecutive non-automated tasks are owner checkpoints in 07-25/07-26)
- [x] Wave 0 covers all MISSING references (no MISSING verifies; each owning plan creates its tests)
- [x] No watch-mode flags
- [x] Feedback latency: crate-scoped per-task commands
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending (plan checker)
