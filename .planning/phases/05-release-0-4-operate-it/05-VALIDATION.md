---
phase: 5
slug: release-0-4-operate-it
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-11-26
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test` (unit; storage contract via `storage_contract_tests!`; new limiter contract via `limiter_contract_tests!` in anvil-cache; HTTP integration in `crates/anvil-web/tests`; binary tests in `crates/anvilid/tests`), proptest, insta, wiremock, testcontainers (Postgres + Redis); Playwright e2e (`tests/e2e`); OpenID conformance (`tests/conformance`); new: k6 (load/HA, `tests/load`), Helm chart-testing on kind + compose smoke (`.github/workflows/deploy.yml`) |
| **Config file** | `justfile` (`ci`, `test-pg`, new `test-redis`, new `fuzz-check`), `tests/e2e/playwright.config.ts`, `scripts/check-security-tests.sh`, `tests/load/*.js`, `deploy/helm/anvilid/ci/*.yaml`, `ct.yaml` |
| **Quick run command** | `cargo test -p <crate> --lib` or `cargo test -p <crate> --test <file>` (the task's `<automated>` command) |
| **Full suite command** | `just ci` + `tests/e2e/run.sh sqlite` / `postgres` + `tests/conformance/run.sh all`; CI only (Docker): `just test-pg`, `just test-redis`, `tests/load/run-perf.sh`, `tests/load/run-ha.sh`, deploy workflow |
| **Estimated runtime** | targeted commands 10–60 s after an incremental build; `just ci` ~15–25 min; e2e ~10 min per backend; perf/HA ~15 min in CI |

---

## Sampling Rate

- **After every task commit:** run the task's `<automated>` command (targeted crate/test file, < 60 s incremental).
- **After every plan wave:** `cargo build --workspace --all-targets --locked && cargo test --workspace --locked` (from wave 2 on; waves 1-2 use the foundation plans' targeted gates because the storage shims fail new contract tests with `Unsupported` by design until wave 3), plus `just console-check` after waves touching admin-ui.
- **Before `/gsd:verify-work`:** `just ci` green; e2e sqlite + postgres green; conformance `all` green with expected failures `[]`; `load.yml` (perf + HA) and `deploy.yml` green on the release commit with numbers recorded (05-28).
- **Max feedback latency:** 60 s for task-level commands (Rust incremental builds dominate; the template's 5 s is not achievable for this workspace).
- **Docker rule:** tests needing Postgres/Redis containers, compose, kind or k6 are run locally only when Docker is available; otherwise the executor runs everything else and states that the Docker-backed part runs in CI (Phase 4 lesson). Local Postgres may use a PG14 throwaway cluster for `.sqlx` regeneration.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 5-01-01 | 01 | 1 | ORG-05, ADM-05, ADM-06 +3 | build | `cargo build --workspace --all-targets --locked && cargo deny --locked check && scripts/check-deps.sh && test -z "$(cargo tree -i ring --t…` | ❌ created in task | ⬜ pending |
| 5-01-02 | 01 | 1 | ORG-05, ADM-05, ADM-06 +3 | build | `cargo build --workspace --all-targets --locked && cargo test -p anvil-core --lib && cargo test -p anvil-web --test openapi_drift && (cd a…` | ❌ created in task | ⬜ pending |
| 5-02-01 | 02 | 2 | ORG-05, ADM-05, AUTH-14 +2 | build+contract | `cargo build --workspace --all-targets --locked && cargo test -p anvil-core --lib && cargo test -p anvil-web --test shell --test openapi_d…` | ❌ created in task | ⬜ pending |
| 5-02-02 | 02 | 2 | ORG-05, ADM-05, AUTH-14 +2 | build+contract | `cargo test -p anvil-storage-sqlite --test contract --no-run && cargo test -p anvil-storage-sqlite --test contract -- tenants outbox logou…` | ❌ created in task | ⬜ pending |
| 5-03-01 | 03 | 1 | QUAL-05, OPS-03 | integration+CI | `cargo test -p anvil-web --test security_body_limit && cargo test -p anvil-web --lib && cargo check --manifest-path fuzz/Cargo.toml --lock…` | ❌ created in task | ⬜ pending |
| 5-03-02 | 03 | 1 | QUAL-05, OPS-03 | integration+CI | `bash -n tests/load/lib.sh tests/load/run-perf.sh tests/load/run-ha.sh && grep -q "constant-arrival-rate" tests/load/token.js && grep -q "…` | ❌ created in task | ⬜ pending |
| 5-04-01 | 04 | 1 | ORG-01 | typecheck+e2e | `cd admin-ui && npm run typecheck && npm run build && ! grep -rn "CONSOLE_TENANT" src` | ❌ created in task | ⬜ pending |
| 5-04-02 | 04 | 1 | ORG-01 | typecheck+e2e | `cd admin-ui && npm run typecheck && npm run build && cd .. && tests/e2e/run.sh sqlite specs/console.spec.ts specs/console-connections.spe…` | ❌ created in task | ⬜ pending |
| 5-05-01 | 05 | 2 | OPS-08, OPS-03, QUAL-05 | integration+binary | `cargo test -p anvilid --test config_phase5 --test serve && cargo test -p anvil-web --test health_metrics -- health && cargo test -p anvil…` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-05-02 | 05 | 2 | OPS-08, OPS-03, QUAL-05 | integration+binary | `cargo test -p anvil-web --test health_metrics && cargo test -p anvil-web --lib observability && cargo test -p anvilid --lib telemetry` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-05-03 | 05 | 2 | OPS-08, OPS-03, QUAL-05 | integration+binary | `cargo test -p anvilid --lib telemetry && cargo test -p anvilid --test serve -- otel && bash -n scripts/measure-idle.sh && grep -q 102400 …` | ❌ created in task | ⬜ pending |
| 5-06-01 | 06 | 3 | ORG-05, ADM-05, AUTH-14 +2 | contract+upgrade | `cargo test -p anvil-storage-sqlite --test contract -- roles attributes registration clients consent setup tenants` | ❌ created in task | ⬜ pending |
| 5-06-02 | 06 | 3 | ORG-05, ADM-05, AUTH-14 +2 | contract+upgrade | `cargo test -p anvil-storage-sqlite --test contract && cargo test -p anvil-storage-sqlite --test upgrade --test plaintext && ! grep -rn "T…` | ❌ created in task | ⬜ pending |
| 5-07-01 | 07 | 3 | ORG-05, ADM-05, AUTH-14 +3 | contract+upgrade (PG) | `ANVILID_TEST_DB=postgres cargo test -p anvil-storage-postgres --test contract -- roles attributes registration clients consent setup tenants` | ❌ created in task | ⬜ pending |
| 5-07-02 | 07 | 3 | ORG-05, ADM-05, AUTH-14 +3 | contract+upgrade (PG) | `ANVILID_TEST_DB=postgres cargo test -p anvil-storage-postgres --test contract && ANVILID_TEST_DB=postgres cargo test -p anvil-storage-pos…` | ❌ created in task | ⬜ pending |
| 5-08-01 | 08 | 2 | OPS-03 | contract (+Redis CI) | `cargo test -p anvil-cache --test limiter_contract --test limiter` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-08-02 | 08 | 2 | OPS-03 | contract (+Redis CI) | `cargo test -p anvil-cache && cargo clippy -p anvil-cache --all-targets -- -D warnings && (docker info >/dev/null 2>&1 && just test-redis …` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-09-01 | 09 | 3 | OIDC-17, AGT-02 | unit+proptest | `cargo test -p anvil-core oauth::registration && cargo check --manifest-path fuzz/Cargo.toml --locked --bins` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-09-02 | 09 | 3 | OIDC-17, AGT-02 | unit+proptest | `cargo test -p anvil-core oauth::cimd && cargo check --manifest-path fuzz/Cargo.toml --locked --bins` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-10-01 | 10 | 3 | ORG-05, ADM-05, ADM-06 +1 | unit | `cargo test -p anvil-core policy::claims_mapping policy::webhook_event && cargo test -p anvil-jose --lib webhook && scripts/check-deps.sh` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-10-02 | 10 | 3 | ORG-05, ADM-05, ADM-06 +1 | unit | `cargo test -p anvil-core service::config && cargo test -p anvil-web --lib attribute_schema` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-11-01 | 11 | 2 | AUTH-14 | integration+e2e | `cargo test -p anvil-web --test flow_mfa_policy --test flow_passkey --test flow_mfa --test i18n_catalogs && cargo test -p anvil-core flow:…` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-11-02 | 11 | 2 | AUTH-14 | integration+e2e | `tests/e2e/run.sh sqlite specs/mfa-policy.spec.ts` | ❌ created in task | ⬜ pending |
| 5-12-01 | 12 | 4 | ORG-05 | unit+integration | `cargo test -p anvil-core service::role service::token service::claims && cargo test -p anvil-web --test rbac_claims --test token --test t…` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-12-02 | 12 | 4 | ORG-05 | unit+integration | `cargo test -p anvil-web --test admin_roles --test security_rbac --test openapi_drift --test admin_api && (cd admin-ui && npm run check:ap…` | ❌ created in task | ⬜ pending |
| 5-13-01 | 13 | 4 | ORG-05, AGT-01, AGT-02 | integration | `cargo test -p anvil-core service::consent flow::consent && cargo test -p anvil-web --test consent --test resource_indicators` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-13-02 | 13 | 4 | ORG-05, AGT-01, AGT-02 | integration | `cargo test -p anvil-web --test consent --test i18n_catalogs --test security_csp` | ❌ created in task | ⬜ pending |
| 5-14-01 | 14 | 4 | ADM-05, OPS-03 | integration+binary | `cargo test -p anvil-core service::webhook service::audit && cargo test -p anvil-web --test webhooks -- service` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-14-02 | 14 | 4 | ADM-05, OPS-03 | integration+binary | `cargo test -p anvil-web --test webhooks --test security_webhooks && cargo test -p anvilid --test webhook_worker` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-15-01 | 15 | 4 | AGT-02, AGT-01 | integration | `cargo test -p anvil-core service::client_resolver && cargo test -p anvil-web --test cimd -- resolver` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-15-02 | 15 | 4 | AGT-02, AGT-01 | integration | `cargo test -p anvil-web --test cimd --test security_cimd --test discovery --test authorize --test token --test security_client_auth --tes…` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-16-01 | 16 | 4 | OPS-03 | binary (Docker in CI) | `cargo test -p anvilid --lib limiter && (docker info >/dev/null 2>&1 && ANVILID_TEST_REDIS=1 cargo test -p anvilid --test limiter_redis \|…` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-16-02 | 16 | 4 | OPS-03 | binary (Docker in CI) | `cargo test -p anvil-core service::bootstrap service::key_rotation && (docker info >/dev/null 2>&1 && ANVILID_TEST_DB=postgres cargo test …` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-17-01 | 17 | 4 | ADM-07, OPS-07 | binary | `cargo test -p anvilid --test backup --test cli && cargo test -p anvil-storage-sqlite --lib backup` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-17-02 | 17 | 4 | ADM-07, OPS-07 | binary | `cargo test -p anvilid --test admin_recover --test healthcheck --test cli && cargo test -p anvil-core service::admin_recovery` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-18-01 | 18 | 3 | QUAL-05 | unit+integration | `cargo test -p anvil-core service::key && cargo test -p anvil-jose --lib && cargo test -p anvil-web --test jwks_rotation --test id_token_a…` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-18-02 | 18 | 3 | QUAL-05 | unit+integration | `cargo test -p anvil-web --test security_tenant --test discovery` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-19-01 | 19 | 4 | AUTH-14 | unit+integration | `cargo test -p anvil-core service::attribute && cargo test -p anvil-web --test security_attributes` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-19-02 | 19 | 4 | AUTH-14 | unit+integration | `cargo test -p anvil-web --test account_attributes --test i18n_catalogs --test security_csrf` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-20-01 | 20 | 5 | ADM-06, ADM-07 | unit+integration+binary | `cargo test -p anvil-core service::config` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-20-02 | 20 | 5 | ADM-06, ADM-07 | unit+integration+binary | `cargo test -p anvil-web --test admin_config --test security_admin_config --test openapi_drift && cargo test -p anvilid --test tenant_conf…` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-21-01 | 21 | 5 | OIDC-17 | unit+integration | `cargo test -p anvil-core service::registration` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-21-02 | 21 | 5 | OIDC-17 | unit+integration | `cargo test -p anvil-web --test registration_dcr --test security_registration --test discovery --test security_ratelimit` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-22-01 | 22 | 5 | OPS-09, OPS-08 | lint+CI deploy | `(command -v helm >/dev/null && helm lint deploy/helm/anvilid -f deploy/helm/anvilid/ci/sqlite-values.yaml && helm template t deploy/helm/…` | ❌ created in task | ⬜ pending |
| 5-22-02 | 22 | 5 | OPS-09, OPS-08 | lint+CI deploy | `bash -n deploy/compose/smoke.sh && python3 -c "import yaml; [yaml.safe_load(open(f)) for f in ['deploy/compose/postgres/compose.yml','dep…` | ❌ created in task | ⬜ pending |
| 5-23-01 | 23 | 6 | AUTH-14, ADM-05, OIDC-17 +2 | integration | `cargo test -p anvil-web --test admin_attributes --test admin_webhooks --test attribute_claims` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-23-02 | 23 | 6 | AUTH-14, ADM-05, OIDC-17 +2 | integration | `cargo test -p anvil-web --test admin_registration --test security_admin_v04 --test openapi_drift --test admin_api --test admin_api_v03 &&…` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-24-01 | 24 | 7 | ORG-01, ORG-05, AUTH-14 +4 | typecheck+e2e | `cd admin-ui && npm run typecheck && npm run build` | ❌ created in task | ⬜ pending |
| 5-24-02 | 24 | 7 | ORG-01, ORG-05, AUTH-14 +4 | typecheck+e2e | `cd admin-ui && npm run typecheck && npm run build` | ❌ created in task | ⬜ pending |
| 5-24-03 | 24 | 7 | ORG-01, ORG-05, AUTH-14 +4 | typecheck+e2e | `tests/e2e/run.sh sqlite specs/console-roles.spec.ts specs/console-webhooks.spec.ts specs/console-registration.spec.ts` | ❌ created in task | ⬜ pending |
| 5-25-01 | 25 | 7 | AGT-01, AGT-02 | integration+e2e | `cargo test -p anvil-web --test resource_indicators && python3 -c "import json; json.load(open('docs/examples/mcp/oauth-protected-resource…` | ❌ created in task | ⬜ pending |
| 5-25-02 | 25 | 7 | AGT-01, AGT-02 | integration+e2e | `tests/e2e/run.sh sqlite specs/mcp.spec.ts` | ❌ created in task | ⬜ pending |
| 5-26-01 | 26 | 7 | OPS-03, QUAL-05, OPS-08 | binary+CI load | `cargo test -p anvilid --test telemetry_redaction` | ❌ W0 (task writes tests first) | ⬜ pending |
| 5-26-02 | 26 | 7 | OPS-03, QUAL-05, OPS-08 | binary+CI load | `bash -n tests/load/run-perf.sh tests/load/run-ha.sh tests/load/lib.sh && node --check tests/load/webhook-sink.mjs && python3 -c "import y…` | ❌ created in task | ⬜ pending |
| 5-27-01 | 27 | 7 | ORG-05, AUTH-14, ADM-05 +6 | e2e+docs check | `tests/e2e/run.sh sqlite specs/attributes.spec.ts specs/webhooks.spec.ts specs/dcr.spec.ts specs/rbac-claims.spec.ts` | ❌ created in task | ⬜ pending |
| 5-27-02 | 27 | 7 | ORG-05, AUTH-14, ADM-05 +6 | e2e+docs check | `cargo run -q -p anvilid -- config show --insecure-http 2>/dev/null \| grep -o 'redis_url\\|otel_endpoint\\|metrics_listen\\|shutdown_drai…` | ❌ created in task | ⬜ pending |
| 5-28-01 | 28 | 8 | ORG-01, ORG-05, ADM-05 +11 | gate+CI | `scripts/check-security-tests.sh && scripts/check-security-tests.sh --self-test && scripts/check-migrations.sh && grep -q '^version = "0.4…` | ✅ existing | ⬜ pending |
| 5-28-02 | 28 | 8 | ORG-01, ORG-05, ADM-05 +11 | gate+CI | `test "$(gh run list --branch main --limit 30 --json headSha,conclusion,workflowName -q "[.[] \| select(.headSha==\"$(git rev-parse HEAD)\…` | ✅ existing | ⬜ pending |
| 5-29-01 | 29 | 9 | ORG-01, ORG-05, ADM-05 +11 | checkpoint+release | `checkpoint: owner resume signal` | ✅ existing | ⬜ pending |
| 5-29-02 | 29 | 9 | ORG-01, ORG-05, ADM-05 +11 | checkpoint+release | `gh release view v0.4.0 --json assets -q '.assets \| length' \| grep -qx 8` | ✅ existing | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

Requirement → plans (every Phase 5 ID is covered):

| Requirement | Plans |
|-------------|-------|
| ORG-01 | 05-04 (console multi-tenant), 05-23 (issuer on tenant DTO), 05-24 |
| ORG-05 | 05-01/05-02 (foundation), 05-06/05-07 (storage), 05-10 (claim mapping), 05-12 (RBAC, lockout + escalation guards), 05-13 (consent resources), 05-24, 05-27 |
| ADM-05 | 05-01/05-02, 05-06/05-07, 05-10 (signature, events), 05-14 (worker, lease), 05-23 (admin API), 05-24, 05-27 |
| ADM-06 | 05-01, 05-10 (plan diff), 05-20 (export/apply/CLI/API, system tenant rules), 05-24 |
| ADM-07 | 05-17 (backup, recover incl. fresh admin, healthcheck), 05-20 (import/export), 05-27 |
| OIDC-17 | 05-01/05-02, 05-06/05-07, 05-09 (validation, jwks_uri rejected), 05-21 (endpoint), 05-23 (policy + IATs), 05-24, 05-27 |
| AGT-01 | 05-13, 05-15, 05-25 (MCP e2e + docs) |
| AGT-02 | 05-01/05-02, 05-09 (http-loopback flag, jwks_uri rejected), 05-15 (resolver), 05-23, 05-24, 05-25 |
| AUTH-14 | 05-01/05-02, 05-10 (schema adapter), 05-19 (service + account page), 05-23, 05-24, 05-27 (05-11 passkey carry-over filed here for traceability only) |
| OPS-03 | 05-03 (harness), 05-05 (drain, pool, AppState handles), 05-07, 05-08 (Redis backend), 05-14 (exactly-once jobs), 05-16 (wiring, concurrent start), 05-26 (HA gate) |
| OPS-07 | 05-17 |
| OPS-08 | 05-05 (health, metrics, OTel, logs), 05-22 (shipped artefact smoke), 05-26 (redaction) |
| OPS-09 | 05-22 (Helm with database.type + Redis guard, Compose, deploy CI), 05-27 |
| QUAL-05 | 05-03 (harness), 05-05 (idle gate), 05-18 (perf work), 05-26 (CI gate), 05-28 (escalation after 3 failed median runs) |

---

## Wave 0 Requirements

Phase 5 has no separate wave-0 plan: each test scaffold is created by the first task that needs it (TDD tasks write their tests first) or
by the foundation plans 05-01 (wave 1: deps incl. every dev-dependency) and 05-02 (wave 2: ports, contract suite).

- [ ] `crates/anvil-storage/src/contract/{roles,attributes,webhooks,registration}.rs` + extensions of `clients.rs`, `consent.rs`, `audit.rs`, `setup.rs`, `tenants.rs` — 05-02
- [ ] All dev-dependencies (anvilid: wiremock, testcontainers-modules postgres+redis, anvil-storage[postgres-container], tokio test features, tracing-subscriber, opentelemetry_sdk testing; anvil-cache: testcontainers redis, tokio) — 05-01
- [ ] `crates/anvil-cache/src/limiter/contract.rs` + `crates/anvil-cache/tests/limiter_contract.rs` (both backends) — 05-08
- [ ] `crates/anvil-web/tests/{webhook_support,cimd_support}/mod.rs` — 05-14, 05-15
- [ ] `crates/anvilid/tests/{config_phase5,telemetry_redaction,backup,admin_recover,healthcheck,tenant_config,limiter_redis,concurrent_start,webhook_worker}.rs` — 05-05, 05-26, 05-17, 05-20, 05-16, 05-14
- [ ] `tests/load/` k6 scripts + `run-perf.sh` / `run-ha.sh`, `deploy/compose/ha/`, `.github/workflows/load.yml` — 05-03 (gating in 05-26)
- [ ] `deploy/helm/anvilid/ci/{sqlite,postgres}-values.yaml`, `ct.yaml`, `deploy/compose/smoke.sh`, `.github/workflows/deploy.yml` — 05-22
- [ ] `tests/mcp/` mock MCP client + resource server and `tests/e2e/specs/mcp.spec.ts` — 05-25
- [ ] Fuzz targets `registration_parse`, `cimd_parse` (05-09), `tenant_config_parse` (05-20) + ci.yml `fuzz-build` job (05-03)
- [ ] `scripts/check-security-tests.sh` entries for every Phase 5 control incl. escalation, lockout, fresh-admin recovery, CIMD http-in-production and jwks_uri tests — 05-28 (the map's only Phase 5 editor)
- [ ] `scripts/measure-idle.sh` < 100 MB gate — 05-05; container idle VmRSS from host /proc/<pid>/status — 05-26

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Owner authorization to publish v0.4.0 and confirmation that v0.3.0 is tagged first (decision Q9) | all (release) | Publishing is an owner decision; the 04-33 provider checklist is owner-only | 05-29 Task 1 checkpoint: review the 05-28 summary, check `git tag -l v0.3.0`, type "publish" |
| Push authorization for the gate (05-28 Task 2) | all (gate) | Pushing to the public main branch requires the owner's authorization in the executing session | If not authorized, 05-28 returns a checkpoint after Task 1 |
| Perf numbers on a public shared runner | QUAL-05 | Automated and gating in CI, but the environment (shared 4 vCPU) is an owner cost decision (Q2) | Read the load.yml step summary recorded in 05-28; after 3 failed median runs 05-28 returns a checkpoint:decision with the numbers (thresholds never relaxed silently) |

All functional behaviours have automated verification; the rows above are authorization/environment checks.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies (05-29 Task 1 is a checkpoint by design)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (scaffolds created by the first task needing them, listed above)
- [x] No watch-mode flags
- [ ] Feedback latency < 5s (not achievable for Rust incremental builds; target is < 60 s per task command)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
