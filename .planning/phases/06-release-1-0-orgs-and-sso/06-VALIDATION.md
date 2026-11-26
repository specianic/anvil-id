---
phase: 6
slug: release-1-0-orgs-and-sso
status: planned
nyquist_compliant: true
wave_0_complete: false
created: 2026-11-26
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test` (core unit tests; storage contract via `storage_contract_tests!`; HTTP integration in `crates/anvil-web/tests`; binary tests in `crates/anvilid/tests`), proptest, insta, wiremock, testcontainers (Postgres; local PG14 fallback without Docker); Playwright e2e (`tests/e2e`); OpenID conformance (`tests/conformance`); cargo-fuzz (`fuzz/`). New in Phase 6: test-time SAML signer (`crates/anvil-web/tests/saml_support`, bergshamra on aws-lc), local UDP DNS stub (`crates/anvil-web/tests/dns_support`, hickory-proto), `FakeTxt` in `tests/support` (test code only), Node mock SAML IdP (xml-crypto 6.4.0) and mock DNS (node:dgram) in `tests/e2e/lib` |
| **Config file** | `justfile`, `tests/e2e/playwright.config.ts`, `tests/e2e/run.sh`, `scripts/check-security-tests.sh`, `scripts/check-migrations.sh`, `fuzz/Cargo.toml` |
| **Quick run command** | `cargo test -p <crate> --lib <module>` or `cargo test -p anvil-web --test <file>` (the task's `<automated>` command) |
| **Full suite command** | `just ci` (fmt, clippy, deny, deps, migrations-check, test, test-pg, test-redis, release-graph, security-tests, console-check, fuzz-check) + `tests/e2e/run.sh sqlite` / `postgres` + `tests/conformance/run.sh all` |
| **Estimated runtime** | quick: 10-60 s per task command (single test binary, incremental build); full `just ci`: ~15-25 min; e2e per backend: ~15 min |

---

## Sampling Rate

- **After every task commit:** run the task's `<automated>` command (one or a few test binaries; each < 60 s after an incremental build).
- **After every plan wave:** `cargo build --workspace --all-targets --locked && cargo test --workspace --locked` (from wave 3 on, when both
  storage backends are real); `just ci` after waves 3, 5 and 7. Docker-only recipes (test-pg, test-redis, Postgres e2e) run in CI when
  Docker is unavailable locally; Postgres plans verify on a local PG14 cluster (04-05/05-07 precedent).
- **Before `/gsd:verify-work`:** the gate (06-26) — `just ci` green, e2e green on both backends, conformance `all` green with no new
  expected failures, `security_saml` corpus green with the case list in the D4 report, every workflow green on main.
- **Max feedback latency:** 60 seconds per task command (incremental). Wave-level runs are longer by nature and are not per-task feedback.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command |
|---------|------|------|-------------|-----------|-------------------|
| 6-01-01 | 01 | 1 | ORG-03, ORG-04 | auto | `cargo build --workspace --all-targets --locked && cargo deny --locked check && scripts/check-deps.sh && scripts/check-deps.sh --self-test...` |
| 6-01-02 | 01 | 1 | ORG-03, ORG-04 | auto | `cargo test -p anvil-web --test saml_dsig_spike && grep -q "tsp-ltv" docs/ARCHITECTURE.md && ! grep -q "PRIVATE KEY-----" crates/anvil-web...` |
| 6-02-01 | 02 | 1 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `cargo build -p anvil-core --lib && cargo test -p anvil-core --lib model:: && cargo test -p anvil-core --lib error` |
| 6-02-02 | 02 | 1 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `cargo test -p anvil-core --lib model::audit && cargo test -p anvil-core --lib policy::webhook_event && cargo test -p anvil-core --lib pol...` |
| 6-02-03 | 02 | 1 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `cargo build --workspace --all-targets --locked && cargo test -p anvil-core --lib && cargo test -p anvil-mail && cargo test -p anvil-web -...` |
| 6-03-01 | 03 | 1 | ORG-03, ORG-04 | auto | `cd tests/e2e && npm ci && npx tsc --noEmit -p . && npx playwright test specs/mock-saml-idp.spec.ts --project=chromium` |
| 6-03-02 | 03 | 1 | ORG-03, ORG-04 | auto | `cd tests/e2e && npx tsc --noEmit -p . && npx playwright test specs/mock-dns.spec.ts --project=chromium` |
| 6-04-01 | 04 | 2 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `cargo build -p anvil-core -p anvil-storage-sqlite -p anvil-storage-postgres --all-targets && cargo test -p anvil-core --lib ports && carg...` |
| 6-04-02 | 04 | 2 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `cargo build --workspace --all-targets --locked && cargo test -p anvil-web --test shell --test openapi_drift --test admin_connections && c...` |
| 6-04-03 | 04 | 2 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `cargo test -p anvil-storage-sqlite --test contract --no-run && cargo test -p anvil-storage-sqlite --test contract -- tenants outbox logou...` |
| 6-05-01 | 05 | 2 | ORG-02, ORG-03, ORG-04 | auto | `cargo test -p anvil-core --lib -- policy::home_realm policy::domain_verification` |
| 6-05-02 | 05 | 2 | ORG-02, ORG-03, ORG-04 | auto | `cargo test -p anvil-core --lib -- policy::org_claims policy::mfa policy::claims_mapping` |
| 6-05-03 | 05 | 2 | ORG-02, ORG-03, ORG-04 | auto | `cargo test -p anvil-core --lib saml:: && cargo clippy -p anvil-core --all-targets -- -D warnings` |
| 6-06-01 | 06 | 2 | AUTH-08 | auto | `cargo test -p anvil-web --test flow_mfa_policy && cargo test -p anvil-web --test flow_passkey && cargo clippy -p anvil-core --all-targets...` |
| 6-07-01 | 07 | 3 | ORG-02, ORG-03, ORG-04 | auto | `cargo test -p anvil-storage-sqlite --test upgrade && scripts/check-migrations.sh` |
| 6-07-02 | 07 | 3 | ORG-02, ORG-03, ORG-04 | auto | `cargo test -p anvil-storage-sqlite --test contract && cargo test -p anvil-storage-sqlite --test upgrade && ! grep -rn "TRANSITIONAL(06-07...` |
| 6-08-01 | 08 | 3 | ORG-02, ORG-03, ORG-04 | auto | `cargo test -p anvil-storage-postgres --test upgrade && scripts/check-migrations.sh` |
| 6-08-02 | 08 | 3 | ORG-02, ORG-03, ORG-04 | auto | `cargo test -p anvil-storage-postgres --test contract && cargo test -p anvil-storage-postgres --test upgrade && ! grep -rn "TRANSITIONAL(0...` |
| 6-09-01 | 09 | 3 | ORG-03, ORG-04 | auto | `cargo test -p anvil-web --test saml_xml_adapter && cargo clippy -p anvil-web --all-targets -- -D warnings` |
| 6-09-02 | 09 | 3 | ORG-03, ORG-04 | auto | `cargo test -p anvil-web --test security_saml && test ! -f crates/anvil-web/tests/saml_dsig_spike.rs` |
| 6-09-03 | 09 | 3 | ORG-03, ORG-04 | auto | `just fuzz-check && scripts/fuzz.sh list \| grep -q saml_response_parse && grep -q org_domain_parse .github/workflows/fuzz.yml` |
| 6-10-01 | 10 | 3 | ORG-04 | auto | `cargo test -p anvil-core --lib service::domain_check && cargo test -p anvil-web --test dns_txt_adapter && ! grep -rn "TRANSITIONAL(06-10)...` |
| 6-11-01 | 11 | 3 | ADM-02 | auto | `cargo test -p anvil-web --test admin_keys --test openapi_drift && (cd admin-ui && npm run check:api && npm run typecheck)` |
| 6-12-01 | 12 | 4 | ORG-02, ORG-03 | auto | `cargo build -p anvil-core --all-targets && cargo test -p anvil-core --lib && cargo clippy -p anvil-core --all-targets -- -D warnings` |
| 6-12-02 | 12 | 4 | ORG-02, ORG-03 | auto | `cargo build -p anvil-web --all-targets && cargo test -p anvil-web --test openapi_drift && (cd admin-ui && npm run check:api && npm run ty...` |
| 6-12-03 | 12 | 4 | ORG-02, ORG-03 | auto | `cargo test -p anvil-web --test admin_orgs --test security_admin_v10 && cargo clippy -p anvil-web --all-targets -- -D warnings` |
| 6-13-01 | 13 | 4 | ORG-02 | auto | `cargo test -p anvil-core --lib -- oauth::authorize_request service::authorize service::role && cargo build --workspace --all-targets` |
| 6-13-02 | 13 | 4 | ORG-02 | auto | `cargo test -p anvil-web --test org_claims --test discovery --test token --test userinfo --test rbac_claims --test security_introspect_rev...` |
| 6-14-01 | 14 | 4 | ORG-03 | auto | `cargo test -p anvil-core --lib upstream::linking && cargo test -p anvil-web --test upstream_login --test upstream_google --test upstream_...` |
| 6-14-02 | 14 | 4 | ORG-03 | auto | `cargo test -p anvil-web --test enterprise_oidc --test security_linking --test upstream_buttons && cargo clippy -p anvil-core -p anvil-web...` |
| 6-15-01 | 15 | 4 | ORG-02, ORG-03 | auto | `cargo test -p anvil-core --lib -- oauth::registration oauth::cimd service::client && cargo test -p anvil-web --test security_org_scopes -...` |
| 6-15-02 | 15 | 4 | ORG-02, ORG-03 | auto | `cargo test -p anvil-web --test admin_config --test security_admin_config && cargo test -p anvilid --test tenant_config` |
| 6-16-01 | 16 | 4 | ADM-02 | auto | `cd admin-ui && npm run check:api && npm run typecheck && npm run build && grep -q 'keys' src/routeTree.gen.ts` |
| 6-16-02 | 16 | 4 | ADM-02 | auto | `cd tests/e2e && npx tsc --noEmit -p . && ./run.sh sqlite specs/console-keys.spec.ts` |
| 6-17-01 | 17 | 5 | ORG-03, ORG-04, ADM-02 | auto | `cargo test -p anvil-web --test admin_org_sso --test admin_connections && ! grep -rn "TRANSITIONAL(06-17)" crates/` |
| 6-17-02 | 17 | 5 | ORG-03, ORG-04, ADM-02 | auto | `cargo test -p anvil-web --test security_domains --test admin_org_sso` |
| 6-17-03 | 17 | 5 | ORG-03, ORG-04, ADM-02 | auto | `cargo test -p anvil-web --test admin_branding --test theme --test openapi_drift && (cd admin-ui && npm run check:api && npm run typecheck...` |
| 6-18-01 | 18 | 5 | ORG-03 | auto | `cargo test -p anvil-core --lib -- service::saml flow::login && cargo clippy -p anvil-core --all-targets -- -D warnings` |
| 6-18-02 | 18 | 5 | ORG-03 | auto | `cargo test -p anvil-web --test saml_login --test i18n_catalogs --test security_body_limit && cargo clippy -p anvil-web --all-targets -- -...` |
| 6-19-01 | 19 | 5 | ORG-02 | auto | `cargo test -p anvil-core --lib -- service::authorize policy::mfa && ! grep -rn "TRANSITIONAL(06-19)" crates/` |
| 6-19-02 | 19 | 5 | ORG-02 | auto | `cargo test -p anvil-web --test org_switch --test org_claims --test authorize_step_up --test i18n_catalogs --test render && cargo clippy -...` |
| 6-20-01 | 20 | 5 | ORG-02, ORG-04 | auto | `cargo test -p anvil-mail && cargo test -p anvil-web --test org_invitations --test i18n_catalogs --test render && ! grep -rn "TRANSITIONAL...` |
| 6-20-02 | 20 | 5 | ORG-02, ORG-04 | auto | `cargo build -p anvil-core --all-targets && cargo test -p anvilid --test jobs` |
| 6-21-01 | 21 | 5 | ADM-02, ORG-02 | auto | `cd admin-ui && npm run typecheck && npm run build && grep -q organizations src/routeTree.gen.ts` |
| 6-21-02 | 21 | 5 | ADM-02, ORG-02 | auto | `cd tests/e2e && npx tsc --noEmit -p . && ./run.sh sqlite specs/console-orgs.spec.ts` |
| 6-22-01 | 22 | 6 | ORG-04 | auto | `cargo test -p anvil-core --lib -- flow::login service::flow && cargo clippy -p anvil-core --all-targets -- -D warnings` |
| 6-22-02 | 22 | 6 | ORG-04 | auto | `cargo test -p anvil-web --test hrd_login --test security_enumeration --test flow_login --test flow_email_code --test flow_passkey --test ...` |
| 6-23-01 | 23 | 6 | ADM-02, ORG-03, ORG-04 | auto | `cd admin-ui && npm run check:api && npm run typecheck && npm run build && grep -q domains src/routeTree.gen.ts` |
| 6-23-02 | 23 | 6 | ADM-02, ORG-03, ORG-04 | auto | `cd tests/e2e && npx tsc --noEmit -p . && ./run.sh sqlite specs/console-org-sso.spec.ts` |
| 6-24-01 | 24 | 7 | ORG-02, ORG-03, ORG-04 | auto | `cd tests/e2e && npx tsc --noEmit -p . && ./run.sh sqlite specs/org-switch.spec.ts specs/invitations.spec.ts` |
| 6-24-02 | 24 | 7 | ORG-02, ORG-03, ORG-04 | auto | `cd tests/e2e && npx tsc --noEmit -p . && ./run.sh sqlite specs/saml.spec.ts specs/hrd.spec.ts specs/nojs-hrd.spec.ts` |
| 6-25-01 | 25 | 7 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `test -s docs/ORGANIZATIONS.md && test -s docs/SAML.md && grep -q "saml_experimental" docs/SAML.md && grep -q "allow_local_password" docs/...` |
| 6-25-02 | 25 | 7 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `grep -q "organization" docs/ARCHITECTURE.md && grep -q "domain_verification_resolvers" docs/OPERATIONS.md && grep -q "organization.domain...` |
| 6-26-01 | 26 | 8 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `scripts/check-security-tests.sh && scripts/check-security-tests.sh --self-test && scripts/check-migrations.sh && scripts/check-release-gr...` |
| 6-26-02 | 26 | 8 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `test "$(gh run list --branch main --limit 40 --json headSha,conclusion -q "[.[] \| select(.headSha==\"$(git rev-parse HEAD)\")] \| map(.c...` |
| 6-27-01 | 27 | 9 | ORG-02, ORG-03, ORG-04, ADM-02 | checkpoint:human-verify | `manual: Owner's resume signal recorded verbatim in the summary` |
| 6-27-02 | 27 | 9 | ORG-02, ORG-03, ORG-04, ADM-02 | auto | `gh release view v1.0.0-beta.1 --json assets,isPrerelease -q '(.assets \| length == 8) and .isPrerelease' \| grep -qx true` |

Every `auto` task creates the test files it verifies with (test-first where the task is marked `tdd="true"`); the contract tests for
storage are written in 06-04 and turn green in 06-07/06-08. The single checkpoint (6-27-01) is the owner's publish decision.

---

## Phase Requirements -> Test Map

| Req | Behaviour | Tests (owning plan) |
|-----|-----------|---------------------|
| ORG-02 | org CRUD, members, org roles, invitations admin, org-admin principal | `admin_orgs`, `security_admin_v10` (06-12); contract `orgs`, `roles`, `org_invitations` (06-04, green in 06-07/06-08) |
| ORG-02 | `organization` param, org claims in every token surface, refresh re-check, org:admin bounding, opaque/introspection claims | `policy::org_claims` (06-05), `org_claims` (06-13), `security_org_scopes` (06-15) |
| ORG-02 | switcher, switching, org MFA | `org_switch` (06-19), `specs/org-switch.spec.ts` (06-24) |
| ORG-02 | invitation acceptance, single use, enumeration, registration modes | `org_invitations` (06-20), `specs/invitations.spec.ts` (06-24) |
| ORG-03 | D4 spike and corpus | `saml_dsig_spike` (06-01, folded into 06-09), `saml_xml_adapter`, `security_saml` (06-09), fuzz `saml_response_parse`/`saml_metadata_parse` |
| ORG-03 | SAML request/conditions | `saml::request`, `saml::validate` (06-05) |
| ORG-03 | SAML login flow, replay, binding cookie, flag | `saml_login` (06-18), `specs/saml.spec.ts` (06-24) |
| ORG-03 | enterprise OIDC, domain-bound trust, JIT membership | `upstream::linking`, `enterprise_oidc`, `security_linking` (06-14) |
| ORG-03 | org connection admin (OIDC/SAML, metadata import, flag off refusal) | `admin_org_sso` (06-17) |
| ORG-04 | domain rules, record format, routing decision | `policy::home_realm`, `policy::domain_verification` (06-05), fuzz `org_domain_parse` (06-09) |
| ORG-04 | hickory adapter, uniform outcome | `service::domain_check`, `dns_txt_adapter` (06-10) |
| ORG-04 | domain admin, one verified org per domain, routing guards | `security_domains` (06-17); contract `org_domains` |
| ORG-04 | re-check job | `anvilid --test jobs` (06-20) |
| ORG-04 | identifier-first routing, enumeration | `hrd_login`, `security_enumeration` (06-22), `specs/hrd.spec.ts`, `specs/nojs-hrd.spec.ts` (06-24) |
| ADM-02 | keys API | `admin_keys` (06-11) |
| ADM-02 | console: keys, organizations, org SSO tabs, audit actions | `specs/console-keys.spec.ts` (06-16), `specs/console-orgs.spec.ts` (06-21), `specs/console-org-sso.spec.ts` (06-23), `npm run typecheck` (06-02 audit record) |
| migrations | 0.4 -> 1.0 keeps every row, rebuild FK check | `anvil-storage-sqlite --test upgrade` (06-07), `anvil-storage-postgres --test upgrade` (06-08), `scripts/check-migrations.sh` |
| config | YAML excludes org objects | `admin_config`, `anvilid --test tenant_config` (06-15) |
| carry-over | passkey picker narrowed | `flow_mfa_policy` (06-06) |

---

## Wave 0 Requirements

Phase 6 has no separate wave 0: the test scaffolds are created by the foundation and infrastructure plans of waves 1-3.

- [ ] `crates/anvil-storage/src/contract/{orgs,org_invitations,org_domains}.rs` + extensions to roles/connections/grants/mail_settings/branding/clients (06-04)
- [ ] Upgrade fixtures 0.4 -> 1.0 in both `tests/upgrade.rs` (06-07, 06-08)
- [ ] `crates/anvil-web/tests/saml_support/` test-time signer, builder, mutators (06-09)
- [ ] `crates/anvil-web/tests/support`: `FakeTxt` + `TestApp::txt()` (06-04); `admin_support` org helpers and org-admin token minting (06-12); `upstream_flow` org helpers (06-14)
- [ ] `crates/anvil-web/tests/dns_support/` UDP DNS stub (06-10)
- [ ] `tests/e2e/lib/mock-saml-idp.ts`, `tests/e2e/lib/mock-dns.ts` + self-tests, xml-crypto devDependency (06-03); `lib/console-v10.ts` (06-16); `lib/org.ts` (06-24); run.sh env for SAML flag and DNS resolvers (06-23)
- [ ] Fuzz targets `saml_response_parse`, `saml_metadata_parse`, `org_domain_parse` (06-09)
- [ ] `scripts/check-security-tests.sh` entries for every new control (06-26)
- [ ] Framework installs: bergshamra-dsig/-keys/-xml, uppsala, hickory-resolver (+ hickory-proto dev), psl, idna (core), flate2 (06-01); xml-crypto (06-03)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Publishing the prerelease | all | Owner decision (release, chrono deny exception, SAML experimental status) | 06-27 Task 1 checkpoint |
| SAML against real IdPs (Entra ID, Okta, Google Workspace, Keycloak) | ORG-03 | Needs real tenant accounts; required before lifting the experimental flag (Q3), scheduled for Phase 7 | Checklist template in docs/SAML.md (06-25) |
| macOS release binaries with bergshamra on aws-lc | ORG-03 | Cannot build macOS targets locally | release-build workflow at the gate (06-26) |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies (the one checkpoint is the owner's publish decision)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (scaffolds created inside the plans that first need them)
- [x] No watch-mode flags
- [ ] Feedback latency < 60 s per task command (to confirm during execution; incremental builds)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
