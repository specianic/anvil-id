---
phase: 05-release-0-4-operate-it
plan: 28
subsystem: release-gate
tags: [gate, QUAL-01, QUAL-05, ci, release, migrations, load, ha, deploy, fuzz, conformance]
requires:
  - phase: 05-release-0-4-operate-it
    provides: "05-01..05-27 and the gap plans 05-30..05-33"
provides:
  - "QUAL-01 map covers every Phase 5 control: 632 control/test pairs (202 new)"
  - "plaintext-at-rest scan covers the 0.4 secrets (initial and registration access token hashes, sealed webhook secrets) on SQLite and Postgres"
  - "anvilid 0.4.0 on main; SQLite 0007 and Postgres 0006 pinned"
  - "The 14 Phase 5 requirements marked complete with evidence"
  - "HA shared-limit burst measured without TCP connection setup (window 0.111 s instead of 0.56-1.92 s)"
  - "Every workflow green on the release commit f80dcb4 (run ids below)"
affects: [05-29 (release v0.4.0 after owner sign-off; v0.3.0 tag first), Phase 5 verification]
tech-stack:
  added: []
  patterns:
    - "Security map: crates/anvil-cache/src/limiter/contract.rs maps to the limiter_contract binary; generic contract fns (`fn name<...>(`) pass the source check"
key-files:
  created:
    - .planning/phases/05-release-0-4-operate-it/05-28-SUMMARY.md
  modified:
    - scripts/check-security-tests.sh
    - scripts/released-migrations.sha256
    - crates/anvilid/Cargo.toml
    - Cargo.lock
    - crates/anvil-storage-sqlite/tests/plaintext.rs
    - crates/anvil-storage-postgres/tests/plaintext.rs
    - crates/anvil-cache/tests/limiter_contract.rs
    - tests/load/run-ha.sh
    - .planning/REQUIREMENTS.md
    - .planning/STATE.md
key-decisions:
  - "All 14 Phase 5 requirements ticked, as the plan's must-haves say. ORG-05 is ticked for its 0.4 scope (tenant-level roles and permissions in tokens); org-level roles come with organizations in Phase 6, recorded as a scope note in REQUIREMENTS.md"
  - "The Redis breaker test proves 'Redis not touched' by exact retry_after and error counts instead of a 40 ms wall-clock bound, which a scheduler stall broke on CI. The exact checks catch a breaker-bypass mutation"
  - "The HA shared-limit guard (burst window <= 1 s) and its bound stay. The client now opens its connections before the start barrier, because SYN retransmissions through Docker's published ports had stretched the window to ~1.9 s without the server seeing the requests sooner"
  - "Browser-only 0.4 journeys (console pages, MCP authorization, in-flow passkey enrolment) stay in the map's 'not mapped' note: Playwright specs cover them"
requirements-completed: [ORG-01, ORG-05, ADM-05, ADM-06, ADM-07, OIDC-17, AGT-01, AGT-02, AUTH-14, OPS-03, OPS-07, OPS-08, OPS-09, QUAL-05]
duration: ~75min
completed: 2026-11-26
---

# Phase 5 Plan 28: Phase 5 gate (release 0.4) Summary

**The security map now names a registered negative test for every Phase 5 control: 632 pairs, up from 430. The plaintext-at-rest scan also covers the 0.4 secrets on both backends. anvilid is 0.4.0 and the 0.4 migrations are pinned. Two CI-only failures were fixed at their cause: a wall-clock bound in a Redis breaker test, and TCP connection setup inside the HA shared-limit burst window. On the release commit f80dcb4, ci, e2e, conformance, release-build, fuzz, deploy and load (perf and HA) are all green. Token endpoint: 1000 req/s at a median p99 of 4.18 ms. Idle RSS: 53,396 kB. HA: 0 failures through 3 restarts and exactly-once webhooks. Tagging v0.4.0 is 05-29, and it waits for v0.3.0 (04-33).**

## Performance

- **Duration:** ~75 min
- **Started:** 2026-11-26T07:12Z
- **Completed:** 2026-11-26T08:35Z
- **Tasks:** 2
- **Files modified:** 10

## Tasks

| # | Task | Commit |
|---|------|--------|
| 1 | Security map, 0.4 plaintext scan, version 0.4.0, 0.4 migration pins, requirements | `db8a199` |
| 2 | Push and drive every workflow to green (Redis breaker test, HA burst harness) | `794a580`, `f80dcb4` |

## Security map (scripts/check-security-tests.sh)

202 new pairs (632 total). Each pair is a `file::test_fn` that the owning test binary lists under `--list`:

- **DCR:** 404 when disabled, system tenant always disabled (web, admin v04, config document), allow-listed policy needs an IAT, IAT single use (also when metadata is rejected, also under concurrency in the contract), expiry and revocation, hashed at rest and shown once, RAT required and wrong RAT 401, static clients not manageable, update constraints, redirect host allow-list and redirect rules, software_statement, admin scope, scopes and resources from the policy, request shape, jwks_uri / private_key_jwt needs inline jwks, max clients, rate limit. The 18 `security_registration.rs` names are all there.
- **CIMD:** policy and allow-list checked before any fetch, private destinations, no redirects, 5 KiB cap, client_id match, no shared-secret methods, jwks_uri rejected (web and core), http refused in production including loopback (web and core), admin scope, errors not cached, refused documents not stored, disabled policy never fetches, never redirects on failure, fetch budget, and the consent page that names the host. Every `security_cimd.rs` test is mapped.
- **MCP / consent:** a CIMD client gets a token only for its resource. A new resource asks again (web and core), deny does not add the resource, and revocation clears resources.
- **Webhooks:** signature (spec vector, tamper, bad secrets), both secrets during rotation only, SSRF at create and at send, redirects not followed, write-only secret (web and admin v04), sealed at rest (both `plaintext.rs`), no personal data (web and core), failures emit nothing, each delivery claimed once (8-way contract `webhook_claim_concurrent_each_row_once` plus `two_workers_deliver_each_row_exactly_once`), the lease outlives the request timeout, the shutdown waits for an in-flight request, tenant isolation.
- **Attributes / claims:** remote refs refused offline, size and depth caps, linear-time patterns, validated writes, errors do not echo values, cross-tenant, non-editable on the account page. The claim mapping never overrides reserved claims (validation, runtime, service merge).
- **RBAC:** tenant isolation (web and contract), admin scopes bounded by role permissions, non-system roles never grant admin scopes, no escalation beyond the caller's scopes, last administrator (unassign, role delete, user delete, disable), role routes need their scopes.
- **Static clients:** admin scopes refused outside the system tenant (admin API, config apply, the updated `system_clients_need_full_admin`). The system tenant keeps them, and legacy rows stay editable.
- **Limiter:** contract equivalence of the Redis and in-process backends (the generic `contract.rs` tests that run as `in_process::*` and `redis_backend::*`), Redis outage fails closed for auth and the gate (cache crate and binary), explicit local mode, an unreachable Redis fails startup, nodes share one budget, hashed key names, Redis/OTLP URL credentials redacted.
- **Config:** apply never reads server env or files, export holds no secrets or hashes, plans never print inline secrets, an invalid document changes nothing (API and CLI), apply needs admin write, apply cannot lock out system admins, system tenant rules, CLI `--prune` / `--yes`.
- **Operations:** restore refuses a running server (serve.lock), corrupt or foreign files, a newer binary's backup, a wrong KEK and an existing database without `--yes`. Backup never creates a missing source. Admin recover has no HTTP route, refuses unknown, other-tenant and blocked accounts, its URL expires, and it creates a fresh admin only after a lockout. Healthcheck refuses non-loopback hosts without connecting and fails when not ready or draining.
- **Passkeys:** enrolment challenge single use and bound to its flow and step (5 web tests plus core). Second factor (the 8 05-30 names in `flow_mfa_policy.rs` plus core): passkey-only users get the passkey step, the passkey is bound to the step user, the challenge is single use and bound to its flow and step, and a TOTP code at a passkey-only step is invalid input.
- **Other:** config routes 1 MiB and no more, the 0.4 admin routes require scopes and isolate tenants, telemetry carries no personal data, secrets or client IPs.

Script changes: crates/anvil-cache/src/limiter/contract.rs maps to the `limiter_contract` binary of anvil-cache. The source check accepts generic functions (`fn name<F, Fut>(`). The header now describes release 0.4, and the browser note lists the 0.4 Playwright journeys. `--self-test` passes.

## Plaintext-at-rest scan (gate disposition c, entry 7)

Both `tests/plaintext.rs` files now seed the following through the storage traits:
- an initial access token, stored by hash;
- two dynamic clients, one with its registration access token hash set at create and one set by `set_registration_token` (the rotation path);
- a webhook endpoint whose `whsec_` secret is sealed as `seal_webhook_secret` does, then rotated so `previous_secret_enc` is populated too.

The scan asserts that no token marker, `whsec_` string or decoded HMAC key appears in any column. For SQLite it also checks the raw database file and WAL. Each hash column holds exactly the 32-byte digest of its marker, and the endpoint stores both sealed secrets. A mutation that stored the webhook secret unsealed fails the SQLite test. Both pass locally, with Postgres under Docker.

## Local gate

Docker was available. Every `just ci` recipe passed locally, though not as one invocation:
- fmt-check, lint (clippy -D warnings), deny, deps, migrations-check (and --self-test), and test (workspace) passed in the first `just ci` run.
- test-pg failed twice in that setting, in `discovery` and then `security_refresh`. Both failures were "admin connection to the test Postgres failed after retries: Connection refused": the container was up and ready, but Docker Desktop's WSL port forwarding was not. Run on its own with `--no-fail-fast`, the full test-pg (`ANVILID_TEST_DB=postgres cargo test -p anvil-web -p anvilid`) passed, and so did the isolated `discovery` rerun.
- test-redis (25 limiter contract tests against real Redis plus the anvilid Redis tests), release-graph, security-tests (632 pairs), console-check and fuzz-check passed.
- `cargo test -p anvil-storage-{sqlite,postgres} --test plaintext` passed.
- e2e and conformance were not run locally. CI runs them on every push and is authoritative.

## CI

| Commit | What | Result |
|--------|------|--------|
| 40b0298 (before this plan) | ci 45773326080 failed (Redis breaker timing); load 45773326153 failed (HA burst window 1.921 s); deploy, conformance, e2e, release-build green | fixed below |
| db8a199 (Task 1) | ci 45776672296, e2e 45776672317, conformance 45776672720, release-build 45776672659, deploy 45776672523, load 45776672302 (HA window 0.911 s), fuzz 45776727557 (dispatched) | all green |
| **f80dcb4 (release commit)** | see below | all green |

f80dcb4:

| Workflow | Run | Result |
|----------|-----|--------|
| ci (fmt + clippy, tests sqlite, tests postgres incl. test-redis, sqlx offline, deny, dependency rules, release graph, fuzz targets compile, console) | 45779843787 | success |
| e2e (Playwright sqlite + postgres, QUAL-04 sqlite + postgres, image size gate) | 45779843989 | success |
| conformance (Basic, Config, Form Post, RP-Initiated Logout, Back-Channel Logout; expected failures `[]`) | 45779843734 | success |
| release-build | 45779843817 | success |
| fuzz (dispatched) | 45779871971 | success |
| deploy (chart lint, kind install SQLite + Postgres, compose smoke; dispatched, since tests/load is not in its paths) | 45779868198 | success |
| load (perf + HA) | 45779843724 | success |

Conformance totals (db8a199 and f80dcb4): Basic 36 modules / 1910 successes, Config 2 / 35, Form Post 36 / 2066, RP-Initiated Logout 12 / 559, Back-Channel Logout 3 / 90. Every plan had 0 failures and 0 warnings.

## Load numbers (QUAL-05, OPS-03)

Perf job on f80dcb4 (public GitHub 4 vCPU runner shared by k6, Postgres and AnvilID; 1000 req/s target, p99 < 50 ms, median of 3):

| trial | p99 (ms) | throughput (req/s) | failed | dropped | HTTP 429 |
|-------|----------|--------------------|--------|---------|----------|
| 1 (median) | 4.18 | 1000.0 | 0 | 0 | 0 |
| 2 | 4.04 | 1000.0 | 0 | 0 | 0 |
| 3 | 4.27 | 1000.0 | 0 | 0 | 0 |

Idle VmRSS (host /proc, Postgres backend): 53,396 kB (limit 102,400 kB).

The other perf runs today all passed: db8a199 had a median p99 of 2.62 ms and 50,968 kB, and 40b0298 had 2.21 ms and 52,792 kB. The perf gate never missed.

HA job on f80dcb4:
- Concurrent first start: 3 nodes, 1 setup token.
- 36,001 requests at 300 req/s through HAProxy across 3 drained restarts: 0 failed, 0 dropped, 0 HTTP 429, p99 2.56 ms, 3/3 nodes running after.
- Webhooks: 80 users created, 80 deliveries, 80 unique webhook-ids, 0 duplicates.
- Shared limit: 90 requests in 0.111 s across 3 nodes at 10/s (burst 10). Allowed 10 against a bound of 13 (a per-node limiter would allow at least 30), 80 limited, 0 other.

## Requirements evidence

- **ORG-01:** console multi-tenant pages (05-04, 05-24; e2e console specs), `TenantView.issuer` (05-23), path/host tenants (`discovery.rs`, `security_tenant.rs`), RFC 8414/OIDC path insertion (05-32).
- **ORG-05 (0.4 scope, tenant level):** `rbac_claims.rs`, `security_rbac.rs`, `admin_roles.rs`, core `service/role.rs` and `policy/claims_mapping.rs`, contract `roles.rs`. Org-level roles come with ORG-02 in Phase 6.
- **ADM-05:** `webhooks.rs`, `security_webhooks.rs`, `admin_webhooks.rs`, contract `webhooks.rs`, `anvilid/tests/webhook_worker.rs`, and the HA exactly-once check (80/80, 0 duplicates).
- **ADM-06:** `admin_config.rs`, `security_admin_config.rs`, `anvilid/tests/tenant_config.rs` (round trip into a fresh instance, re-apply is a no-op), core `service/config.rs`.
- **ADM-07:** `anvilid/tests/{backup,admin_recover,healthcheck,keys_cli,cli,tenant_config}.rs`.
- **OIDC-17:** `registration_dcr.rs`, `security_registration.rs`, `admin_registration.rs`, core `oauth/registration.rs` and `service/registration.rs`, contract `registration.rs`.
- **AGT-01:** `resource_indicators.rs` (CIMD client token for the MCP server only, RFC 8414 path insertion with MCP fields), e2e MCP spec, docs/MCP.md.
- **AGT-02:** `cimd.rs`, `security_cimd.rs`, core `oauth/cimd.rs`, consent display tests.
- **AUTH-14:** `admin_attributes.rs`, `account_attributes.rs`, `attribute_claims.rs`, `security_attributes.rs`, `adapters/attribute_schema.rs`.
- **OPS-03:** load HA job (above), `anvilid/tests/concurrent_start.rs`, `limiter_redis.rs`, limiter contract against Redis.
- **OPS-07:** `anvilid/tests/backup.rs` (online backup while serving and writing, restore guards), sqlite `backup.rs` unit tests, Postgres guidance in OPERATIONS.md.
- **OPS-08:** `health_metrics.rs`, `anvilid/tests/telemetry_redaction.rs` (stderr JSON log, OTLP bytes, /metrics, audit stdout), `config_phase5.rs`.
- **OPS-09:** deploy workflow (chart lint, kind install SQLite and Postgres, compose smoke), green on db8a199 and f80dcb4.
- **QUAL-05:** load perf job (above): 1000 req/s, median p99 4.18 ms, idle RSS 53,396 kB on the documented 4 vCPU runner.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Wall-clock bound in the Redis breaker test**
- **Found during:** Task 2 (ci 45773326080 on 40b0298, `tests (postgres)` / test-redis)
- **Issue:** `redis_outage_auth_and_gate_fail_closed_breaker_skips_then_recovers` asserted that two breaker-skipped calls take under 40 ms. On the shared runner they took 101 ms. The skipped path has no await point, so the time was a scheduler stall, not a Redis contact. It was the first failure of this test on main.
- **Fix:** The test now proves the skip exactly. Both calls (the Auth check and the brute-force gate) must deny with the rest of the original window (cool-down minus 1 s). A call that reached the paused Redis would re-open the breaker and return the full cool-down. The gate must also record zero `error` counts. A breaker-bypass mutation (Skip turned into Proceed) fails the test (5 s vs 4 s).
- **Files modified:** crates/anvil-cache/tests/limiter_contract.rs (outside the plan's file list)
- **Commit:** `794a580`

**2. [Rule 1 - Bug] TCP connection setup inside the HA shared-limit window**
- **Found during:** Task 2 (load 45773273330 on fd7642d and 45773326153 on 40b0298, both before this plan's push)
- **Issue:** "the burst took 1.88 / 1.92 s (> 1 s): inconclusive", while allowed (15/16) stayed within the bound. The server logs showed request latencies of a few ms but arrivals in two groups 0.8-0.95 s apart: part of the 90 simultaneous new connections through Docker's published ports were retried after a SYN retransmission (~1 s). anvilid's accept path, the harness and the HA compose files were unchanged since the green 74e0dbe runs (0.56 / 0.72 s), and db8a199 passed at 0.911 s.
- **Fix:** Each burst thread opens its HTTP connection before the barrier and sends after it, so W covers only the requests. The 1 s guard, the bound `Q + ceil(Q*W) + 1`, the quota and the run size are unchanged; a W near 2 s would make the bound exceed the per-node floor, so relaxing the guard was not an option. A refused connection still counts as an unexpected status. Against a stub, the shared case passes, and an allow-everything limiter and a closed port are both rejected. f80dcb4: window 0.111 s, allowed 10 (bound 13).
- **Files modified:** tests/load/run-ha.sh (outside the plan's file list)
- **Commit:** `f80dcb4`

### Other

- REQUIREMENTS.md was ticked in the Task 1 commit (`db8a199`), as the plan's file list says, before CI went green. QUAL-05's evidence is the green perf job above.
- Files edited outside the plan's list: STATE.md (Current Position repair, which the orchestrator asked for), plus the two fixes above.
- `just ci` ran as separate recipe invocations, because Docker Desktop's port forwarding refused Postgres connections twice under the full run. Every recipe passed.

## Open items

- **v0.3.0 is not tagged** (`git tag -l` lists v0.1.0 and v0.2.0). 04-33 (manual real-provider checklist, then tag v0.3.0) is still pending with the owner. It blocks 05-29 (v0.4.0), not this gate.
- Gate dispositions (d), moved to Phase 6: role claims for opaque tokens/introspection (entry 20) and resource URI case folding (entry 33).
- The HA shared-limit window now excludes connection setup. If W ever exceeds 1 s again, the server itself is slow, which is worth a look.

## Self-Check: PASSED

Commits 794a580, db8a199 and f80dcb4 exist on main. The modified files are present. Version is 0.4.0, and the pins name 0007_release_0_4.sql and 0006_release_0_4.sql. The map references security_registration, security_cimd and flow_mfa_policy, and both plaintext.rs files seed webhook secrets.
