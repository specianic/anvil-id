---
phase: 05-release-0-4-operate-it
plan: 26
subsystem: load-testing, ha, observability, ci
tags: [k6, haproxy, ha, perf, qual-05, ops-03, ops-08, telemetry, redaction, webhooks, rate-limit, valkey]

requires:
  - phase: 05-03
    provides: k6/HAProxy harness, dispatch-only load.yml
  - phase: 05-05
    provides: drain + readiness, JSON logs, /metrics on the main port, OTLP exporter
  - phase: 05-14
    provides: webhook delivery worker (webhook-id, lease 45 s)
  - phase: 05-16
    provides: Redis limiter selection, concurrent first start
  - phase: 05-18
    provides: token endpoint performance work
  - phase: 05-23
    provides: webhook admin API, DCR/CIMD tenant settings
provides:
  - "crates/anvilid/tests/telemetry_redaction.rs: logs/spans/metrics redaction proof against the real binary"
  - "load.yml gating: perf and ha jobs on push to main (server/load/HA paths), nightly 03:17 UTC, dispatch"
  - "run-perf.sh idle gate: host VmRSS of the container process after 30 s idle (< 102400 kB); HTTP 429 threshold"
  - "run-ha.sh: concurrent first start, restarts under load with user creations, exactly-once webhooks, shared GCRA bound"
  - "tests/load/webhook-sink.mjs: counting sink (webhook-id), /stats"
affects: [05-27, 05-28]

tech-stack:
  added: ["node:24-alpine (sink image, pinned by digest)"]
  patterns:
    - "Telemetry redaction is tested end to end on the shipped binary: stderr JSON log, OTLP protobuf bytes, /metrics text, audit stdout"
    - "Exactly-once is judged by the receiver: deliveries == unique webhook-ids == distinct user ids == creations, after a grace period longer than the delivery lease"

key-files:
  created:
    - crates/anvilid/tests/telemetry_redaction.rs
    - tests/load/webhook-sink.mjs
  modified:
    - tests/load/token.js
    - tests/load/ha.js
    - tests/load/lib.sh
    - tests/load/run-perf.sh
    - tests/load/run-ha.sh
    - tests/load/README.md
    - deploy/compose/ha/compose.yml
    - .github/workflows/load.yml

key-decisions:
  - "Redaction test drives the real `anvilid serve` process (not an in-process router with InMemorySpanExporter): it covers the shipped subscriber, the audit stdout layer, the OTLP exporter and the Prometheus recorder exactly as operators run them"
  - "Idle memory is sampled 30 s after readiness and before setup (the plan's 'after startup'); setup's Argon2 hashing is not idle"
  - "Shared-limit bound: allowed <= Q + ceil(Q x W) + 1 for rate = burst = Q, W <= 1 s (GCRA contract from 05-08); a per-node limiter would allow >= 3 x min(Q, per-node requests)"
  - "Exactly-once judged after a 50 s grace period (> 45 s webhook lease), so a late duplicate from an expired lease would be caught"
  - "HA stack sets ANVILID_BREACH_CHECK=off (hermetic: no internet lookups for test-user passwords) and ANVILID_OUTBOUND_ALLOW_CIDRS to the compose subnet; the sink sits at 172.30.75.200 outside the dynamic ip_range"
  - "Perf median trial must also reach RATE x 60 measured requests (minus 1 for a scheduler boundary), in addition to the k6 thresholds"

requirements-completed: [OPS-03, OPS-08, QUAL-05]

duration: ~75min
completed: 2026-11-26
---

# Phase 5 Plan 26: HA and performance gates, telemetry redaction Summary

**load.yml now gates every relevant push to main, every night and every dispatch. The perf job checks the PRD token target over a median of 3 trials, 0 x 429, and idle VmRSS read from host procfs. The HA job checks concurrent first start, three drained restarts under 300 req/s, exactly-once webhook delivery and a shared Valkey limit. A new binary-level test shows that no email, password, secret, code, token, login_hint, state or client IP reaches logs, exported spans or metrics. The first CI run passed every target without server changes.**

## CI results (public 4-vCPU `ubuntu-24.04` runner)

Run 45764051728 (push of 74e0dbe), both jobs green:

| trial | p99 (ms) | throughput (req/s) | failed | dropped | HTTP 429 |
|---|---|---|---|---|---|
| 1 (median) | 2.27 | 1000.0 | 0 | 0 | 0 |
| 2 | 2.27 | 1000.0 | 0 | 0 | 0 |
| 3 | 2.25 | 1000.0 | 0 | 0 | 0 |

- Idle VmRSS (host `/proc/<pid>/status`, Postgres backend, 30 s idle before setup): **51,164 kB** (limit 102,400).
- HA: 36,001 requests at 300 req/s through HAProxy during 3 restarts. Failed rate 0, dropped 0, 429 0, p99 3.80 ms, 3/3 nodes running afterwards.
  - Each node logged its drain. HAProxy marked it DOWN on the 503, then UP after the restart.
  - All three nodes selected `backend: redis`.
- Concurrent first start: one distinct setup token, so exactly one installer. 3/3 ready on their own ports.
- Webhooks: 80 users created during the restarts, all 201. 80 deliveries, 80 unique webhook-ids, 80 distinct user ids, 0 duplicates, 0 malformed (after the 50 s grace).
- Shared limit: 90 requests (30 per node) in 0.557 s at 10/s with burst 10.
  - Allowed 12 (shared bound 17; a per-node limiter would allow at least 30). Limited 78, other 0.
  - Allowed per node port: 8081 = 2, 8082 = 9, 8083 = 1.

Run 45765868449 (`workflow_dispatch`, which=both, same commit), both jobs green:

- Perf trials, p99: 12.14, 9.11 and 9.45 ms. The median trial is 9.45 ms.
- Throughput 1000.0 req/s, with 0 failed, 0 dropped and 0 x 429 in every trial.
- Idle VmRSS: 52,932 kB.
- HA: 36,001 requests, failed 0, p99 3.62 ms, 3/3 nodes running.
- Webhooks: 80 users, 80 deliveries, 80 unique ids, 0 duplicates.
- Shared limit: allowed 13 of 90 in 0.718 s (bound 19; a per-node limiter would allow at least 30).

The p99 varies between runs on the shared runner (2.3 ms vs 9.5 ms). Both runs are far below the
50 ms target, so no threshold question arises for the owner.

## Telemetry redaction (OPS-08)

`crates/anvilid/tests/telemetry_redaction.rs` starts a real `anvilid serve` with this configuration:

- SQLite, loopback public URL;
- JSON logs with our crates at `debug`;
- `ANVILID_OTEL_ENDPOINT` set to a wiremock collector;
- `/metrics` on the main port;
- trusted proxy 127.0.0.1, with `X-Forwarded-For: 203.0.113.77` sent on every request.

The test drives these flows:

- setup (admin email and password);
- a system admin token;
- webhook endpoint create;
- user create, which triggers a delivery to a loopback sink;
- a confidential client;
- `/authorize?login_hint=…`, then a wrong-password login, the correct login and consent;
- code exchange (PKCE), refresh and userinfo;
- open DCR registration;
- a CIMD fetch through `/authorize`.

**Sentinels searched for:**
- user and admin emails, including the URL-encoded form;
- the correct, wrong and admin passwords;
- state, nonce, the CIMD state and the PKCE verifier;
- the literal `login_hint=`;
- the management, client and webhook secrets;
- the authorization code;
- the access, refresh and id tokens, plus the refreshed and rotated ones;
- the DCR `client_secret` and `registration_access_token`.

**Where they are checked:**
- None may appear in the stderr log, in the OTLP protobuf bytes or in `/metrics`.
- The IP may appear in none of those three either.
- Audit stdout must carry no sentinel. It must contain the IP: that shows the trusted-proxy path worked, so the IP checks are not vacuous.

**Non-vacuity checks:** spans contain `http.request` and `/token`, the log has `anvil_web::access` lines, and the metrics contain `anvil_http_requests_total` and `anvil_tokens_issued_total`.

**Mutation check (local, not committed):** adding the setup token as a sentinel makes the test fail with "in the log" and "in the audit stream". The setup token is printed by design.

A one-off local run with `RUST_LOG=trace` for every crate also found no leak. No leak was found, so no emitting site needed a fix.

## Task Commits

1. **Task 1: telemetry redaction test:** `b44ca34` (test)
2. **Task 2: gating perf + HA workflow, shared-limit and exactly-once checks:** `74e0dbe` (feat)

## Verification

- `cargo test -p anvilid --test telemetry_redaction`: 1 passed (about 3 s).
- `cargo clippy -p anvilid --test telemetry_redaction -- -D warnings`: clean. `rustfmt --edition 2024` was run on the file.
- The plan's Task 2 verify passes: `bash -n` on the 3 scripts, `node --check` on the sink, and a YAML check that load.yml has both `schedule` and `push`. k6 is not installed locally, so `k6 inspect` was skipped; CI ran both scripts.
- Sink smoke test, run locally on a scratch port: it counts duplicates and malformed deliveries correctly.
- CI: runs 45764051728 (push) and 45765868449 (dispatch) are both green (numbers above).

## Deviations from Plan

### Auto-fixed / adjusted

**1. [Rule 3 - Approach] Redaction test against the real binary, not an in-process router**
- The plan suggested `anvil_web::router` with a capturing fmt layer, InMemorySpanExporter and a local recorder. anvilid has no library target, so its subscriber, audit layer and exporter setup cannot be imported. Rebuilding them in the test would test a copy.
- The test runs the shipped binary, as `serve.rs` already does for OTLP, and searches raw OTLP protobuf bytes. Protobuf strings are verbatim UTF-8.

**2. [Rule 2 - Correctness] Setup token counted, not `Setup URL:` lines**
- With JSON logs the installer prints the URL on both stderr and stdout. run-ha.sh counts distinct setup tokens across the node logs, and the count must be 1.

**3. [Rule 2] Late-duplicate grace and explicit 201 check for user creations**
- After all deliveries arrive, the script waits 50 s, longer than the 45 s lease, before judging exactly-once. Every user creation through HAProxy during the restarts must answer 201. The plan's "0 failed requests" applies to the admin API path too.

**4. HA compose additions**
- Node ports 8081-8083, a sink service, `ANVILID_OUTBOUND_ALLOW_CIDRS` and `ANVILID_BREACH_CHECK=off`.
- The network's dynamic `ip_range` is the lower half of the subnet, so the sink's fixed address cannot collide with a node.
- Host ports are bound to loopback.

**5. Perf idle sample timing**
- The sample is taken 30 s after readiness and before setup, as the plan says ("sampled after 30 s idle following startup"). The old `docker stats` reading and the optional musl `measure-idle.sh` call were removed, so there is one idle measurement.

### Forced extras
- None. Only files in `files_modified` changed.

## Not run locally

- Docker (exit 126 here), k6 and shellcheck. Both load jobs ran in CI instead (run ids above).

## Push authorization

- The task prompt for this session allowed pushing `main` and dispatching load.yml. The push of 74e0dbe also carried the wave-7 sibling commits that were already on local main (05-24, 05-25).

## Self-Check: PASSED

- FOUND: crates/anvilid/tests/telemetry_redaction.rs, tests/load/webhook-sink.mjs, tests/load/run-ha.sh, tests/load/run-perf.sh, .github/workflows/load.yml, deploy/compose/ha/compose.yml
- FOUND: commits b44ca34, 74e0dbe (both on origin/main)
