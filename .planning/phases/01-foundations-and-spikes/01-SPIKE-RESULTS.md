# Phase 1 (M0) Spike Results

Planning document (not published docs). It records the outcome of spikes A, B and C against the
conditions on the Rust choice in `docs/ARCHITECTURE.md` §2.1, with GitHub Actions as the authoritative
evidence.

Date: 2026-11-25. Toolchain: Rust 1.100.0 (pinned). Commit under test: see the CI evidence table.

## §2.1 conditions at a glance

| §2.1 condition | Spike | Verdict |
|---|---|---|
| 1. OpenID conformance suite runs in CI from M1 onward | C | **Met** (pipeline green in CI at M0; see Spike C) |
| 2. One crypto backend (aws-lc-rs) builds statically for musl on amd64 and arm64 | B | **Met** (both arches built, static, measured in CI) |
| 3. Two sqlx storage implementations stay manageable | A | **Met** (manageable; see duplication cost) |
| 4. SAML experimental until a pure-Rust XML-DSig stack passes an attack corpus | n/a | Not in M0 scope (Phase 6, decision D4) |

**Overall: stack confirmed.** No condition proved unworkable in M0, so the language decision is not
revisited before M1. Watch items are listed per spike.

## CI evidence

Authoritative green runs on commit `64270e5` (plan 08 conformance fix), pushed to `main`:

| Workflow | Jobs | Result | Run |
|---|---|---|---|
| ci.yml | dependency rules, fmt + clippy, cargo deny, sqlx offline metadata, tests (SQLite + Postgres) | success | https://github.com/specianic/anvil-id/actions/runs/45524848960 |
| release-build.yml | musl x86_64 + musl aarch64 (native runners), size/RSS in job summary | success | https://github.com/specianic/anvil-id/actions/runs/45524848917 |
| conformance.yml | OpenID conformance (Config OP), release-v5.3.5 | success | https://github.com/specianic/anvil-id/actions/runs/45524848884 |

Earlier runs on `ce293ab` (end of plan 07): ci success (run 45524048972), release-build success (run
45524049016), conformance failure (run 45524049040, the git sparse-checkout issue fixed in plan 08).

Work went straight to `main` (the user authorized pushing to origin/main for this project), so there is no
`phase-1-foundations` branch or PR. The plan's verify command filtered on that branch; the equivalent evidence
is the three successful runs on `main` above.

## Spike A: two sqlx storage backends (§2.1 condition 3)

Source: 01-03-SUMMARY (SQLite), 01-05-SUMMARY (Postgres).

| Metric | SQLite | Postgres |
|---|---|---|
| `src/` Rust LOC | 373 | 280 |
| Migrations SQL LOC | 23 | 24 |
| `query!` call sites | 6 | 6 |
| Call sites needing type/nullability overrides | 4 of 6 | 0 of 6 |
| Backend-specific conversion code | ~50 lines (ms timestamps, BLOB hash, error map, row mapping) | ~15 lines (bytea hash, error map) |
| Connection setup | 113 lines (WAL, single writer + reader pool) | 58 lines (one PgPool) |
| Backend test glue | 44 lines | 85 lines (testcontainers, fresh DB per test) |
| Wall-clock to port to green | ~4 min | ~2.5 min, green on first run, zero contract changes |

- Shared contract suite (`anvil_storage::contract`, 337 lines) is used unchanged by both backends.
- Contract tests: SQLite 16 test functions (8 contract tests in file and in-memory mode), Postgres 8.
  Both run in `just ci` and in ci.yml (Postgres via testcontainers).
- Concurrency: 32-way concurrent `consume_code` on the same code, 10 rounds: exactly 1 `Consumed`, 31
  `AlreadyConsumed`, zero errors, on both backends. SQLite uses the production single-writer config;
  Postgres uses one pool (40 connections in the test so the race really overlaps in the database).
- Really duplicated per backend: about 150 lines of near-parallel statement and row-mapping code.

**Verdict (condition 3): met.** Each new repository operation costs one SQL statement per dialect plus a
few lines of mapping, and the shared contract macro turns drift into a CI failure. Watch item: cost grows
linearly with repositories (clients, users, sessions, keys in Phase 2+). Every new operation must go into
the shared contract suite.

## Spike B: static musl binary with aws-lc-rs (§2.1 condition 2)

Source: 01-07-SUMMARY (local), release-build.yml (CI). The binary includes aws-lc-rs (rustls), mimalloc,
sqlx SQLite + Postgres, migrations and the embedded theme. Idle = `anvilid serve` with
`sqlite::memory:` after discovery answers. In every run the embedded-asset check (`/assets/anvil.css`
served from an empty working directory, sha256 db8bb6ee...) passed.

| Target | Where | Size | VmRSS | VmHWM | Pss | Linkage | Build time |
|---|---|---|---|---|---|---|---|
| x86_64-unknown-linux-musl | local (WSL2) | 9,897,392 B (9.44 MiB) | 18,308 kB | 18,308 kB | 18,712 kB | static-pie, stripped | 168 s cold |
| x86_64-unknown-linux-musl | CI (ubuntu, run on ce293ab) | 9,897,392 B (9.44 MiB) | 21,508 kB | 21,508 kB | 21,500 kB | static-pie, stripped | cargo 3m27s |
| aarch64-unknown-linux-musl | CI (native arm64 runner, run on ce293ab) | 8,029,632 B (7.66 MiB) | 18,632 kB | 18,632 kB | 18,624 kB | statically linked (non-PIE), stripped | cargo 3m58s |
| x86_64-unknown-linux-musl | CI (run 45524848917 on 64270e5, warm cache) | 9,897,392 B (9.44 MiB) | 21,504 kB | 21,504 kB | 21,496 kB | static-pie, stripped | cargo 1m07s |
| aarch64-unknown-linux-musl | CI (run 45524848917 on 64270e5, warm cache) | 8,029,632 B (7.66 MiB) | 20,688 kB | 20,688 kB | 20,680 kB | statically linked (non-PIE), stripped | cargo 1m19s |

Idle RSS varies by about 2 MB between runs on the same binary (18.6 to 20.7 MB on arm64), so read these
numbers as "about 20 MB" rather than exact values.

For comparison, the research probe (no storage, no TLS) was 3.5 MB / 9.1 MB RSS.

**Verdict (condition 2): met.** aws-lc-rs builds statically for musl on both amd64 and arm64 (native
runners, no cross toolchain), and both binaries serve with embedded assets. Size and idle RSS stay
small for a single-binary IdP. Watch items: the aarch64 output is `statically linked` rather than
`static-pie` (the build script accepts both; PIE on aarch64 musl can be revisited for hardening). If size
matters later: `opt-level="z"` and fewer idle SQLite reader connections.

## Spike C: OpenID conformance pipeline (§2.1 condition 1)

Source: 01-06-SUMMARY (local), conformance.yml (CI).

- `just conformance` (tests/conformance/run.sh) fetches suite release-v5.3.5 (prebuilt images, same tag),
  starts a fresh `anvilid serve --database-url sqlite::memory:` on the host, runs
  `oidcc-config-certification-test-plan` with the suite's own `run-test-plan.py`, enforces the exact
  ratchet in `tests/conformance/expected-failures-m0.json`, and tears down.
- Local: green (exit 0, "All tests ran to completion", every failing condition expected).
- CI: the first two runs on GitHub (faec5c7, ce293ab) failed **before the suite started**: newer git on
  the runner rejects the non-cone pattern `/docker-compose-prebuilt.yml` in `sparse-checkout add`. Plan 08
  replaced the sparse checkout with a blobless `--no-checkout` clone plus a path checkout, which works
  on both git versions. It also moved the suite's mongo data to a named volume, so each run starts
  empty and no root-owned files remain under `./suite`.
- Ratchet (unchanged from 01-06; CI matched the local bootstrap): 7 failures + 1 warning, all caused by
  the http issuer at M0 (5), ES256-only signing algs (1), no userinfo endpoint (warning), and /jwks
  returning 501 (FetchServerKeys stops the module, which counts as INTERRUPTED/complete).

- CI (run 45524848884 on 64270e5): green. "Loaded 8 expected failures", "All tests ran to completion",
  `run-test-plan.py exited with 0`. The CI outcome matched the locally bootstrapped ratchet exactly, so
  `expected-failures-m0.json` did not change. Plain http was enough for M0, so the TLS-listener fallback
  (Open Question 3) was not needed.

**Verdict (condition 1): met.** The conformance suite already runs in CI at M0 on every push to main,
with no secrets, using the same entry point as local runs. Watch item: once /jwks serves keys (Phase 2),
conditions later in the module run for the first time and the ratchet will flag new failures. That is
the intended behaviour.

## Doc follow-ups raised (not silently diverged)

1. **RS256 default vs ES256 advertised.** ARCHITECTURE makes RS256 the default signing algorithm, and
   certification requires it; the M0 discovery document advertises only ES256. Phase 2 must advertise
   (and sign with) RS256. Tracked in the ratchet comment.
2. **http issuer for conformance until Phase 2 TLS.** The M0 conformance job runs over plain http, so the
   five https-related discovery conditions are expected failures. Phase 2 adds an https job
   (rustls listener with a throwaway key) and removes them from the ratchet.
3. **Storage ports location.** Ports live in `anvil_core::ports` and backends depend on anvil-core only.
   ARCHITECTURE §4/§7.1/§7.2 were already updated in plan 01; no open divergence.
4. **Dependency rules scope.** Rules apply to normal + build edges only (dev-dependencies allowed, e.g.
   the contract suite). Already reflected in ARCHITECTURE §4 by plan 01.
5. **Migrations location.** Per-crate `migrations/` directories embedded with `sqlx::migrate!`, matching
   ARCHITECTURE §4 and the migrations section. No divergence.
6. **No implicit default database in M0.** `anvilid serve` requires `--database-url`. The PRD's zero-config
   start (SQLite file by default) is a later-milestone item; this is a deliberate M0 gap, not a divergence
   to fix now.
7. **cargo-deny >= 0.22 required** (0.21 fails on transitive dev-only advisories). Recorded in the dev
   setup; bans were not loosened.
