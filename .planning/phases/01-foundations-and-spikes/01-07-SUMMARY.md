---
phase: 01-foundations-and-spikes
plan: 07
subsystem: infra
tags: [musl, static-binary, aws-lc-rs, mimalloc, rust-embed, sqlx, storage-wiring, spike-b, ci]
requires:
  - phase: 01-03
    provides: SqliteStorage::connect / migrate
  - phase: 01-04
    provides: anvilid serve, anvil_web::router, embedded /assets
  - phase: 01-05
    provides: PostgresStorage::connect / migrate
  - phase: 01-06
    provides: tests/conformance/run.sh (ANVILID_ARGS line)
provides:
  - anvilid storage::open_storage(url) selecting SQLite/Postgres by URL scheme, migrating before serve
  - required --database-url / ANVILID_DATABASE_URL on anvilid serve
  - scripts/build-musl.sh (native-arch Alpine static build, asserts static-pie)
  - scripts/measure-idle.sh (embedded-asset check, size + VmRSS/VmHWM/Pss, markdown + JSON)
  - .github/workflows/release-build.yml (musl amd64 + arm64 on native runners)
affects: [01-08, phase-02]
tech-stack:
  added: []
  patterns:
    - "Only anvilid names concrete storage crates; it holds Arc<dyn Storage> for the server lifetime"
    - "Database URL never logged or echoed in errors; only the backend kind is logged"
    - "Static musl builds run natively per arch in rust:<toolchain>-alpine with RUSTUP_TOOLCHAIN overriding rust-toolchain.toml"
key-files:
  created:
    - crates/anvilid/src/storage.rs
    - crates/anvilid/tests/serve.rs
    - scripts/build-musl.sh
    - scripts/measure-idle.sh
    - .github/workflows/release-build.yml
  modified:
    - crates/anvilid/Cargo.toml
    - crates/anvilid/src/main.rs
    - Cargo.lock
    - tests/conformance/run.sh
key-decisions:
  - "anvilid serve requires --database-url (no implicit default database in M0); unknown schemes fail with 'unsupported database URL scheme' and the URL is never echoed"
  - "Postgres pool size fixed at 10 in the binary for M0 (no config surface yet)"
  - "Local static x86_64 musl binary: 9.44 MiB, 18.3 MB idle RSS. That is larger than the research probe (3.5 MB / 9.1 MB) because sqlx SQLite+Postgres, aws-lc-rs TLS, migrations and the SQLite writer+reader pools are now linked and live. Still well within single-binary goals"
requirements-completed: [FND-04]
duration: 10min
completed: 2026-11-25
---

# Phase 1 Plan 07: Storage wiring and static musl binary (Spike B) Summary

**`anvilid serve --database-url` now opens SQLite or Postgres by URL scheme and runs migrations before it starts serving. A static-pie x86_64 musl binary (aws-lc-rs, mimalloc, sqlx SQLite+Postgres, embedded theme) builds in Alpine at 9.44 MiB and idles at 18.3 MB RSS. CI builds and measures both amd64 and arm64.**

## Performance

- **Duration:** about 10 min
- **Started:** 2026-11-25T01:01:40Z
- **Completed:** 2026-11-25T01:11:30Z
- **Tasks:** 3
- **Files modified:** 9

## Accomplishments

- `storage::open_storage(url)`: `sqlite:` → `SqliteStorage`, `postgres://`/`postgresql://` → `PostgresStorage` (pool 10), anything else → error. Migrations run before the listener binds. Only the backend kind is logged.
- Integration tests in `crates/anvilid/tests/serve.rs` spawn the real binary:
  - A file SQLite database is created and migrated, and a restart on the same file starts cleanly.
  - `sqlite::memory:` serves discovery.
  - `mysql://` is rejected.
  - A missing `--database-url` is rejected.
  - Every wait is time-bounded, so a hung server cannot stall the suite.
- Manual Postgres smoke run against the dev container (in a scratch database, dropped afterwards): the server started, applied 1 migration and answered /healthz. The URL did not appear in the logs.
- The conformance runner now starts anvilid with `--database-url "sqlite::memory:"`.
- Spike B result for local x86_64 is below. `file` reports `static-pie linked, stripped`. `/assets/anvil.css`, served from an empty temp directory, has the same sha256 as the repo file (db8bb6ee…), which proves the asset is embedded.

| target | size | VmRSS | VmHWM | Pss | build time (cold) |
|---|---|---|---|---|---|
| x86_64-unknown-linux-musl | 9,897,392 B (9.44 MiB) | 18,308 kB | 18,308 kB | 18,712 kB | 168 s (2m46s cargo) |
| research probe (for comparison) | 3.5 MB | 9.1 MB | – | – | – |

aws-lc-rs and mimalloc symbols are present in the binary (`strings` shows AWS-LC and mimalloc).

## Task Commits

1. **Task 1 (TDD): storage wiring.** RED `893af7d` (test), GREEN `d573b70` (feat)
2. **Task 2: musl build and measurement scripts.** `d4287a1` (feat)
3. **Task 3: release-build workflow.** `2736228` (feat)

## Files Created/Modified

- `crates/anvilid/src/storage.rs`: backend selection by scheme plus migrate, with unit tests (including a check that the URL never leaks into errors)
- `crates/anvilid/src/main.rs`: required `--database-url` (env `ANVILID_DATABASE_URL`, `hide_env_values`); storage is opened before bind
- `crates/anvilid/tests/serve.rs`: end-to-end tests of the binary
- `crates/anvilid/Cargo.toml`, `Cargo.lock`: path deps anvil-core and the two storage crates, plus dev-dep tempfile. The lock diff covers only the anvilid dependency list; no registry crate versions changed.
- `tests/conformance/run.sh`: only the ANVILID_ARGS line changed
- `scripts/build-musl.sh`, `scripts/measure-idle.sh`: Spike B tooling (invoked by `just musl` / `just measure`)
- `.github/workflows/release-build.yml`: amd64 and arm64 matrix, caching, artifacts, step summary

## Decisions Made

See frontmatter `key-decisions`.

## Deviations from Plan

None. The plan was executed as written. One small hardening inside Task 1: `expect_failure` in the test polls with a deadline instead of blocking on `wait_with_output`. In RED, the old binary ignored the missing URL and ran forever, which hung the test for 60+ s.

## Issues Encountered

- The binary is about 2.8x the research probe in size and 2x in RSS. This is expected now that real storage, TLS and both sqlx drivers are linked. It is recorded for the §2.1 condition 2 evaluation and is not treated as a failure. Things that could shrink it later if needed: `opt-level="z"` and fewer SQLite reader connections when idle.
- shellcheck and actionlint are not installed locally. The scripts were checked with `bash -n` and the workflow with a YAML structural assertion. The real proof is the release-build.yml run on GitHub (plan 08), including the arm64 build, which cannot be done locally.

## Next Phase Readiness

- Plan 08 can push and confirm that release-build.yml, ci.yml and conformance.yml pass on GitHub, including the aarch64 musl artifact and its measurement.
- M1 should pass the held `Arc<dyn Storage>` into anvil-web state. It is currently held with no handler using it, by design.

## Self-Check: PASSED
