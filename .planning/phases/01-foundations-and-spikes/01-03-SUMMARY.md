---
phase: 01-foundations-and-spikes
plan: 03
subsystem: storage
tags: [sqlx, sqlite, storage-contract, concurrency, spike-a]
requires:
  - phase: 01-01
    provides: anvil_core::ports (Storage, TenantRepo, GrantRepo), domain model, crate manifests
provides:
  - anvil_storage::contract (TestStorage, eight contract fns, storage_contract_tests! macro)
  - anvil_storage_sqlite::SqliteStorage (connect, migrate, impl Storage)
  - scripts/sqlx.sh (db-up, prepare, check; per-crate .sqlx/)
  - crates/anvil-storage-sqlite/.sqlx/ offline metadata
affects: [01-05, 01-07]
tech-stack:
  added: [sqlx-cli 0.9.1 (local tool)]
  patterns:
    - "Contract suite as a macro; backends instantiate it as a dev-dependency"
    - "SQLite: single writer connection + read-only reader pool; in-memory = one pinned connection"
    - "Atomic consume via UPDATE ... RETURNING, follow-up read only classifies the loser"
    - "Per-crate sqlx.toml database-url-var + per-crate .sqlx/"
key-files:
  created:
    - crates/anvil-storage/src/contract/mod.rs
    - crates/anvil-storage-sqlite/sqlx.toml
    - crates/anvil-storage-sqlite/build.rs
    - crates/anvil-storage-sqlite/migrations/0001_init.sql
    - crates/anvil-storage-sqlite/src/convert.rs
    - crates/anvil-storage-sqlite/src/tenants.rs
    - crates/anvil-storage-sqlite/src/grants.rs
    - crates/anvil-storage-sqlite/tests/contract.rs
    - crates/anvil-storage-sqlite/tests/support/mod.rs
    - crates/anvil-storage-sqlite/.sqlx/ (6 query files)
    - scripts/sqlx.sh
  modified:
    - crates/anvil-storage/src/lib.rs
    - crates/anvil-storage-sqlite/src/lib.rs
key-decisions:
  - "SQLite contract passes with the production single-writer configuration; no multi-connection writer"
  - "Unique and primary-key violations both map to StorageError::Conflict via sqlx is_unique_violation"
  - "Dev Postgres container port is published on 127.0.0.1 only"
requirements-completed: []  # FND-03 SQLite half; completes with plan 05 (Postgres)
duration: 4min
completed: 2026-11-25
---

# Phase 1 Plan 03: Storage Contract Suite and SQLite Backend Summary

**The shared storage contract suite lives in anvil-storage (eight tests, one macro). A SQLite backend with a single WAL writer passes all 16 instantiations, including 32-way concurrent consume (1 winner, 31 AlreadyConsumed, 10 rounds) and the tenant-isolation negative test. All six queries are compile-time checked, and the offline `.sqlx/` metadata is committed.**

## Performance

- **Duration:** ~4 min wall-clock (epoch timestamps, plan start to final task commit)
- **Completed:** 2026-11-25
- **Tasks:** 3
- **Files:** 13 created/modified (plus 6 `.sqlx` query files)

## Accomplishments

- `anvil_storage::contract` (feature `contract` only) contains `TestStorage`, the helpers, and eight contract fns: tenant_create_and_get, tenant_slug_conflict, consume_code_once, consume_code_expired (including the strict `expires_at == now` edge), consume_code_unknown, consume_code_wrong_tenant, create_code_duplicate_conflict, consume_code_concurrent_single_winner. `storage_contract_tests!` expands all eight from a single list. tokio is absent from anvil-storage's default normal dependency graph.
- `SqliteStorage::connect/migrate` follows the plan-07 contract. File URLs get WAL, synchronous=NORMAL, busy_timeout 5s and foreign_keys, with one writer connection and an 8-connection read-only reader pool. `sqlite::memory:` (also `:memory:` and `sqlite://:memory:`) gets one pinned connection that serves as both writer and reader.
- `consume_code` runs a single `UPDATE ... WHERE consumed_at IS NULL AND expires_at > ?3 RETURNING ...` on the writer. A follow-up SELECT only classifies the loser (AlreadyConsumed or NotFound).
- `scripts/sqlx.sh` runs prepare and check per crate and skips crates without a `sqlx.toml`, so the Postgres crate is picked up automatically once plan 05 adds one. It also guards that sqlx-cli is 0.9.x. `check` was shown to fail when a `.sqlx` file is missing.
- The crate builds and tests offline (`SQLX_OFFLINE=true`, no database URL set).

## Duplication-cost baseline (for plan 05)

| Metric | SQLite |
|---|---|
| `src/` Rust LOC (total) | 373 (lib 113, grants 119, tenants 79, convert 62 incl. 25 lines of unit tests) |
| `migrations/` SQL LOC | 23 (1 file) |
| SQL embedded in Rust (in query! strings) | ~45 lines |
| `query!` call sites | 6 (`query_as!`: 0) |
| Call sites needing overrides | 4 of 6 (every query that returns columns; overrides on every selected column). The 2 INSERTs need none |
| Conversion code | ~37 lines in convert.rs (ms<->OffsetDateTime, BLOB->CodeHash, error mapping) + 13-line `to_tenant` helper. Uuid<->BLOB is handled by sqlx via `AS "x!: uuid::Uuid"` overrides, so no hand-written code |
| Backend test glue | 44 lines (tests/contract.rs 11 + tests/support/mod.rs 33) vs 337 lines of shared contract suite |
| Wall-clock on SQLite backend | ~4 min, including the sqlx-cli 0.9.1 upgrade; tests passed on the first run with live checking |

## Task Commits

1. **Task 1: Shared contract suite in anvil-storage**: `fd893ec` (feat)
2. **Task 2: SQLite backend + contract tests** (TDD): `f362b68` (test, RED: unresolved `SqliteStorage`), `1cde66f` (feat, GREEN: 16/16)
3. **Task 3: Offline metadata and scripts/sqlx.sh**: `ef48333` (chore)

## Decisions Made

- The single-writer configuration is enough for the exactly-one-winner property. Concurrent consumers queue on the 1-connection writer pool, and no SQLITE_BUSY errors surfaced in five repeated runs.
- SQLite reports unique and primary-key violations through `is_unique_violation()`, so the duplicate code_hash (PK) and duplicate slug (UNIQUE) cases both map to `Conflict`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] Added a length CHECK on `authorization_code.token_family_id`**
- **Issue:** the research schema checks the lengths of `id` and `code_hash` but not of the nullable UUID column.
- **Fix:** `CHECK (token_family_id IS NULL OR length(token_family_id) = 16)`.
- **Commit:** 1cde66f

**2. [Rule 2 - Security] Dev Postgres published on 127.0.0.1 only**
- **Issue:** the plan's `-p 55432:5432` would expose a container with a known password on all interfaces.
- **Fix:** `-p 127.0.0.1:55432:5432`.
- **Commit:** ef48333

**3. [Rule 1 - Bug] Wrong expected value in a convert.rs unit test**: corrected the hardcoded ms literal before commit. The rustfmt pass over contract/mod.rs is included in 1cde66f.

## Issues Encountered / Deferred

- Pre-existing manifest warnings (owned by plan 01, out of scope): anvil-storage's default build reports unused `anvil-core`, and `async-trait` and `thiserror` are unused in anvil-storage and anvil-storage-sqlite respectively. These are cargo manifest lints, not `-D warnings` failures. Removing the deps would change Cargo.lock, which plan 01 owns.
- The test binary path appears under `target/debug/build/...`, presumably because of the toolchain's build-dir layout. Harmless.

## Next Phase Readiness

- Plan 05 can copy the structure: add `crates/anvil-storage-postgres/sqlx.toml` (`ANVIL_PG_DATABASE_URL`) and `scripts/sqlx.sh prepare` picks it up automatically, starting the dev Postgres first.
- Plan 07 can call `SqliteStorage::connect(url).await?.migrate().await?`.

## Self-Check: PASSED
