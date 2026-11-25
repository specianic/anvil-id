---
phase: 01-foundations-and-spikes
plan: 05
subsystem: storage
tags: [sqlx, postgres, testcontainers, storage-contract, concurrency, spike-a]
requires:
  - phase: 01-01
    provides: anvil_core::ports, domain model, crate manifests
  - phase: 01-03
    provides: anvil_storage::contract (storage_contract_tests!), scripts/sqlx.sh, SQLite baseline
provides:
  - anvil_storage_postgres::PostgresStorage (connect(url, max_connections), migrate, impl Storage)
  - crates/anvil-storage-postgres/.sqlx/ offline metadata (6 queries)
  - Postgres 18 testcontainers harness (one container per test binary, fresh database per test)
  - Duplication-cost measurement and verdict on ARCHITECTURE.md §2.1 condition 3
affects: [01-07]
tech-stack:
  added: [postgres:18-alpine (test/dev container)]
  patterns:
    - "Postgres: native uuid/bytea/timestamptz/jsonb; query! with zero type/nullability overrides"
    - "Shared per-binary OnceCell container; CREATE DATABASE test_<uuid> per test; no pool shared across test runtimes"
    - "sqlx 0.9 dynamic SQL must be wrapped in sqlx::AssertSqlSafe"
key-files:
  created:
    - crates/anvil-storage-postgres/sqlx.toml
    - crates/anvil-storage-postgres/build.rs
    - crates/anvil-storage-postgres/migrations/0001_init.sql
    - crates/anvil-storage-postgres/src/convert.rs
    - crates/anvil-storage-postgres/src/tenants.rs
    - crates/anvil-storage-postgres/src/grants.rs
    - crates/anvil-storage-postgres/tests/contract.rs
    - crates/anvil-storage-postgres/tests/support/mod.rs
    - crates/anvil-storage-postgres/.sqlx/ (6 query files)
  modified:
    - crates/anvil-storage-postgres/src/lib.rs
key-decisions:
  - "Two sqlx backends are manageable (ARCHITECTURE.md §2.1 condition 3 met): the Postgres port took ~2.5 min to reach green, with no contract changes and no overrides"
  - "A single PgPool serves all repositories; no reader/writer split on Postgres"
  - "The shared OnceCell container works across per-test tokio runtimes; no fallback to one container per test was needed"
requirements-completed: [FND-03]
duration: 4min
completed: 2026-11-25
---

# Phase 1 Plan 05: Postgres Storage Backend and Duplication Cost Summary

**The Postgres 18 backend (sqlx, native uuid/bytea/timestamptz/jsonb) passes the same eight contract tests as SQLite, including the 32-way concurrent consume (1 Consumed, 31 AlreadyConsumed, zero errors, 10 rounds, pool of 40). Offline `.sqlx/` metadata is committed for both crates. Maintaining two backends costs about 280 lines of Rust per backend, with the SQL nearly identical, so ARCHITECTURE.md §2.1 condition 3 is met.**

## Performance

- **Duration:** ~3.5 min wall-clock (epoch 1795568217 to 1795568429)
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files:** 10 created/modified (plus 6 `.sqlx` query files)

## Accomplishments

- `PostgresStorage::connect(url, max_connections)` / `migrate()` match the plan-07 contract exactly; `impl Storage`.
- `consume_code` is one `UPDATE ... WHERE tenant_id = $1 AND code_hash = $2 AND consumed_at IS NULL AND expires_at > $3 RETURNING ...`. On zero rows, a follow-up SELECT only classifies the loser (AlreadyConsumed{family_id} or NotFound). No check-then-update.
- `map_err`: SQLSTATE 23505 (through `is_unique_violation`) maps to Conflict, everything else to Backend. A bytea hash with the wrong length maps to Corrupt (unit tested).
- The testcontainers harness starts one `postgres:18-alpine` (`max_connections=500`) per test binary and creates a fresh `test_<uuid>` database per test through a short-lived admin connection to `postgres`. Each test opens a pool of 40 connections (> 32 consumers, so the concurrency test really overlaps in the DB). The contract suite passed 6 consecutive runs live and 1 offline.
- `scripts/sqlx.sh prepare|check` now processes both crates. The SQLite `.sqlx/` was unchanged by prepare.
- Offline proof: `SQLX_OFFLINE=true` with no database URL. Both contract suites (SQLite 16, Postgres 8) and workspace clippy `-D warnings` are green.

## Duplication cost

| Metric | SQLite (01-03) | Postgres (this plan) |
|---|---|---|
| `src/` Rust LOC (total) | 373 (lib 113, grants 119, tenants 79, convert 62) | 280 (lib 58, grants 109, tenants 67, convert 46) |
| of which unit tests in convert.rs | 25 | 22 |
| `migrations/` SQL LOC | 23 | 24 |
| SQL embedded in `query!` strings | ~45 lines | ~20 lines (no `AS "x!: T"` override suffixes) |
| `query!` call sites / `query_as!` | 6 / 0 | 6 / 0 |
| Call sites needing type/nullability overrides | 4 of 6 (every selected column) | **0 of 6** (uuid, bytea, timestamptz, nullability all inferred) |
| Backend-specific conversion code | ~37 lines (ms<->OffsetDateTime, BLOB->CodeHash, error map) + 13-line `to_tenant` | ~15 lines (bytea->CodeHash, error map); timestamps and uuids are native |
| Connection setup (lib.rs) | 113 (WAL, single writer + reader pool, in-memory special case) | 58 (one PgPool) |
| Backend test glue | 44 (contract 11 + support 33) | 85 (contract 7 + support 78; container + per-test DB) |
| Shared contract suite | 337 lines, used unchanged by both | |
| Wall-clock to port | ~4 min SQLite (incl. sqlx-cli upgrade) | ~2.5 min from Task 1 start to 8/8 green (incl. Postgres image pull); green on first run |

What is really duplicated: the statement shapes (INSERT, the atomic UPDATE ... RETURNING, the classify SELECT, two tenant SELECTs) and the row-to-domain mapping in grants.rs/tenants.rs, about 150 lines of near-parallel Rust per backend. The differences are confined to placeholders (`?N` vs `$N`), SQLite's type overrides and ms timestamps, and connection topology. Neither backend needed a contract change.

**Verdict on ARCHITECTURE.md §2.1 condition 3: manageable.** Each new repository operation costs one SQL statement per dialect plus a few lines of mapping, and the shared contract suite catches divergence. Postgres is the cheaper backend: native types remove all overrides and most conversion code. SQLite carries the fixed cost (type overrides, ms conversion, single-writer topology). The risk to watch is that this grows linearly with the number of repositories (phase 2+ adds clients, users, sessions, keys). Keep every operation under the shared contract macro so drift fails CI rather than review.

## Task Commits

1. **Task 1: Postgres backend + contract tests** (TDD): `c97817a` (test, RED: unresolved `PostgresStorage`), `b5956e2` (feat, GREEN: 8/8)
2. **Task 2: Offline metadata + duplication cost**: `87b2b2a` (chore)

## Decisions Made

- One `PgPool` for all repositories. Postgres row locks plus READ COMMITTED re-evaluation decide the race, so no writer serialization is needed.
- The `tenant.settings jsonb NOT NULL DEFAULT '{}'` column exists in the schema but is not yet in the domain model (no `Tenant.settings` field). It is left at its default until a milestone needs it.
- The shared `tokio::sync::OnceCell` container works across per-test runtimes, because the factory keeps no pools across tests. The fallback (one container per test) was not needed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] sqlx 0.9 rejects dynamic SQL strings**
- **Found during:** Task 1 (RED compile)
- **Issue:** `sqlx::query(&format!("CREATE DATABASE {db}"))` fails to compile ("dynamic SQL strings should be audited for possible injections").
- **Fix:** wrapped it in `sqlx::AssertSqlSafe(...)`, with a comment that `db` consists only of a UUID's hex digits. This is test code only.
- **Files modified:** crates/anvil-storage-postgres/tests/support/mod.rs
- **Commit:** c97817a

## Issues Encountered / Deferred

- Pre-existing (plan 01, out of scope): `thiserror` is an unused normal dependency of anvil-storage-postgres, the same as for SQLite. Removing it would change Cargo.lock, which plan 01 owns.
- Leftover testcontainers containers were not observed after the runs (`docker ps -a --filter label=org.testcontainers=true` was empty). The `just clean-test-containers` helper from the research is therefore optional.

## Next Phase Readiness

- Plan 07 can call `PostgresStorage::connect(url, n).await?.migrate().await?`.
- FND-03 is complete: the shared contract suite passes on SQLite and Postgres.

## Self-Check: PASSED
