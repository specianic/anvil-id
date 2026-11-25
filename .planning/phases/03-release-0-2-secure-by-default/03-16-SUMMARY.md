---
phase: 03-release-0-2-secure-by-default
plan: 16
subsystem: storage-migrations
tags: [migrations, sqlx, upgrade, ops, ci, lint]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: "0.2 migrations (03-05 SQLite 0003/0004, 03-06 Postgres 0003) with -- anvil:non-destructive-rebuild annotations"
provides:
  - "MigrateOptions / MigrateError / PendingMigration and migrate_with on both backends (destructive guard)"
  - "anvilid --allow-destructive-migrations / ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS"
  - "0.1 -> 0.2 upgrade tests and the contract suite on upgraded databases (both backends)"
  - "scripts/check-migrations.sh + scripts/released-migrations.sha256 (CI lint job)"
affects: [03-24, 03-29]
tech-stack:
  added: []
  patterns:
    - "Destructive migrations are recognised by file name only: NNNN_destructive_*.sql (sqlx description starts with 'destructive ')"
    - "open_storage(url, Migrations::{Skip, Run { allow_destructive }}) is the single migration entry point of the binary"
key-files:
  created:
    - crates/anvil-storage-sqlite/src/migrate.rs
    - crates/anvil-storage-postgres/src/migrate.rs
    - crates/anvil-storage-{sqlite,postgres}/tests/fixtures/destructive/{0001_init,0002_destructive_drop_x}.sql
    - crates/anvil-storage-{sqlite,postgres}/tests/upgrade.rs
    - crates/anvil-storage-{sqlite,postgres}/tests/fixtures/v0_1.sql
    - scripts/check-migrations.sh
    - scripts/released-migrations.sha256
  modified:
    - crates/anvil-storage-{sqlite,postgres}/src/lib.rs
    - crates/anvilid/src/{storage,config,main,startup}.rs
    - crates/anvilid/tests/cli.rs
    - .github/workflows/ci.yml
    - justfile
key-decisions:
  - "sqlx turns the file name after the version into the description with underscores as spaces, so 0005_destructive_drop_x.sql is (5, \"destructive drop x\"); the guard matches description == \"destructive\" or a \"destructive \" prefix"
  - "The guard computes the pending set without creating anything (no _sqlx_migrations table on a fresh DB) and refuses before any migration runs, so a refusal leaves the database untouched"
  - "Postgres: check and run share one pool connection that holds sqlx's own pg_advisory_lock (key from the database name, the same lock sqlx migrate uses); sqlx's nested lock/unlock in run is re-entrant. On error or failed unlock the connection is closed rather than returned to the pool"
  - "SQLite: sqlx's lock is a no-op; check and run use the single writer connection. Across processes the guard still cannot be bypassed because the pending set only shrinks and the run uses the same embedded list it was checked against"
  - "migrate() == migrate_with(MigrateOptions::default()) and refuses destructive migrations; backends return a typed MigrateError::Destructive and anvilid words the operator message"
  - "The non-destructive-rebuild annotation is file-level (03-05's 0004 also drops a temp integrity-check table outside the annotated rebuild block)"
  - "Released migrations pinned by sha256 manifest instead of a git tag; manifest values verified equal to git show v0.1.0:<path>"
duration: 60min
completed: 2026-11-25
---

# Phase 3 Plan 16: Migration safety (OPS-04) Summary

**Migrations still run on start, but a pending `NNNN_destructive_*` migration now makes start refuse unless the operator passes `--allow-destructive-migrations`. Both backends are proven to upgrade a populated 0.1 database through the storage traits, and the 114-test contract suite also passes on upgraded databases. A CI lint keeps the 0.1 migration files byte-for-byte unchanged and rejects destructive SQL that is neither named `destructive_` nor annotated.**

## Performance

- **Duration:** about 60 min
- **Tasks:** 3
- **Files:** 13 created, 11 modified

## Accomplishments

### Destructive-migration guard (Task 1)

- Each backend has a `migrate.rs` with:
  - `MigrateOptions { allow_destructive }`;
  - `PendingMigration { version, description }`, displayed as `0002 destructive drop x`;
  - `MigrateError::{Destructive(Vec<PendingMigration>), Storage(StorageError)}`;
  - `pending()`, `destructive()`, `run_guarded()`, `migrate_with()` and `migrate()`.
- `pending()` reads `_sqlx_migrations` only if the table exists (`sqlite_master` / `to_regclass`), so a refused fresh database stays completely empty.
- On Postgres, `locked()` wraps the check and the run in sqlx's advisory lock on one connection. A concurrency test runs two `migrate()` calls in parallel on one database and both succeed.
- anvilid:
  - New config key `allow_destructive_migrations` (bool, default false). It can be set by the CLI flag `--allow-destructive-migrations`, by `ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS` or in `anvilid.toml`, and `config show` lists it with its source.
  - `storage::Migrations::{Skip, Run { allow_destructive }}` replaces the `migrate: bool` argument of `open_storage`. `Config::migrations()` maps `no_migrate` and the flag onto it.
  - Refusal message: `refusing to run destructive migrations: <list>; re-run with --allow-destructive-migrations after taking a backup`.
- Tests:
  - A fixture migrator in `tests/fixtures/destructive` on both backends: refused with no tables created, applied when allowed, an already-applied destructive migration does not block, nothing pending is a no-op, the embedded migrations are not destructive, and name matching (`destructiveness` is not destructive).
  - anvilid: a unit test for the message, a config test (default, env, `no_migrate` gives Skip), and 5 CLI tests: migrate with the flag, config show default/env/cli source, serve parses the env value, and serve rejects a non-boolean value.

### 0.1 to 0.2 upgrade tests (Task 2)

- Per backend, `tests/upgrade.rs`:
  1. `run_to(2)` on a fresh DB (SQLite file in a tempdir; a fresh database on a shared Postgres testcontainer).
  2. Load `fixtures/v0_1.sql`: system and default tenants with 0.1 settings JSON, a confidential client with a secret hash, a public client, a user with an Argon2 PHC, a browser session, and a token family with an unconsumed code and a live refresh token.
  3. Insert a signing key sealed at test time with a fixed test KEK, and an outbox row whose payload is sealed with `seal_payload`.
  4. Upgrade with `migrate_with(Default)`.
- Checks through the traits:
  - Tenant settings equal 0.1 values plus `signing_algs == ["RS256"]` and `captcha == None`; `is_installed` is true.
  - The PHC is unchanged, and `list_credentials` returns exactly the password.
  - Both clients have `token_format=jwt`, `consent_mode=required`, `can_introspect=false` and id_token alg None.
  - The session is active with `ip`/`user_agent` None.
  - `consume_code` consumes once (the second call returns AlreadyConsumed), and `rotate_refresh` rotates.
  - `keys().active(default, "RS256")` opens with `open_key` and signs.
  - `claim_due` returns the outbox row, and `open_payload` gives back the original payload.
  - A restart migrate is a no-op.
- `upgraded_contract`: the full `storage_contract_tests!` runs against a factory that builds each database through the upgrade path. It then deletes the two fixture tenants through `tenants().delete`, which cascades every fixture row through the upgraded foreign keys, because the contract tests expect an uninstalled database.

### Migration lint (Task 3)

- `scripts/released-migrations.sha256`, in sha256sum format, pins `0001_init.sql` and `0002_release_0_1.sql` for both backends. The values were generated from `git show v0.1.0:<path>` and also pass `sha256sum -c` on the current tree.
- `scripts/check-migrations.sh`:
  - Immutability: a modified, missing or malformed manifest entry fails.
  - Lint: an unreleased migration is scanned with SQL comments stripped and whitespace collapsed, so multi-line statements are caught. It is checked for DROP TABLE, DROP COLUMN, a bare `ALTER TABLE … DROP <col>` (also after a comma), RENAME, `ALTER [COLUMN] … [SET DATA] TYPE`, DELETE FROM and TRUNCATE.
  - Such a migration passes only with a `NNNN_destructive_*.sql` name (prints a warning) or the file-level `-- anvil:non-destructive-rebuild` annotation.
  - Constraint swaps (`DROP CONSTRAINT`, `DROP NOT NULL`, `DROP DEFAULT`) and `ON DELETE CASCADE` are not flagged.
  - Portable: perl for matching, `sha256sum` or `shasum -a 256`, no bash-4 associative arrays.
  - `--self-test` builds a temp tree and runs 14 cases.
- `just migrations-check` was added but deliberately left out of the `ci` recipe (03-29 owns that). The CI `lint` job gets a "Migration lint" step that runs the check and then `--self-test`.

## Release procedure for the manifest (for 03-29)

At release, append the new migrations, for example `sha256sum crates/anvil-storage-*/migrations/0003_*.sql crates/anvil-storage-sqlite/migrations/0004_*.sql >> scripts/released-migrations.sha256`, and commit. From then on those files are immutable. Schema changes go into new migrations, and destructive ones get a `NNNN_destructive_` name.

## Task Commits

1. **Task 1: Destructive guard + anvilid flag:** `50c1d21`
2. **Task 2: 0.1 to 0.2 upgrade tests:** `2fc6580`
3. **Task 3: Migration lint and CI step:** `b8e3ad4`

## Verification

- `cargo test -p anvil-storage-sqlite --lib migrate`: 6/6. `cargo test -p anvil-storage-postgres --lib migrate`: 7/7.
- `cargo test -p anvil-storage-sqlite --test upgrade`: 116/116 (2 upgrade tests and 114 contract tests on upgraded DBs). `cargo test -p anvil-storage-postgres --test upgrade`: 116/116.
- `cargo test -p anvilid --test cli`: 15/15. anvilid bin unit tests: 27/27.
- `scripts/check-migrations.sh`: OK. `scripts/check-migrations.sh --self-test`: OK, 14 cases.
- `cargo clippy -p anvil-storage-sqlite -p anvil-storage-postgres -p anvilid --all-targets -- -D warnings`: clean, run in worktree `target/wt-03-16` because another plan's in-progress anvil-core edit broke the shared tree's build at the time.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `crates/anvilid/src/main.rs` and `startup.rs` edited (not in files_modified)**
- **Found during:** Task 1
- **Issue:** Both files call `open_storage`, whose signature had to change to carry the destructive flag.
- **Fix:** Changed only the three call sites: `cfg.migrations()` in startup, `Migrations::Run { allow_destructive }` in `migrate`, and `Migrations::Skip` in `admin setup-url`. No parallel plan had edits in these files.
- **Commit:** 50c1d21

**2. [Rule 2 - Correctness] Advisory-locked connection is never returned to the pool in an unknown lock state**
- **Issue:** If a migration or the unlock fails, a pooled Postgres connection could keep the migration lock.
- **Fix:** `close_on_drop()` on error or failed unlock. Closing the session releases the advisory lock.
- **Commit:** 50c1d21

### Process note

- The TDD tasks (1 and 3) did not get separate RED commits. Tests and implementation landed together in one commit per task. Every negative case is covered: refusal leaves the database empty, and the self-test checks that each rule rejects bad input.

## Known limitations (upgrade notes)

- A rolling upgrade with mixed 0.1 and 0.2 binaries is not supported for password writes. On the 0.2 schema, 0.1's `ON CONFLICT (user_id, kind)` no longer matches a unique index and it does not supply `credential.id` (see 03-06). Reads keep working. Upgrade all nodes together, or stop 0.1 nodes before the first 0.2 node migrates.
- SQLite has no cross-process migration lock (sqlx's lock is a no-op there). The guard cannot be bypassed, but two processes migrating one file concurrently rely on SQLite's busy timeout. `serve.lock` prevents two servers on one data dir.

## Self-Check: PASSED
