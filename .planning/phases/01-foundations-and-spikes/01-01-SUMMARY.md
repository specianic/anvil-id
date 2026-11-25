---
phase: 01-foundations-and-spikes
plan: 01
subsystem: infra
tags: [rust, cargo-workspace, sqlx, async-trait, just, toolchain]

requires: []
provides:
  - Nine-crate Cargo workspace (ARCHITECTURE.md §4) on pinned Rust 1.100.0
  - Complete Phase 1 Cargo.lock (no further registry crates needed by plans 02-07)
  - anvil_core::ports (Storage, TenantRepo, GrantRepo, ConsumeOutcome, StorageError)
  - anvil_core::model (TenantId, TokenFamilyId, CodeHash, InvalidLength, Tenant, NewTenant, AuthorizationCode, NewAuthorizationCode, truncate_to_ms)
  - justfile recipe contract (ci, fmt-check, fmt, lint, deny, deps, deps-selftest, test, db-up, sqlx-prepare, sqlx-check, clean-test-containers, musl, measure, conformance)
affects: [01-02, 01-03, 01-04, 01-05, 01-06, 01-07, 01-08, phase-02]

tech-stack:
  added: [tokio 1.54.1, axum 0.8.9, sqlx 0.9.1, aws-lc-rs 1.19.0, mimalloc 0.1.52, rust-embed 8.14, uuid 1.29.3, time 0.3.55, thiserror 2, async-trait 0.1.92, serde, serde_json, url, clap 4.6, tracing, tracing-subscriber, anyhow, testcontainers-modules 0.15.0, tempfile 3.27, just 1.x (dev tool)]
  patterns:
    - "Ports in anvil-core; backends normal-depend on anvil-core only, anvil-storage (contract suite) as dev-dependency"
    - "Millisecond timestamp storage contract via model::truncate_to_ms"
    - "justfile recipes delegate to scripts/ owned by later plans"

key-files:
  created:
    - Cargo.toml
    - Cargo.lock
    - rust-toolchain.toml
    - .cargo/config.toml
    - justfile
    - crates/anvil-core/src/model.rs
    - crates/anvil-core/src/ports.rs
    - crates/*/Cargo.toml (nine crates)
  modified:
    - .gitignore
    - README.md
    - docs/ARCHITECTURE.md

key-decisions:
  - "ConsumeOutcome::Consumed holds AuthorizationCode by value with #[expect(clippy::large_enum_variant)] rather than Box, keeping the specified contract"
  - "anvil-core dev-depends on time with the macros feature for test literals (time-macros already in the lockfile; no new registry crate)"
  - "Placeholder crates (jose, cache, mail) and storage/web libs contain doc comments only; anvilid main exits 2 with an explicit error"

patterns-established:
  - "Every crate inherits edition/license/publish/rust-version and [lints] from the workspace"
  - "Workspace dependency versions are declared once in root [workspace.dependencies]"

requirements-completed: [FND-01]

duration: 15min
completed: 2026-11-25
---

# Phase 1 Plan 01: Workspace Skeleton and Storage Ports Summary

**Nine-crate Rust 1.100.0 workspace with a complete Phase 1 Cargo.lock (sqlx 0.9.1 on aws-lc-rs only, no ring/openssl/chrono), storage port traits and domain model in anvil-core, and the `just ci` recipe contract.**

## Performance

- **Duration:** ~15 min
- **Completed:** 2026-11-25
- **Tasks:** 3
- **Files modified:** 28

## Accomplishments
- Virtual workspace (resolver 3, edition 2024, unsafe_code deny, clippy all warn, fat-LTO release profile). The final Phase 1 dependency set is declared per crate. `cargo tree` confirms that ring, openssl, native-tls and chrono are not in the resolved normal/build graph.
- `anvil_core::ports` and `anvil_core::model` match the plan's interface spec. 8 unit tests cover ms truncation, UUIDv7 ids, CodeHash length rejection, dyn-compatibility/Send+Sync of the ports, and StorageError source chaining. anvil-core has no I/O crate in its normal graph.
- justfile exposes all 13 contract recipes plus `fmt` and `clean-test-containers`. README has a Development section. ARCHITECTURE.md §4/§7.1/§7.2 now reflect the ports-in-core decision and the rule that dependency rules cover normal dependencies only.

## Task Commits

1. **Task 1: Workspace manifests, toolchain, nine crate skeletons and Cargo.lock** - `d996c70` (chore)
2. **Task 2: Storage ports and domain model in anvil-core** - `822a457` (test, RED), `3cb2991` (feat, GREEN)
3. **Task 3: justfile, README dev section, ARCHITECTURE update** - `c7cce14` (chore)

## Files Created/Modified
- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/config.toml` - workspace, lockfile, toolchain pin, SQLX_OFFLINE default (not forced)
- `crates/*/Cargo.toml`, `crates/*/src/lib.rs`, `crates/anvilid/src/main.rs` - nine crate skeletons
- `crates/anvil-core/src/{lib,model,ports}.rs` - domain model and storage ports
- `justfile`, `README.md`, `docs/ARCHITECTURE.md`, `.gitignore`

## Decisions Made
- `ConsumeOutcome::Consumed(AuthorizationCode)` is kept unboxed to match the spec. Clippy's `large_enum_variant` is suppressed with a documented `#[expect]`.
- I added `InvalidLength { expected, actual }` (a thiserror type) as the error for `CodeHash::from_slice`. The plan named the type but did not define its shape.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] time `macros` feature for core tests**
- **Found during:** Task 2
- **Issue:** `time::macros::datetime!` is unavailable without the feature
- **Fix:** Added `[dev-dependencies] time = { workspace = true, features = ["macros"] }` to anvil-core. Only the test graph is affected, and time-macros was already in Cargo.lock.
- **Commit:** 822a457

**2. [Rule 1 - Consistency] ARCHITECTURE.md §4 anvil-web rule**
- **Found during:** Task 3
- **Issue:** The anvil-web dependency rule still said "`anvil-storage` (traits only)". That contradicts the ports-in-core decision.
- **Fix:** Changed it to "`anvil-core` (including the storage ports)". This is one line outside the passages the plan listed.
- **Commit:** c7cce14

**3. [Rule 3 - Blocking] Installed `just`**
- `just` was not on the machine, so I ran `cargo install just --locked`, as the verify command prescribes. This was a local tool install and nothing was committed.

## Issues Encountered
- Cargo 1.100 emits manifest lints `cargo::unused_dependencies` and `cargo::unused_workspace_dependencies` for the skeleton crates. These are cargo warnings, not rustc warnings, so `clippy -D warnings` still passes. Most will disappear as plans 03-07 use the dependencies. The `anvil-jose`, `anvil-cache`, `anvil-mail` and `anvilid` workspace entries will keep warning until something depends on them. A later plan could drop the `anvilid` entry or set `[workspace.lints.cargo]` if the noise matters.

## User Setup Required
None.

## Next Phase Readiness
- Plans 02-07 can build against the fixed ports, crate manifests and recipe names without adding registry crates.
- `just ci` will fail until plans 02/03 add `deny.toml` and `scripts/check-deps.sh` (expected; those scripts are out of scope here).

---
*Phase: 01-foundations-and-spikes*
*Completed: 2026-11-25*

## Self-Check: PASSED
