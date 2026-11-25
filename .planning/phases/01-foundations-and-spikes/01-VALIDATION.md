---
phase: 1
slug: foundations-and-spikes
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-11-25
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from 01-RESEARCH.md § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness (`cargo test`) + `#[tokio::test]`; testcontainers-modules 0.15 (Postgres); shell checks for CI-only criteria |
| **Config file** | none — Wave 0 creates `Cargo.toml` workspace, `justfile`, `.cargo/config.toml` |
| **Quick run command** | `cargo test --workspace --locked` |
| **Full suite command** | `just ci` (fmt-check, clippy -D warnings, cargo deny, check-deps, all tests incl. Postgres via Docker) |
| **Estimated runtime** | ~180 seconds (full, warm cache) |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --workspace --locked` (+ clippy for code tasks)
- **After every plan wave:** Run `just ci`
- **Before `/gsd:verify-work`:** `just ci` green locally; ci.yml, release-build.yml and conformance.yml green on GitHub; spike summaries recorded
- **Max feedback latency:** 180 seconds

---

## Per-Task Verification Map

Task IDs are filled in by the planner; requirement → check mapping is fixed here.

| Requirement | Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|----------|-----------|-------------------|-------------|--------|
| FND-01 | Workspace builds/lints/tests with one command | smoke | `just ci` | ❌ W0 | ⬜ pending |
| FND-01 | CI runs fmt/clippy/deny/tests on PRs | CI config | `.github/workflows/ci.yml` green | ❌ W0 | ⬜ pending |
| FND-02 | Clean tree passes dependency rules | script | `just deps` | ❌ W0 | ⬜ pending |
| FND-02 | Forbidden deps are rejected (negative) | negative | `just deps-selftest` | ❌ W0 | ⬜ pending |
| FND-03 | Tenant create/get/slug conflict on both backends | contract | `cargo test -p anvil-storage-sqlite --test contract` / `-p anvil-storage-postgres --test contract` | ❌ W0 | ⬜ pending |
| FND-03 | consume_code once → Consumed, then AlreadyConsumed; expired → NotFound | contract | same | ❌ W0 | ⬜ pending |
| FND-03 | Wrong tenant cannot consume (negative) | contract | `consume_code_wrong_tenant` | ❌ W0 | ⬜ pending |
| FND-03 | N parallel consumes → exactly one winner | concurrency | `consume_code_concurrent_single_winner` (SQLite memory, file, Postgres) | ❌ W0 | ⬜ pending |
| FND-03 | `.sqlx/` offline data current for both crates | CI check | `just sqlx-check` | ❌ W0 | ⬜ pending |
| FND-04 | Static musl binaries amd64 + arm64 | CI build | `release-build.yml` matrix; `file` asserts static | ❌ W0 | ⬜ pending |
| FND-04 | Embedded asset served from the binary | smoke | `scripts/measure-idle.sh` (sha256 compare) | ❌ W0 | ⬜ pending |
| FND-04 | Size + idle RSS reported | CI report | `scripts/measure-idle.sh` → step summary + JSON artifact | ❌ W0 | ⬜ pending |
| FND-05 | Conformance suite runs end to end against a fresh binary | e2e (CI) | `tests/conformance/run.sh` with `expected-failures-m0.json` ratchet | ❌ W0 | ⬜ pending |
| (support) | Discovery from issuer; unimplemented endpoints return 501 | integration | `cargo test -p anvil-web` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Root `Cargo.toml` (virtual workspace, resolver 3, workspace deps/lints), `rust-toolchain.toml` (1.100.0), `.cargo/config.toml`, `Cargo.lock`
- [ ] 9 crate skeletons per ARCHITECTURE.md §4
- [ ] `justfile` with `ci`, `test`, `lint`, `fmt-check`, `deny`, `deps`, `deps-selftest`, `sqlx-prepare`, `sqlx-check`, `db-up`, `musl`, `conformance`
- [ ] `deny.toml` (incl. `wrappers = ["crypto-glue"]` note for later webauthn-rs), `scripts/check-deps.sh`
- [ ] `crates/anvil-storage/src/contract/` + feature `contract`; backend `tests/contract.rs`
- [ ] Per-crate `sqlx.toml`, `migrations/`, `.sqlx/`
- [ ] Tool installs: just, sqlx-cli 0.9.1, cargo-deny
- [ ] `tests/conformance/` harness; `scripts/measure-idle.sh`

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| arm64 binary actually runs | FND-04 | Needs the arm64 runner; verified by CI job output, reviewed once | Check release-build.yml arm64 job summary |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 180s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
