# Phase 1: Foundations and Spikes (M0) - Context

**Gathered:** 2026-11-25
**Status:** Ready for planning
**Source:** docs/ARCHITECTURE.md (§2, §4, §7, §17, §18 M0) — decisions there are locked

<domain>
## Phase Boundary

Prove the chosen stack before feature work. Deliver: the Cargo workspace skeleton with the crate layout
from ARCHITECTURE.md §4, CI on GitHub Actions enforcing lint/deny/tests and crate dependency rules, and
three risk spikes:

- **Spike A** — storage: `TenantRepo` + `GrantRepo::consume_code` implemented in both
  `anvil-storage-sqlite` and `anvil-storage-postgres` (sqlx 0.9, `query!` macros with per-crate `.sqlx/`
  offline metadata), exercised by a shared contract test suite living in `anvil-storage`, including a
  concurrency test (N parallel consumes → exactly one success). Record the duplication cost.
- **Spike B** — static build: musl release binaries for x86_64 and aarch64 with aws-lc-rs, mimalloc
  and an embedded asset; CI reports binary size and idle RSS.
- **Spike C** — conformance pipeline: CI starts a fresh `anvilid` binary and runs the OpenID
  conformance suite (its Docker image) against it end to end. In this phase the binary only needs a
  minimal discovery document; the goal is the pipeline, not passing OIDC test plans.

Out of this phase: any OAuth/OIDC feature logic, login UI, admin console, real migrations beyond what
the spikes need.

</domain>

<decisions>
## Implementation Decisions

### Workspace and toolchain
- Cargo workspace, edition 2024, stable toolchain pinned in `rust-toolchain.toml` (local machine has 1.94.1; verify sqlx 0.9 MSRV — open decision D7)
- Crates exactly as ARCHITECTURE.md §4: anvil-core, anvil-jose, anvil-storage, anvil-storage-sqlite, anvil-storage-postgres, anvil-cache, anvil-web, anvil-mail, anvilid (binary). Crates not needed by the spikes may be empty skeletons with a lib.rs
- Dependency versions pinned in `[workspace.dependencies]` per ARCHITECTURE.md §2

### Rules enforced from day one
- cargo-deny with bans: openssl, native-tls, ring (as second backend — allow transitive only if unavoidable, document), RustCrypto `rsa`, chrono, samael, xmlsec, oxide-auth
- Dependency-rule checker (script over `cargo metadata`): anvil-core may not depend on tokio/sqlx/axum/reqwest or any storage crate; anvil-web may not depend on anvil-storage-sqlite/postgres
- CLAUDE.md rules apply: no stubs returning success, no test hooks in production code

### Storage (Spike A)
- sqlx 0.9 with separate typed implementations; `sqlx::Any` is NOT used
- `consume_code` is a single atomic statement: `UPDATE … SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL AND expires_at>? RETURNING …`; already-consumed returns a distinct `AlreadyConsumed` outcome
- SQLite: WAL, busy_timeout, foreign_keys=ON, single writer + reader pool, STRICT tables, UUID as BLOB, unix-ms integer timestamps
- Postgres: uuid, timestamptz, jsonb; tests via testcontainers (Docker available locally and in CI)
- Every repo method takes a TenantId; tenant isolation is part of the contract tests

### CI
- GitHub Actions (repo: github.com/specianic/anvil-id, public)
- PR workflow: fmt, clippy -D warnings, cargo deny, tests (SQLite + Postgres), dependency-rule check, sqlx offline metadata check
- Release-build job: musl amd64 + arm64 static binaries, size + idle RSS report

### Claude's Discretion
- Exact contract-suite structure (macro vs generic async fns)
- One-command entry point (`make`, `just`, or `cargo xtask`) — pick one and document it in README
- Cross-compilation tool (cargo-zigbuild vs cross vs native arm runners)
- How idle RSS is measured in CI
- How the conformance suite is driven headlessly (its API/CLI runner) and which minimal test plan proves the pipeline

</decisions>

<specifics>
## Specific Ideas

- Repository is public: never commit secrets, keys or internal hostnames; generated test keys only in temp dirs
- If a spike fails, record why and what alternative was considered (ARCHITECTURE.md §2.1 says revisit the stack decision before M1)

</specifics>

<deferred>
## Deferred Ideas

- Full OIDC conformance test plans (Basic OP, Config OP) — Phase 2
- Admin console build in CI — later phase (but the embedded-asset mechanism is exercised by Spike B)

</deferred>

---

*Phase: 01-foundations-and-spikes*
*Context gathered: 2026-11-25 from ARCHITECTURE.md*
