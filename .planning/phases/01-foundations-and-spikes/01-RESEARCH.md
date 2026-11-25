# Phase 1: Foundations and Spikes (M0) - Research

**Researched:** 2026-11-25
**Domain:** Rust Cargo workspace + GitHub Actions CI; sqlx 0.9 dual-backend storage; static musl builds; OpenID conformance suite automation
**Confidence:** HIGH for stack/versions and sqlx mechanics (verified from crate sources); HIGH for musl build (built locally); MEDIUM for conformance pipeline (verified from suite source, not executed locally)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

#### Workspace and toolchain
- Cargo workspace, edition 2024, stable toolchain pinned in `rust-toolchain.toml` (local machine has 1.94.1; verify sqlx 0.9 MSRV — open decision D7)
- Crates exactly as ARCHITECTURE.md §4: anvil-core, anvil-jose, anvil-storage, anvil-storage-sqlite, anvil-storage-postgres, anvil-cache, anvil-web, anvil-mail, anvilid (binary). Crates not needed by the spikes may be empty skeletons with a lib.rs
- Dependency versions pinned in `[workspace.dependencies]` per ARCHITECTURE.md §2

#### Rules enforced from day one
- cargo-deny with bans: openssl, native-tls, ring (as second backend — allow transitive only if unavoidable, document), RustCrypto `rsa`, chrono, samael, xmlsec, oxide-auth
- Dependency-rule checker (script over `cargo metadata`): anvil-core may not depend on tokio/sqlx/axum/reqwest or any storage crate; anvil-web may not depend on anvil-storage-sqlite/postgres
- CLAUDE.md rules apply: no stubs returning success, no test hooks in production code

#### Storage (Spike A)
- sqlx 0.9 with separate typed implementations; `sqlx::Any` is NOT used
- `consume_code` is a single atomic statement: `UPDATE … SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL AND expires_at>? RETURNING …`; already-consumed returns a distinct `AlreadyConsumed` outcome
- SQLite: WAL, busy_timeout, foreign_keys=ON, single writer + reader pool, STRICT tables, UUID as BLOB, unix-ms integer timestamps
- Postgres: uuid, timestamptz, jsonb; tests via testcontainers (Docker available locally and in CI)
- Every repo method takes a TenantId; tenant isolation is part of the contract tests

#### CI
- GitHub Actions (repo: github.com/specianic/anvil-id, public)
- PR workflow: fmt, clippy -D warnings, cargo deny, tests (SQLite + Postgres), dependency-rule check, sqlx offline metadata check
- Release-build job: musl amd64 + arm64 static binaries, size + idle RSS report

### Claude's Discretion
- Exact contract-suite structure (macro vs generic async fns)
- One-command entry point (`make`, `just`, or `cargo xtask`) — pick one and document it in README
- Cross-compilation tool (cargo-zigbuild vs cross vs native arm runners)
- How idle RSS is measured in CI
- How the conformance suite is driven headlessly (its API/CLI runner) and which minimal test plan proves the pipeline

### Specific Ideas
- Repository is public: never commit secrets, keys or internal hostnames; generated test keys only in temp dirs
- If a spike fails, record why and what alternative was considered (ARCHITECTURE.md §2.1 says revisit the stack decision before M1)

### Deferred Ideas (OUT OF SCOPE)
- Full OIDC conformance test plans (Basic OP, Config OP) — Phase 2
- Admin console build in CI — later phase (but the embedded-asset mechanism is exercised by Spike B)

Note: "Config OP" is deferred as a *passing* target. This research still recommends running the
Config OP **plan** in Phase 1 as the pipeline proof, with all failures recorded in an expected-failures
file (see Spike C). That proves the pipeline, which is what Phase 1 asks for, and does not try to pass the plan.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| FND-01 | One command builds/lints/tests the workspace (crate layout per §4); CI runs fmt, clippy, cargo-deny and tests on every PR | `just ci` entry point (§Architecture: One-command entry point); workspace manifest skeleton; `ci.yml` job layout; cargo-deny config verified with cargo-deny on a probe graph |
| FND-02 | CI enforces the crate dependency rules | `scripts/check-deps.sh` built on `cargo tree -p` (per-package feature resolution, verified to be more accurate than `cargo metadata`); a self-test that injects a forbidden dependency and expects failure |
| FND-03 | Spike A: tenant repo + atomic `consume_code` on SQLite and Postgres, shared contract suite incl. concurrency test | sqlx 0.9.1 per-crate `sqlx.toml` (`database-url-var`) + per-crate `.sqlx/`; SQL for both dialects; contract macro pattern; testcontainers-modules 0.15 Postgres helper; concurrency test design; duplication-cost metrics |
| FND-04 | Spike B: static musl binary amd64+arm64 (aws-lc-rs, mimalloc, embedded assets), size and idle RSS reported | Verified locally: `rust:1.100-alpine` builds a static-pie binary with axum+sqlx(sqlite+pg)+aws-lc-rs+mimalloc+rust-embed (3.5 MB, 9.1 MB idle RSS); native `ubuntu-24.04` + `ubuntu-24.04-arm` runners; `/proc/<pid>/status` + `smaps_rollup` measurement |
| FND-05 | Spike C: the OpenID conformance suite runs in CI against a freshly started binary | Prebuilt images `registry.gitlab.com/openid/conformance-suite:release-v5.3.5` (+ `/nginx`), `docker-compose-prebuilt.yml`, `scripts/run-test-plan.py` driving the REST API, Config OP plan = single automated module `oidcc-discovery-endpoint-verification`, expected-failures ratchet file |
</phase_requirements>

## Summary

The stack holds up. Every concrete question from the phase brief has a verified answer. **sqlx 0.9.1
(2026-11-18) has MSRV 1.94.0**, read from its `Cargo.toml` `rust-version` and changelog. That resolves
D7. Current stable Rust is **1.100.0** (2026-11-09), and it is already installed locally as a rustup
toolchain. Pin `1.100.0`. The key sqlx 0.9 feature for this phase is the new per-crate **`sqlx.toml`**
(behind the non-default `sqlx-toml` cargo feature). `[common] database-url-var = "…"` gives each storage
crate its own database URL env var, so `query!` in `anvil-storage-sqlite` checks against SQLite while
`anvil-storage-postgres` checks against Postgres in the same `cargo build`. The macros look up offline
data in `$SQLX_OFFLINE_DIR`, then `<crate>/.sqlx`, then `<workspace>/.sqlx`, in that order (read from
`sqlx-macros-core` source). Run `cargo sqlx prepare` once per crate, not `--workspace`, to get per-crate
`.sqlx/` directories.

The static build works. I built a probe in `rust:1.100-alpine` with the planned dependency set: axum,
sqlx with SQLite bundled and Postgres, rustls with aws-lc-rs, aws-lc-rs, mimalloc and rust-embed, using
fat LTO. The result was a **3.5 MB static-pie binary** in 1m53s. Run on the host with a tokio
multi-thread runtime and an open SQLite pool, it had **9.1 MB idle RSS**. aws-lc-sys 0.47 needs only a
C compiler for musl targets: no CMake, no Go, no bindgen, because pre-generated bindings ship for both
musl targets. Use native GitHub runners (`ubuntu-24.04` and `ubuntu-24.04-arm`, free for public repos,
both with Docker 28). Build inside the official `rust:<pin>-alpine` image so that each arch can also
*run* its binary to measure RSS. cargo-zigbuild and cross are not needed. cross 0.2.5 dates from 2023.

The conformance suite publishes **prebuilt images** for every release:
`registry.gitlab.com/openid/conformance-suite:release-v5.3.5` and `…/nginx:release-v5.3.5`. Its
`docker-compose-prebuilt.yml` runs MongoDB, the server and nginx on `https://localhost.emobix.co.uk:8443`,
a public DNS name that resolves to 127.0.0.1 (verified). The official driver
`scripts/run-test-plan.py`, which needs only `httpx` and `pyparsing`, creates a plan through
`POST /api/plan` and runs each module. It exits non-zero on *unexpected* failures **and** on expected
failures that no longer happen, so an `--expected-failures-file` becomes an exact ratchet. The **Config
OP plan (`oidcc-config-certification-test-plan`) contains exactly one module,
`oidcc-discovery-endpoint-verification`, which is fully automated and needs no browser**. It is the
minimal plan that exercises the binary end to end.

**Primary recommendation:** Pin Rust 1.100.0 and sqlx 0.9.1 with per-crate `sqlx.toml` and `.sqlx/`.
Expose the contract suite as a `storage_contract_tests!` macro behind an `anvil-storage/contract`
feature. Use `testcontainers-modules` 0.15 (which pins `testcontainers` 0.27, *not* 0.28). Use `just`
as the single entry point. Check dependency rules with `cargo tree -p`. Build musl natively per arch in
`rust:1.100-alpine`. Drive Config OP with the upstream `run-test-plan.py` pinned to the image tag.

## Standard Stack

All versions verified against the crates.io API on 2026-11-25 unless noted.

### Core (needed by Phase 1)
| Library | Version | Purpose | Why Standard / Notes |
|---------|---------|---------|----------------------|
| Rust toolchain | **1.100.0** (stable, 2026-11-09) | Pinned in `rust-toolchain.toml` | Installed locally already (`rustup toolchain list`). ≥ sqlx MSRV 1.94.0 |
| sqlx | **0.9.1** (2026-11-18), MSRV **1.94.0** | Typed SQLite + Postgres access, migrations, offline macros | `default-features = false`, because default includes `any`. See feature list below |
| tokio | 1.54.1 (MSRV 1.85) | Async runtime | |
| axum | 0.8.9 (MSRV 1.80) | HTTP for discovery/health/asset endpoints | |
| aws-lc-rs | 1.19.0 (aws-lc-sys 0.47.0) | The single crypto backend | C compiler only for musl; pre-generated bindings for x86_64/aarch64 musl |
| rustls | 0.23.46 | Pulled in by sqlx `tls-rustls-aws-lc-rs` | Verified: with the feature set below, **`ring` is not in the resolved graph** |
| mimalloc | 0.1.52 (libmimalloc-sys 0.1.49) | Global allocator | Builds on musl (verified) |
| rust-embed | 8.14.0 | Embedded assets (Spike B) | Debug builds read from disk; release builds embed |
| uuid | 1.29.3 (`v7`) | IDs | sqlx `uuid` feature: SQLite encodes `Uuid` as 16-byte BLOB (verified in `sqlx-sqlite/src/types/uuid.rs`) |
| time | 0.3.55 | Timestamps (`chrono` banned) | |
| thiserror | 2.0.21 | Error types | |
| async-trait | 0.1.92 | `dyn`-compatible async repo traits | Native `async fn` in traits is not dyn-compatible, and ARCHITECTURE §7.1 uses `&dyn TenantRepo` |
| clap | 4.6.x (`derive`, `env`) | `anvilid serve` flags | figment config is M1 scope |
| tracing / tracing-subscriber | 0.1.44 / 0.3.x (`env-filter`, `json`) | Logging | |
| serde / serde_json | 1.0.229 / 1.0.154 | Discovery JSON | |

**sqlx feature set (workspace dependency):**
```toml
sqlx = { version = "0.9.1", default-features = false, features = [
  "runtime-tokio", "tls-rustls-aws-lc-rs", "macros", "migrate", "sqlx-toml",
  "uuid", "time", "json",
] }
# per crate:
#   anvil-storage-sqlite:   sqlx = { workspace = true, features = ["sqlite-bundled"] }
#   anvil-storage-postgres: sqlx = { workspace = true, features = ["postgres"] }
```
- Use `sqlite-bundled`, not `sqlite`. In 0.9 `sqlite` = `sqlite-bundled` + `sqlite-deserialize` +
  `sqlite-load-extension` + `sqlite-unlock-notify`, and we don't want extension loading.
- Never `sqlite-unbundled`. It needs `libsqlite3-sys/buildtime_bindgen`, which means libclang, which
  breaks static builds.
- Never `tls-rustls`. It is an alias for `tls-rustls-ring`.

### Supporting (tests and tooling)
| Library / Tool | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| testcontainers-modules | **0.15.0** (features `postgres`, `default-features = false`) | Postgres for contract tests | Depends on **testcontainers 0.27.x**, not 0.28.0. Use the re-export `testcontainers_modules::testcontainers`. Do **not** add `testcontainers = "0.28"` directly, or you get two incompatible `Image` traits |
| tempfile | 3.27.0 | SQLite file-backed contract variant | dev-dependency |
| sqlx-cli | **0.9.1** (`--no-default-features --features rustls,sqlite,postgres,sqlx-toml`) | `cargo sqlx prepare`, `migrate` | Local machine has **0.8.6. Must upgrade**: 0.8 doesn't know `sqlx.toml`. Default features include `native-tls`, so install with the explicit features |
| cargo-deny | **0.22.1** (MSRV 1.95 to *build*) | advisories/bans/licenses/sources | CI: `EmbarkStudios/cargo-deny-action@v2` (v2.1.4). Local machine has 0.21.0, which works with the same config |
| just | 1.59.0 | One-command entry point | `taiki-e/install-action` in CI |
| PostgreSQL image | `postgres:18-alpine` | Test and compile-time DB | 19 is also published. The testcontainers module default tag is **11-alpine**, so always `.with_tag(...)` |
| OpenID conformance suite | `release-v5.3.5` (2026-11-24) | Spike C | Prebuilt images + `scripts/run-test-plan.py` from the same git tag |
| GitHub Actions | checkout v7.0.1, Swatinem/rust-cache v2.9.3, taiki-e/install-action v2.90.8, actions/setup-python v7.1.0, actions/upload-artifact v7.0.2 | CI | Runner images ubuntu-24.04 / ubuntu-24.04-arm: Docker 28.0.4, Compose 2.38.2, Python 3.12.3 |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Native arm runner + Alpine container | cargo-zigbuild 0.24.1 | One runner builds both arches, but it can't *run* the arm64 binary for RSS measurement without QEMU, and it adds a zig toolchain (not installed locally) |
| Native arm runner + Alpine container | cross 0.2.5 | Last release 2023-02. Stale |
| Native arm runner + Alpine container | Ubuntu host + `apt install musl-tools` | Works, but you must set `CC_aarch64_unknown_linux_musl=musl-gcc` (cc-rs looks for `aarch64-linux-musl-gcc`). Otherwise it falls back to glibc `cc`, and glibc 2.39 headers cause `__isoc23_*` link errors. Keep as the documented fallback |
| `just` | `make` | Preinstalled, but tab-sensitive and clumsy with arguments |
| `just` | `cargo xtask` | No extra install, but adds a crate outside the locked §4 layout plus compile time. Tools (cargo-deny, sqlx-cli, docker) are still external |
| `cargo tree -p` script | cargo-deny `[bans] deny = [{ crate, wrappers }]` | `wrappers` only restricts *direct* dependents. It cannot express "anvil-core's transitive closure must not contain tokio" |
| `cargo tree -p` script | `cargo metadata` resolve graph | `cargo metadata` resolves features **workspace-unified**. Verified: a crate with `uuid` default-features off still showed `getrandom` because a sibling enabled `v4`. That gives false positives. `cargo tree -p X` resolves per package. (CONTEXT says "script over `cargo metadata`"; `cargo tree` reads the same metadata, so the intent is the same with better accuracy) |
| upstream `run-test-plan.py` | Own 60-line REST driver | Own driver = hand-rolled behavior that drifts from upstream. The upstream script is what the suite's own CI uses, and its expected-failures ratchet is what Phases 2–7 need |

**Installation (local contributor):**
```bash
cargo install just --locked                      # or distro package
cargo install cargo-deny --locked                # run inside repo so rust-toolchain.toml (1.100) is used
cargo install sqlx-cli --version 0.9.1 --no-default-features --features rustls,sqlite,postgres,sqlx-toml
# Docker is required for Postgres contract tests and the conformance suite
```

## Architecture Patterns

### Recommended Project Structure
```
Cargo.toml                    # virtual workspace, resolver = "3", [workspace.dependencies], [workspace.lints]
Cargo.lock                    # committed (binary project)
rust-toolchain.toml           # channel = "1.100.0", components rustfmt+clippy, profile minimal
.cargo/config.toml            # [env] SQLX_OFFLINE = "true"  (not forced; prepare overrides it)
deny.toml
justfile
scripts/
  check-deps.sh               # FND-02 (with --self-test)
  measure-idle.sh             # FND-04 RSS/size report
crates/
  anvil-core/                 # pure; M0: domain types for Tenant/AuthorizationCode/ids (serde, time, uuid, thiserror)
  anvil-jose/                 # empty skeleton lib.rs
  anvil-storage/              # traits + StorageError + src/contract/ (feature "contract")
  anvil-storage-sqlite/       # sqlx.toml, .sqlx/, migrations/, build.rs, src/, tests/contract.rs
  anvil-storage-postgres/     # sqlx.toml, .sqlx/, migrations/, build.rs, src/, tests/contract.rs
  anvil-cache/                # empty skeleton
  anvil-web/                  # axum router: discovery, healthz, embedded assets (rust-embed)
  anvil-mail/                 # empty skeleton
  anvilid/                    # binary: clap `serve`, mimalloc, wiring of concrete storage
themes/default/static/        # one real CSS file embedded by anvil-web (Spike B asset)
tests/conformance/
  compose.override.yml        # extra_hosts host-gateway for the suite server
  config-m0.json              # discoveryUrl etc.
  expected-failures-m0.json   # exact ratchet of current failures
  run.sh                      # local + CI driver
.github/workflows/
  ci.yml                      # PR + main: lint, deny, deps, test, sqlx-check
  release-build.yml           # main + workflow_dispatch (+ PR path filter optional): musl matrix, size+RSS
  conformance.yml             # main + workflow_dispatch (+ PRs during Phase 1)
```
Migrations: ARCHITECTURE §4/§7.3 says `migrations/sqlite/` and `migrations/postgres/`. Keep them **inside
each crate** (`crates/anvil-storage-sqlite/migrations/`). `sqlx::migrate!()` resolves paths relative to
`CARGO_MANIFEST_DIR`, and the crate stays self-contained. Flag the wording difference to the doc owner
rather than silently diverging (CLAUDE.md).

### Pattern 1: Workspace manifest skeleton
```toml
# Cargo.toml (root)
[workspace]
resolver = "3"                      # virtual manifests don't infer it from edition 2024; set explicitly
members = ["crates/*"]

[workspace.package]
edition = "2024"
rust-version = "1.100"              # = pinned toolchain (only version we test); sqlx floor is 1.94
license = "MIT"
publish = false

[workspace.lints.rust]
unsafe_code = "deny"
[workspace.lints.clippy]
all = { level = "warn", priority = -1 }   # CI turns warnings into errors with -D warnings

[workspace.dependencies]
anvil-core    = { path = "crates/anvil-core" }
anvil-storage = { path = "crates/anvil-storage" }
# ... (one entry per internal crate)
tokio      = { version = "1.54", features = ["rt-multi-thread", "macros", "net", "signal", "sync", "time"] }
axum       = "0.8.9"
sqlx       = { version = "0.9.1", default-features = false, features = ["runtime-tokio", "tls-rustls-aws-lc-rs", "macros", "migrate", "sqlx-toml", "uuid", "time", "json"] }
aws-lc-rs  = "1.19"
mimalloc   = "0.1.52"
rust-embed = "8.14"
uuid       = { version = "1.29", features = ["v7", "serde"] }
time       = { version = "0.3.55", features = ["serde"] }
thiserror  = "2"
async-trait = "0.1.92"
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
clap       = { version = "4.6", features = ["derive", "env"] }
tracing    = "0.1.44"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
testcontainers-modules = { version = "0.15", default-features = false, features = ["postgres"] }
tempfile   = "3.27"

[profile.release]
lto = "fat"
codegen-units = 1
strip = true
panic = "abort"
```
Each member: `[lints] workspace = true`, `edition.workspace = true`, `license.workspace = true`, `publish.workspace = true`.

```toml
# rust-toolchain.toml
[toolchain]
channel = "1.100.0"
components = ["rustfmt", "clippy"]
profile = "minimal"
# Do not list musl targets here: every contributor would download them. CI/Alpine handles musl.
```

### Pattern 2: Per-crate sqlx configuration (the dual-backend key)
```toml
# crates/anvil-storage-sqlite/sqlx.toml
[common]
database-url-var = "ANVIL_SQLITE_DATABASE_URL"

[macros.preferred-crates]
date-time = "time"
```
```toml
# crates/anvil-storage-postgres/sqlx.toml
[common]
database-url-var = "ANVIL_PG_DATABASE_URL"

[macros.preferred-crates]
date-time = "time"
```
How it works (verified in `sqlx-macros-core-0.9.1/src/query/{mod.rs,metadata.rs}`):
- The macro loads `$CARGO_MANIFEST_DIR/sqlx.toml`, which needs the `sqlx-toml` feature. Without the
  feature, a present file is a hard error: "found config file … but the `sqlx-toml` feature was not
  enabled".
- If `SQLX_OFFLINE` is not true and the renamed URL var is set → live check against that DB.
- Otherwise it reads `query-<hash>.json` from `$SQLX_OFFLINE_DIR`, then `<crate>/.sqlx`, then
  `<workspace>/.sqlx`.
- `.env` files are read from the crate dir up to the workspace root. Outer files overwrite inner ones,
  and real env vars win over everything. **Do not rely on `.env`; use real env vars set by `just`.**

Prepare and check (per crate, never `--workspace`):
```bash
# just sqlx-prepare (requires a running dev Postgres and a migrated SQLite file)
export ANVIL_SQLITE_DATABASE_URL="sqlite://$PWD/target/sqlx/dev.db?mode=rwc"
export ANVIL_PG_DATABASE_URL="postgres://postgres:postgres@localhost:55432/anvil_dev"   # throwaway local container
(cd crates/anvil-storage-sqlite   && sqlx migrate run && cargo sqlx prepare)
(cd crates/anvil-storage-postgres && sqlx migrate run && cargo sqlx prepare)
# CI: same with `cargo sqlx prepare --check`
```
Why per crate: `cargo sqlx prepare --workspace` sets one `SQLX_OFFLINE_DIR=<root>/.sqlx` for the whole
`cargo check`, so both backends write into one directory. Files are named by the hash of the SQL text,
so a byte-identical query in both crates would collide. Non-workspace prepare writes `<crate>/.sqlx`
and only touches the current package (verified in `sqlx-cli-0.9.1/src/prepare.rs`).
Note: `cargo sqlx prepare --database-url X` exports `DATABASE_URL` to the child `cargo check`. With a
renamed var, the macros ignore that, so **export the renamed vars in the shell**.

### Pattern 3: Storage traits (Phase 1 subset only)
```rust
// crates/anvil-storage/src/lib.rs. Only what the spike implements exists (CLAUDE.md: no stubs)
#[async_trait::async_trait]
pub trait Storage: Send + Sync + 'static {
    fn tenants(&self) -> &dyn TenantRepo;
    fn grants(&self) -> &dyn GrantRepo;
}

#[async_trait::async_trait]
pub trait TenantRepo: Send + Sync {
    async fn create(&self, tenant: &NewTenant) -> Result<Tenant, StorageError>;          // Conflict on duplicate slug (unique index)
    async fn get(&self, id: TenantId) -> Result<Option<Tenant>, StorageError>;
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, StorageError>;   // tenant resolution: the only lookup without a TenantId
}

#[async_trait::async_trait]
pub trait GrantRepo: Send + Sync {
    async fn create_code(&self, tenant: TenantId, code: &NewAuthorizationCode) -> Result<(), StorageError>;
    async fn consume_code(&self, tenant: TenantId, code_hash: &CodeHash, now: OffsetDateTime)
        -> Result<ConsumeOutcome, StorageError>;
}

pub enum ConsumeOutcome {
    Consumed(AuthorizationCode),
    AlreadyConsumed { family_id: Option<TokenFamilyId> },  // always None in M0 (no tokens yet)
    NotFound,                                              // unknown, expired, or other tenant: caller maps all to invalid_grant
}
```
Leave `begin()`/`Tx` and the other repos out until M1 needs them. ARCHITECTURE §7.1 lists them, and
they get added incrementally.

### Pattern 4: Atomic consume_code (both dialects)
```sql
-- Postgres (anvil-storage-postgres)
UPDATE authorization_code
   SET consumed_at = $3
 WHERE tenant_id = $1 AND code_hash = $2
   AND consumed_at IS NULL AND expires_at > $3
RETURNING code_hash, tenant_id, client_id, redirect_uri, scope, code_challenge, nonce,
          token_family_id, expires_at, created_at

-- SQLite (anvil-storage-sqlite); explicit type/nullability overrides on BLOB/RETURNING columns
UPDATE authorization_code
   SET consumed_at = ?3
 WHERE tenant_id = ?1 AND code_hash = ?2
   AND consumed_at IS NULL AND expires_at > ?3
RETURNING code_hash        AS "code_hash!: Vec<u8>",
          tenant_id        AS "tenant_id!: uuid::Uuid",
          client_id        AS "client_id!",
          redirect_uri     AS "redirect_uri!",
          scope            AS "scope!",
          code_challenge   AS "code_challenge!",
          nonce,
          token_family_id  AS "token_family_id: uuid::Uuid",
          expires_at       AS "expires_at!",
          created_at       AS "created_at!"
```
If zero rows are returned, run a follow-up diagnostic read:
`SELECT consumed_at, token_family_id FROM authorization_code WHERE tenant_id=? AND code_hash=?`.
If the row exists and `consumed_at IS NOT NULL`, return `AlreadyConsumed`. Otherwise return `NotFound`.
The race is decided by the single UPDATE. The follow-up only classifies the loser, so it does not
weaken atomicity.

Why it's atomic:
- **Postgres** (READ COMMITTED): concurrent UPDATEs on the same row block on the row lock. The waiter
  then re-evaluates the WHERE clause against the committed row (`consumed_at IS NULL` is now false),
  so it updates 0 rows.
- **SQLite**: all writes go through the single writer connection, and a statement is atomic.

### Pattern 5: Type mapping table
| Domain (anvil-core) | Postgres column → Rust | SQLite STRICT column → Rust |
|---|---|---|
| `TenantId(Uuid)` etc. | `uuid` → `uuid::Uuid` (inferred) | `BLOB` → infers `Vec<u8>`. Override `AS "id: uuid::Uuid"`. Binds of `Uuid` encode as 16-byte BLOB |
| `CodeHash([u8; 32])` | `bytea` → `Vec<u8>` | `BLOB` → `Vec<u8>` |
| timestamps (`OffsetDateTime`) | `timestamptz` → `time::OffsetDateTime` (session TZ is UTC by default) | `INTEGER` (unix ms) → `i64`. Convert in a small `ms_to_odt`/`odt_to_ms` helper |
| JSON (later) | `jsonb` → `sqlx::types::Json<T>` / `serde_json::Value` | `TEXT` → `String` + serde |
| optional | nullable column → `Option<T>` | Nullable → `Option<T>`. SQLite inference is fragile, so use `"col!"` / `"col?"` overrides explicitly |

Precision: Postgres stores microseconds, SQLite (our schema) milliseconds, `OffsetDateTime` nanoseconds.
**The contract is millisecond precision.** Truncate `now` to whole milliseconds in the tests and in the
clock implementation. Otherwise round-trip equality tests fail on one backend only.

### Pattern 6: SQLite pools (writer + readers) and the in-memory variant
```rust
let base = SqliteConnectOptions::from_str(url)?          // e.g. "sqlite:///data/anvil.db"
    .create_if_missing(true)
    .journal_mode(SqliteJournalMode::Wal)
    .synchronous(SqliteSynchronous::Normal)
    .busy_timeout(Duration::from_secs(5))
    .foreign_keys(true);                                 // sqlx default is ON; set explicitly anyway
let writer = SqlitePoolOptions::new().max_connections(1).connect_with(base.clone()).await?;
let reader = SqlitePoolOptions::new().max_connections(n).connect_with(base.read_only(true)).await?;
sqlx::migrate!().run(&writer).await?;                    // migrations always on the writer
```
In-memory: `sqlite::memory:` parses to a **shared-cache named in-memory DB**
(`file:sqlx-in-memory-{seq}`, verified in `sqlx-sqlite/src/options/parse.rs`). Shared-cache mode uses
table-level locks that return `SQLITE_LOCKED`, which `busy_timeout` doesn't cover, and the database
disappears when its last connection closes. For the memory variant, **use one pool of exactly one
connection as both writer and reader**, with `min_connections(1)`, `idle_timeout(None)` and
`max_lifetime(None)`.

### Pattern 7: Contract suite as a macro (recommended over generic fns + manual wiring)
```rust
// crates/anvil-storage/src/contract/mod.rs   (compiled only with feature "contract")
pub struct TestStorage {
    pub storage: std::sync::Arc<dyn crate::Storage>,
    pub _guard: Box<dyn std::any::Any + Send + Sync>,   // TempDir, PG database handle, etc.
}
pub async fn tenant_create_and_get(s: &TestStorage) { /* asserts */ }
pub async fn tenant_slug_conflict(s: &TestStorage) { /* Conflict, never check-then-insert */ }
pub async fn consume_code_once(s: &TestStorage) { /* Consumed, then AlreadyConsumed */ }
pub async fn consume_code_expired(s: &TestStorage) { /* NotFound */ }
pub async fn consume_code_wrong_tenant(s: &TestStorage) { /* NotFound, and code still consumable by owner */ }
pub async fn consume_code_concurrent_single_winner(s: &TestStorage) { /* see Pattern 8 */ }

#[macro_export]
macro_rules! storage_contract_tests {
    ($factory:path) => {
        $crate::storage_contract_tests!(@each $factory;
            tenant_create_and_get, tenant_slug_conflict, consume_code_once,
            consume_code_expired, consume_code_wrong_tenant,
            consume_code_concurrent_single_winner);
    };
    (@each $factory:path; $($name:ident),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $name() {
                let s = $factory().await;
                $crate::contract::$name(&s).await;
            }
        )+
    };
}
```
```rust
// crates/anvil-storage-sqlite/tests/contract.rs
mod memory { anvil_storage::storage_contract_tests!(crate::support::sqlite_memory); }
mod file   { anvil_storage::storage_contract_tests!(crate::support::sqlite_file); }
// crates/anvil-storage-postgres/tests/contract.rs
anvil_storage::storage_contract_tests!(support::postgres);
```
Backend crates enable it only as a dev-dependency:
`[dev-dependencies] anvil-storage = { workspace = true, features = ["contract"] }` plus `tokio`.
With resolver 3, dev-dependency features don't leak into normal builds, so the `contract` module never
ships in the binary (CLAUDE.md: test code stays out of production paths). The test list lives in one
place, so a backend can't silently skip a test.

### Pattern 8: Concurrency test (exactly one winner)
```rust
pub async fn consume_code_concurrent_single_winner(s: &TestStorage) {
    const N: usize = 32;
    for _round in 0..10 {                                   // repeat to raise confidence
        let (tenant, hash) = seed_tenant_and_code(s).await;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(N));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..N {
            let (st, b, h) = (s.storage.clone(), barrier.clone(), hash.clone());
            set.spawn(async move { b.wait().await; st.grants().consume_code(tenant, &h, now_ms()).await });
        }
        let (mut won, mut lost) = (0, 0);
        while let Some(r) = set.join_next().await {
            match r.expect("task panicked").expect("no storage errors allowed (e.g. SQLITE_BUSY)") {
                ConsumeOutcome::Consumed(_) => won += 1,
                ConsumeOutcome::AlreadyConsumed { .. } => lost += 1,
                ConsumeOutcome::NotFound => panic!("code must be found"),
            }
        }
        assert_eq!((won, lost), (1, N - 1));
    }
}
```
- Postgres: the pool must allow real overlap. Use `max_connections >= N` for the test pool, and start
  the container with `-c max_connections=500` because many test pools share one server.
- SQLite: the test runs against the production configuration (one writer). It proves the contract at
  the API level, and no SQLite *errors* may surface. Do not "strengthen" it with a multi-writer pool.
  WAL plus several writers can return `SQLITE_BUSY`/`BUSY_SNAPSHOT` that `busy_timeout` doesn't always
  retry, which is exactly why the architecture mandates a single writer. (MEDIUM confidence on the
  exact SQLite busy semantics. The single-writer recommendation is HIGH.)

### Pattern 9: Postgres test container: one per test binary, a fresh database per test
```rust
// crates/anvil-storage-postgres/tests/support/mod.rs
use testcontainers_modules::{postgres::Postgres, testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt}};
static PG: tokio::sync::OnceCell<(ContainerAsync<Postgres>, String /*admin url*/)> = tokio::sync::OnceCell::const_new();

pub async fn postgres() -> TestStorage {
    let (_, admin_url) = PG.get_or_init(|| async {
        let c = Postgres::default().with_tag("18-alpine")
            .with_cmd(["postgres", "-c", "max_connections=500"])
            .start().await.expect("docker must be running for Postgres contract tests");
        let url = format!("postgres://postgres:postgres@{}:{}/postgres",
            c.get_host().await.unwrap(), c.get_host_port_ipv4(5432).await.unwrap());
        (c, url)
    }).await;
    // CREATE DATABASE test_<uuid simple> on an admin connection to "postgres" (never template1),
    // connect, run sqlx::migrate!(), return TestStorage { storage, _guard: drop-handle }
    todo!()
}
```
- Run the Postgres contract tests with **`cargo test`**, not nextest. nextest runs each test in its
  own process, which defeats the per-binary `OnceCell` and starts one container per test.
- The `static` container is never dropped, so it outlives the test process. In CI the VM is discarded.
  Locally, add `just clean-test-containers`
  (`docker ps -aq --filter label=org.testcontainers=true | xargs -r docker rm -f`; verify the label
  name on first run).
- `testcontainers-modules` default features enable `ring` (bollard TLS). Use `default-features = false`.
  Verified: with that setting, `ring` is absent from the graph and `cargo deny check bans` passes.

### Pattern 10: Migrations embedding and rebuilds
- `sqlx::migrate!()` (default `./migrations` relative to the crate) embeds SQL at compile time.
- Add `build.rs` with `println!("cargo:rerun-if-changed=migrations");`. Without it, editing a
  migration does not trigger a rebuild. This is sqlx's documented pattern (`sqlx migrate build-script`).
- SQLite migrations: `CREATE TABLE … ( … ) STRICT;`, `PRAGMA foreign_keys` is set per connection by
  options (not in migrations).

### Pattern 11: Binary for Spikes B and C
- `anvilid serve --listen 0.0.0.0:9090 --issuer <url> --database-url <sqlite url>` opens storage, runs
  migrations, and serves:
  - `GET /.well-known/openid-configuration`: a real document generated from the issuer.
  - `GET /healthz`
  - `GET /assets/{path}`: rust-embed from `themes/default/static/`.
  - Every advertised-but-unimplemented endpoint (`/authorize`, `/token`, `/jwks`) returns
    **`501 Not Implemented`** with an explicit JSON error. This follows CLAUDE.md ("unimplemented
    features return an explicit error"). Never return an empty-success placeholder.
- mimalloc in `anvilid/src/main.rs`: `#[global_allocator] static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;`
  (safe code, compatible with `unsafe_code = "deny"`). Use it on all targets so tests exercise the
  shipped allocator.
- rust-embed: `#[derive(rust_embed::Embed)] #[folder = "../../themes/default/static/"] struct Assets;`
  (relative to the crate dir). Release builds embed. Debug builds read from disk.
- aws-lc-rs must be linked for a real reason. The ETag for embedded assets is
  `aws_lc_rs::digest::SHA256` (a real feature), and sqlx's rustls TLS provider for Postgres also links it.

### Pattern 12: Static musl build (native per arch, Alpine container)
```yaml
# .github/workflows/release-build.yml (excerpt)
jobs:
  musl:
    strategy:
      matrix:
        include:
          - { runner: ubuntu-24.04,     target: x86_64-unknown-linux-musl }
          - { runner: ubuntu-24.04-arm, target: aarch64-unknown-linux-musl }
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v7
      - name: Build static binary
        run: |
          TOOLCHAIN=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
          docker run --rm -u "$(id -u):$(id -g)" -e CARGO_HOME=/src/.cargo-home \
            -e RUSTUP_TOOLCHAIN="$TOOLCHAIN" \
            -v "$PWD":/src -w /src "rust:${TOOLCHAIN}-alpine" \
            sh -c 'cargo build --release --locked -p anvilid --target ${{ matrix.target }}'
      # Verified: rust:1.100-alpine preinstalls musl-dev and gcc (no apk needed, so non-root works).
      # RUSTUP_TOOLCHAIN overrides rust-toolchain.toml so rustup doesn't download the rustfmt/clippy
      # components listed there (the image ships only cargo/rustc/rust-std).
      - run: file target/${{ matrix.target }}/release/anvilid   # must say "static-pie linked" / "statically linked"
      - run: scripts/measure-idle.sh target/${{ matrix.target }}/release/anvilid ${{ matrix.target }}
      - uses: actions/upload-artifact@v7
        with: { name: anvilid-${{ matrix.target }}, path: target/${{ matrix.target }}/release/anvilid }
```
Verified locally (x86_64): `rust:1.100-alpine` + `cargo build --release --target
x86_64-unknown-linux-musl` gives an `ELF 64-bit LSB pie executable, static-pie linked, stripped`. Always
pass `--target` explicitly in Alpine. Otherwise target settings apply to host artifacts too
(proc-macros), and you get "cannot produce proc-macro" errors.

### Pattern 13: Idle memory and size measurement
```bash
# scripts/measure-idle.sh BIN TARGET
DATA=$(mktemp -d)
cd "$DATA"                                  # run outside the repo: proves assets are embedded, not read from disk
"$BIN" serve --listen 127.0.0.1:9090 --issuer http://127.0.0.1:9090 \
  --database-url "sqlite://$DATA/anvil.db?mode=rwc" & PID=$!
for i in $(seq 50); do curl -fsS http://127.0.0.1:9090/healthz >/dev/null && break; sleep 0.2; done
curl -fsS http://127.0.0.1:9090/.well-known/openid-configuration >/dev/null
curl -fsS http://127.0.0.1:9090/assets/anvil.css | sha256sum   # compare with repo file hash
sleep 5
RSS=$(awk '/^VmRSS/{print $2}' /proc/$PID/status); HWM=$(awk '/^VmHWM/{print $2}' /proc/$PID/status)
PSS=$(awk '/^Pss:/{print $2}' /proc/$PID/smaps_rollup); SIZE=$(stat -c %s "$BIN")
kill $PID
printf '| %s | %s bytes | VmRSS %s kB | VmHWM %s kB | Pss %s kB |\n' "$TARGET" "$SIZE" "$RSS" "$HWM" "$PSS" >> "$GITHUB_STEP_SUMMARY"
```
- Report **VmRSS** (headline), **VmHWM** (peak during startup) and **Pss**. Also write a JSON artifact
  so later phases can track regressions.
- Probe numbers (x86_64, 12-core host): VmRSS 9100 kB, Pss 9340 kB, binary 3,504,240 bytes. tokio
  starts one worker per core. Runners have 4 vCPU, so expect similar or lower numbers.

### Pattern 14: Conformance pipeline (Spike C)
```yaml
# .github/workflows/conformance.yml (excerpt), runs on ubuntu-24.04 (amd64)
env:
  CONFORMANCE_TAG: release-v5.3.5
steps:
  - uses: actions/checkout@v7
  - uses: Swatinem/rust-cache@v2
  - run: cargo build --locked -p anvilid            # gnu debug build is fine here
  - name: Fetch suite (scripts + compose) at the pinned tag
    run: |
      git clone --depth 1 --branch "$CONFORMANCE_TAG" --filter=blob:none --sparse \
        https://gitlab.com/openid/conformance-suite.git suite
      git -C suite sparse-checkout set scripts
      git -C suite sparse-checkout add /docker-compose-prebuilt.yml
  - name: Start suite
    run: |
      IMAGE_TAG=$CONFORMANCE_TAG docker compose -p conformance \
        -f suite/docker-compose-prebuilt.yml -f tests/conformance/compose.override.yml up -d
  - name: Start a fresh anvilid
    run: |
      ./target/debug/anvilid serve --listen 0.0.0.0:9090 \
        --issuer http://host.docker.internal:9090 --database-url "sqlite::memory:" > anvilid.log 2>&1 &
      for i in $(seq 50); do curl -fsS http://127.0.0.1:9090/.well-known/openid-configuration && break; sleep 0.2; done
  - uses: actions/setup-python@v7
    with: { python-version: "3.12" }
  - run: pip install -r suite/scripts/requirements.txt          # httpx, pyparsing
  - name: Run Config OP plan (pipeline proof)
    env:
      CONFORMANCE_SERVER: https://localhost.emobix.co.uk:8443/
      CONFORMANCE_DEV_MODE: "1"                                  # dev profile: no API token, TLS verify off
    run: |
      python3 suite/scripts/run-test-plan.py --verbose \
        --expected-failures-file tests/conformance/expected-failures-m0.json \
        --export-dir conformance-results \
        oidcc-config-certification-test-plan tests/conformance/config-m0.json
  - if: always()
    run: docker compose -p conformance logs --no-color > suite.log; cat anvilid.log
  - if: always()
    uses: actions/upload-artifact@v7
    with: { name: conformance-results, path: "conformance-results\nsuite.log\nanvilid.log" }
```
```yaml
# tests/conformance/compose.override.yml
services:
  server:
    extra_hosts:
      - "host.docker.internal:host-gateway"   # suite server → binary listening on the runner (0.0.0.0:9090)
```
```json
// tests/conformance/config-m0.json  (no secrets; placeholder static client)
{ "description": "anvilid M0 pipeline proof",
  "server": { "discoveryUrl": "http://host.docker.internal:9090/.well-known/openid-configuration" },
  "client": { "client_id": "m0-placeholder", "client_secret": "m0-placeholder" } }
```
- **What failure looks like:** the discovery module reaches FINISHED with result FAILED. Expected
  failing conditions include `CheckDiscEndpointAllEndpointsAreHttps` (http issuer) and `FetchServerKeys`
  (JWKS returns 501, and this is `callAndStopOnFailure`, so the rest of the module stops there).
  Possibly also schema/`userinfo_endpoint` warnings. Bootstrap the expected-failures file from the
  first run's `--verbose` output, which prints a JSON template. Entry format, as used upstream:
  `{"test-name","variant","configuration-filename","current-block","condition","expected-result":"failure"|"warning","comment"}`.
- **Ratchet semantics** (verified in `run-test-plan.py`): exit 1 if the module did not complete, if
  there are unexpected failures/warnings, **or if an expected failure did not happen**. Phase 2 shrinks
  the file to empty for Basic and Config OP.
- **Networking:** the suite's own outbound requests to the binary go from the `server` container to
  `host.docker.internal` (host-gateway → runner). The binary must bind `0.0.0.0`. The issuer must
  equal the URL prefix the suite fetches. The runner reaches the suite API through port 8443, mapped
  from nginx, at `localhost.emobix.co.uk` → 127.0.0.1.
- Startup: the JVM + Mongo take tens of seconds. `run-test-plan.py` already polls `api/plan?length=1`
  for up to 360 s.
- Phase 2 will need HTTPS on the issuer: the Basic OP browser automation and the https checks. Plan
  for TLS (rustls) or a TLS sidecar then. Not needed now.

### Pattern 15: Dependency-rule checker
```bash
#!/usr/bin/env bash
# scripts/check-deps.sh: FND-02. Uses per-package feature resolution (cargo tree -p), not unified metadata.
set -euo pipefail
deps_of() { cargo tree --locked -q -p "$1" -e normal,build --target all --prefix none --format '{p}' | awk '{print $1}' | sort -u; }
direct_of() { cargo tree --locked -q -p "$1" -e normal --depth 1 --prefix none --format '{p}' | awk 'NR>1{print $1}' | sort -u; }
fail=0
forbid() { local crate=$1; shift; local all; all=$(deps_of "$crate")
  for bad in "$@"; do grep -qx "$bad" <<<"$all" && { echo "RULE VIOLATION: $crate depends (transitively) on $bad"; fail=1; }; done; }
allow_direct() { local crate=$1; shift; for d in $(direct_of "$crate"); do
  printf '%s\n' "$@" | grep -qx "$d" || { echo "RULE VIOLATION: $crate has non-allowlisted direct dependency $d"; fail=1; }; done; }

IO="tokio mio hyper axum tower reqwest sqlx sqlx-core libsqlite3-sys tokio-postgres"
STORE_IMPLS="anvil-storage-sqlite anvil-storage-postgres"
allow_direct anvil-core anvil-jose serde serde_json time uuid url thiserror
forbid anvil-core $IO $STORE_IMPLS anvil-storage anvil-web anvil-cache anvil-mail
forbid anvil-storage sqlx sqlx-core $STORE_IMPLS anvil-web          # traits crate stays driver-free
forbid anvil-web $STORE_IMPLS sqlx sqlx-core
for s in $STORE_IMPLS; do forbid "$s" anvil-web; done
for c in anvil-jose anvil-cache anvil-mail anvil-web; do forbid "$c" $STORE_IMPLS; done   # only anvilid knows impls
exit $fail
```
Self-test (CI step, also `just deps-selftest`): copy the workspace (minus `target/`) into a temp dir.
Run `cargo add --offline -p anvil-core tokio` and assert that `check-deps.sh` exits non-zero. Repeat
with `cargo add --offline -p anvil-web anvil-storage-sqlite --path …`. Offline works because both
crates are already in `Cargo.lock`. This is the "CI fails a PR that adds…" proof for success criterion 2.

### Pattern 16: cargo-deny config (current format: no `version` keys; template from `cargo deny init`)
```toml
[graph]
targets = ["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
           "aarch64-apple-darwin", "x86_64-apple-darwin"]
all-features = false

[advisories]
yanked = "deny"
# unmaintained defaults to "workspace" scope since 0.22.0, so transitive unmaintained crates won't fail CI

[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause",
         "ISC", "Unicode-3.0", "Zlib", "CDLA-Permissive-2.0", "BSL-1.0", "MIT-0", "CC0-1.0", "Unlicense"]
confidence-threshold = 0.9

[bans]
multiple-versions = "warn"
wildcards = "deny"
allow-wildcard-paths = true          # internal path deps have no version; publish = false makes this apply
deny = [
  { crate = "openssl",     reason = "single crypto backend: aws-lc-rs" },
  { crate = "openssl-sys", reason = "single crypto backend: aws-lc-rs" },
  { crate = "native-tls",  reason = "rustls only" },
  { crate = "ring",        reason = "single crypto backend: aws-lc-rs (not currently in graph; if it becomes unavoidable, use wrappers = [..] and document)" },
  { crate = "rsa",         reason = "RUSTSEC-2023-0071 (Marvin), no fix" },
  { crate = "chrono",      reason = "time crate only" },
  { crate = "samael",      reason = "C XML security libs" },
  { crate = "xmlsec",      reason = "C XML security libs" },
  { crate = "oxide-auth",  reason = "dormant; we own the OAuth state machine" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```
Verified on the probe graph (sqlx 0.9.1 sqlite+postgres+rustls-aws-lc-rs, axum, aws-lc-rs, mimalloc,
rust-embed, clap, tracing, testcontainers-modules without default features): `bans ok`, `licenses ok`.
`ring` and `chrono` appear in `Cargo.lock` as optional entries but are **not** in the resolved graph.
aws-lc-sys is licensed `ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND …`,
which is covered by the list. webpki-roots is `CDLA-Permissive-2.0`.

### Pattern 17: One-command entry point (`just`)
```make
# justfile
set shell := ["bash", "-euo", "pipefail", "-c"]

default: ci
ci: fmt-check lint deny deps test           # what a contributor runs; needs Docker for Postgres tests

fmt-check:
    cargo fmt --all --check
lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings
deny:
    cargo deny --locked check
deps:
    scripts/check-deps.sh
deps-selftest:
    scripts/check-deps.sh --self-test
test:
    cargo test --workspace --locked
sqlx-prepare: db-up
    # exports ANVIL_*_DATABASE_URL, migrates, runs per-crate prepare (Pattern 2)
sqlx-check: db-up
    # same, with --check
db-up:
    # docker run -d --name anvil-dev-pg -p 55432:5432 -e POSTGRES_PASSWORD=postgres postgres:18-alpine (idempotent)
musl:
    # docker run rust:<pin>-alpine … (Pattern 12) for the host arch
conformance:
    tests/conformance/run.sh
```
CI calls the same recipes (`just lint`, `just test`, …) so local and CI cannot drift. The README
documents `just ci` and the tool prerequisites.

### CI workflow layout (ci.yml, on `pull_request` + `push: main`)
| Job | Runner | Steps |
|---|---|---|
| lint | ubuntu-24.04 | `rustup toolchain install` (reads rust-toolchain.toml); rust-cache; `just fmt-check lint` (SQLX_OFFLINE from `.cargo/config.toml`) |
| deny | ubuntu-24.04 | `EmbarkStudios/cargo-deny-action@v2` with `command: check` |
| deps | ubuntu-24.04 | `just deps deps-selftest` |
| test | ubuntu-24.04 | rust-cache; `just test` (Docker on the runner serves testcontainers) |
| sqlx-check | ubuntu-24.04 | install sqlx-cli 0.9.1; `just sqlx-check` (fails if `.sqlx/` is stale in either crate) |
`release-build.yml` (musl matrix, Pattern 12/13) and `conformance.yml` (Pattern 14) run on `push: main`
and `workflow_dispatch`. During Phase 1 they should also run on PRs that touch `crates/**`,
`tests/conformance/**`, `.github/**` or `Cargo.*`, so the spikes are proven before merge. ARCHITECTURE
§17 puts them on main at minimum.

### Anti-Patterns to Avoid
- **`cargo sqlx prepare --workspace` with two backends:** one shared `.sqlx/` with hash-name collisions on identical SQL. Prepare per crate.
- **Relying on `.env` for per-crate URLs:** the outer `.env` overwrites the inner one, and shell env overrides both. Use `sqlx.toml` `database-url-var` plus explicit env vars.
- **`sqlx` with default features:** pulls `any` (banned by architecture), and `tls-rustls` means ring.
- **Direct `testcontainers = "0.28"` next to `testcontainers-modules = "0.15"`:** two incompatible crate versions.
- **Multi-connection writer pool for SQLite:** busy/snapshot errors under contention. Single writer only.
- **Check-then-act for consume or create:** atomic UPDATE…RETURNING and unique indexes only.
- **Placeholder success responses** (`{"keys":[]}`, a fake token): use explicit 501s (CLAUDE.md).
- **Listing musl targets in rust-toolchain.toml:** taxes every contributor.
- **`SQLX_OFFLINE_DIR` set globally:** it takes precedence over per-crate `.sqlx/` and breaks the layout.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Driving the conformance suite | Custom REST client for `/api/plan`, `/api/runner`, `/api/info` | `scripts/run-test-plan.py` from the pinned tag | Handles server readiness, retries, variants, expected-failure/skip ratchet, export. Used by the suite's own CI |
| Running the conformance suite | Building it from source with Maven | Prebuilt `registry.gitlab.com/openid/conformance-suite[:/nginx]:release-vX` + `docker-compose-prebuilt.yml` | Saves a Maven + JDK build in CI; tags match git tags |
| Postgres lifecycle in tests | `docker run` shell glue inside tests | `testcontainers-modules` `Postgres` (+ `with_tag`, `with_cmd`) | Wait strategy for the double "ready" log line, port mapping, cleanup |
| Migrations | Custom migration runner/table | `sqlx::migrate!()` + `build.rs` rerun hint | Embedded, checksummed, works with both drivers |
| Offline query checking | Committing generated code | `.sqlx/` via `cargo sqlx prepare` + `--check` in CI | Official mechanism; CI detects staleness |
| Static linking / cross toolchains | Hand-built musl cross-gcc | `rust:<pin>-alpine` on native runners | Native musl gcc; verified static-pie output |
| License/advisory/ban policy | grep over Cargo.lock | cargo-deny | Feature-aware graph, RustSec DB |
| Asset embedding | `include_bytes!` tables | rust-embed 8.14 | Directory walk, MIME, debug-from-disk |

**Key insight:** every M0 risk (dialect drift, static linking, conformance automation) already has
upstream tooling. The spike's job is to wire those tools together correctly and measure them, not to
build alternatives.

## Common Pitfalls

### Pitfall 1: The wrong DATABASE_URL reaches the wrong crate
**What goes wrong:** the Postgres crate's `query!` is checked against SQLite (or the reverse). Errors
look like "no database driver found matching URL scheme".
**Why it happens:** the default `DATABASE_URL` is global to the compile.
**How to avoid:** per-crate `sqlx.toml` `database-url-var` and the `sqlx-toml` feature on. CI builds use
`SQLX_OFFLINE=true` (`.cargo/config.toml` `[env]`).
**Warning signs:** build succeeds locally only with certain env vars exported.

### Pitfall 2: sqlx-cli 0.8 used against 0.9 code
**What goes wrong:** prepare ignores `sqlx.toml`, or offline files mismatch.
**How to avoid:** sqlx-cli **0.9.1** (local is 0.8.6). Pin the version in CI and README. Note
`cargo install --locked sqlx-cli` doesn't work as expected since 0.9 (no lockfile in the crate). Use a
plain install with `--version 0.9.1`.

### Pitfall 3: SQLite nullability inference on RETURNING / BLOB columns
**What goes wrong:** columns come back as `Option<Vec<u8>>`, or as the wrong type.
**How to avoid:** always annotate RETURNING/SELECT columns: `AS "col!: uuid::Uuid"`, `AS "col!"`,
`AS "col?"`. Bind-parameter nullability is never compile-checked (sqlx 0.9.1 changelog #4345).

### Pitfall 4: In-memory SQLite vanishes or locks
**What goes wrong:** data disappears between test steps, or "database table is locked" errors appear.
**How to avoid:** one connection, `min_connections(1)`, no idle timeout or max lifetime, shared as
writer and reader (Pattern 6).

### Pitfall 5: Timestamp precision mismatch between backends
**What goes wrong:** a round-trip equality test passes on SQLite and fails on Postgres, or the reverse.
**How to avoid:** the contract is millisecond precision. Tests and the clock truncate to ms.

### Pitfall 6: Concurrency test that doesn't actually overlap
**What goes wrong:** the test passes trivially because tasks serialize on pool acquisition. Or it
fails with "too many clients" on the shared container.
**How to avoid:** Barrier + JoinSet on a multi-thread runtime; PG pool ≥ N; container
`max_connections=500`; repeat rounds; assert zero errors.

### Pitfall 7: testcontainers defaults
**What goes wrong:** Postgres 11 by default (module `TAG = "11-alpine"`). The `ring` feature drags
ring into the graph. nextest spawns one container per test.
**How to avoid:** `.with_tag("18-alpine")`, `default-features = false`, `cargo test` for these suites.

### Pitfall 8: Feature-unification false positives in the dep checker
**What goes wrong:** `cargo metadata` shows anvil-core depending on crates it doesn't use, because the
resolve is workspace-unified.
**How to avoid:** use `cargo tree -p <crate> -e normal,build --target all` (verified per-package resolution).

### Pitfall 9: Alpine/musl build gotchas
**What goes wrong:** proc-macro build errors, root-owned `target/` on the runner, missing `musl-dev`.
**How to avoid:** always `--target <arch>-unknown-linux-musl`; run as `-u $(id -u):$(id -g)` with
`CARGO_HOME` inside the workspace (or chown afterwards). `musl-dev` and `gcc` are preinstalled in
`rust:1.100-alpine` (verified). The image ships only cargo/rustc/rust-std, so set
`RUSTUP_TOOLCHAIN=<pin>`. Otherwise rustup tries to install the rustfmt/clippy components from
`rust-toolchain.toml`. Derive the image tag from `rust-toolchain.toml`.
**Warning signs:** `file` output says "dynamically linked".

### Pitfall 10: Conformance networking and issuer mismatch
**What goes wrong:** the suite can't reach the binary (it bound 127.0.0.1, or host-gateway is missing),
or the issuer check fails because the issuer doesn't match the fetched URL.
**How to avoid:** bind `0.0.0.0`; `extra_hosts: host.docker.internal:host-gateway` on `server`; issuer
= `http://host.docker.internal:9090` in M0. Pin `IMAGE_TAG` and the script git tag to the **same**
release.

### Pitfall 11: Expected-failures file drift
**What goes wrong:** CI goes red after an *improvement*, because an expected failure didn't happen.
**How to avoid:** that is intended ratchet behavior. Update the file in the same PR. Keep it small and
commented.

### Pitfall 12: cargo-deny install fails locally
**What goes wrong:** `cargo install cargo-deny` 0.22.1 needs rustc ≥ 1.95. The machine default stable
is 1.94.1.
**How to avoid:** run the install inside the repo (rust-toolchain.toml → 1.100), or use prebuilt
binaries. CI uses the action.

### Pitfall 13: wildcards = "deny" vs internal path deps
**What goes wrong:** cargo-deny flags `anvil-core = { path = … }` as a wildcard.
**How to avoid:** `allow-wildcard-paths = true` + `publish = false` on all members.

### Pitfall 14: rustup auto-install on CI
**What goes wrong:** the toolchain from `rust-toolchain.toml` isn't installed (rustup 1.28.0 behavior;
1.28.1 restored auto-install).
**How to avoid:** an explicit `rustup toolchain install` step (no args = read rust-toolchain.toml)
before cargo.

## Code Examples

### Millisecond timestamp helpers (SQLite crate)
```rust
// Source: time 0.3 API (OffsetDateTime::unix_timestamp_nanos / from_unix_timestamp_nanos)
fn odt_to_ms(t: OffsetDateTime) -> i64 { (t.unix_timestamp_nanos() / 1_000_000) as i64 }
fn ms_to_odt(ms: i64) -> Result<OffsetDateTime, StorageError> {
    OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000).map_err(|e| StorageError::Corrupt(e.to_string()))
}
```

### SQLite schema (spike scope)
```sql
CREATE TABLE tenant (
  id           BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  slug         TEXT    NOT NULL UNIQUE,
  display_name TEXT    NOT NULL,
  created_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE authorization_code (
  code_hash       BLOB    NOT NULL PRIMARY KEY CHECK (length(code_hash) = 32),
  tenant_id       BLOB    NOT NULL REFERENCES tenant(id),
  client_id       TEXT    NOT NULL,
  redirect_uri    TEXT    NOT NULL,
  scope           TEXT    NOT NULL,
  code_challenge  TEXT    NOT NULL,
  nonce           TEXT,
  token_family_id BLOB,
  expires_at      INTEGER NOT NULL,
  consumed_at     INTEGER,
  created_at      INTEGER NOT NULL
) STRICT;
```
Postgres equivalent: `uuid`, `bytea`, `text`, `timestamptz`. Add `jsonb` (`settings jsonb NOT NULL
DEFAULT '{}'`) on `tenant` so the Postgres type set (uuid/timestamptz/jsonb) is actually exercised.

### Recording the duplication cost (FND-03 deliverable)
Measure and record in the spike summary (and resolve D7 in ARCHITECTURE §20):
- LOC per backend: `src/` and `migrations/` (e.g. `wc -l` or `tokei`), split into SQL vs Rust glue.
- Number of `query!`/`query_as!` call sites per backend, and how many needed type/nullability overrides.
- Lines of backend-specific conversion code (ms↔OffsetDateTime, BLOB↔Uuid).
- Wall-clock effort to port the second backend after the first one passed the contract suite.
- Contract suite size (shared) vs backend-specific test glue.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| One global `DATABASE_URL` for sqlx macros | Per-crate `sqlx.toml` `[common] database-url-var` (feature `sqlx-toml`) | sqlx 0.9.0 (2026-05-06) | Makes the dual-backend workspace clean |
| `query("…".to_string())` | `query*()` take `impl SqlSafeStr`: `&'static str` or `AssertSqlSafe(..)` | sqlx 0.9.0 | SQLi-resistant by default; `query!` macros already use literals. Never use `AssertSqlSafe` without review |
| `sqlite` feature = bundled only | `sqlite` = bundled + deserialize + load-extension + unlock-notify; use `sqlite-bundled` | sqlx 0.9.0 | Pick the narrower feature |
| `Executor::execute("raw")` | `sqlx::raw_sql("…").execute(..)` | sqlx 0.9.0 | Use for PRAGMAs/DDL outside migrations |
| sqlx repo under launchbadge | `github.com/transact-rs/sqlx` | 2026 | Update links |
| cargo-deny `version = 2` opt-in keys | Not in the current `cargo deny init` template | ≤ 0.21/0.22 | Omit `version` keys |
| cargo-deny unmaintained = all | default `workspace` scope | 0.22.0 | Fewer transitive false alarms |
| Rust musl targets on musl 1.2.3 | musl 1.2.5 | Rust 1.93 | Not an issue with Alpine builds; note if a static link error appears |
| arm64 GitHub runners (preview) | `ubuntu-24.04-arm` GA for public repos | 2025-08-07 | Native arm64 builds and runs at no cost |

**Deprecated/outdated:**
- `cross` 0.2.5 (2023): use native runners.
- `tls-rustls` sqlx feature name: it means ring. Use `tls-rustls-aws-lc-rs`.
- `sqlx-cli` 0.8.x: incompatible with `sqlx.toml`.
- `cargo install --locked sqlx-cli`: the crate no longer ships a lockfile (0.9.0 note).

## Open Questions

1. **(Resolved during research) `rust:1.100-alpine` contents:** `musl-dev` and `gcc` are preinstalled,
   the default user is root, `/usr/local/rustup` and `/usr/local/cargo` are world-writable, and only
   cargo/rustc/rust-std are installed (no rustfmt/clippy). Non-root builds work. Set `RUSTUP_TOOLCHAIN`
   (Pattern 12).

2. **Exact failing conditions of the Config OP plan against the M0 binary.**
   - What we know: the module is `oidcc-discovery-endpoint-verification`. `FetchServerKeys` stops on failure. `CheckDiscEndpointAllEndpointsAreHttps` fails on http.
   - What's unclear: the precise condition list. A local execution attempt was blocked in this research session, so the pipeline is verified from source only.
   - Recommendation: plan an early task to run `tests/conformance/run.sh` once, capture the `--verbose` template, and commit it as `expected-failures-m0.json`.

3. **Does the Java suite fetch plain-http discovery URLs in dev mode without error before reaching the https checks?**
   - What we know: `GetDynamicServerConfiguration` is `callAndStopOnFailure`. The https check is a separate later condition.
   - What's unclear: whether http is rejected at fetch time. If it is, the run still *completes* (FAILED), which satisfies FND-05.
   - Recommendation: accept either outcome for M0. If the pipeline can't complete at all over http, put a self-signed TLS listener (rustls) in front for the conformance job. Never commit the key; generate it in a temp dir.

4. **Postgres version floor.**
   - What we know: 18-alpine and 19-alpine images exist. ARCHITECTURE doesn't state a minimum.
   - Recommendation: use 18 for M0 tests. Decide the supported floor (and a CI matrix) in Phase 2.

5. **Placement of migrations** (`crates/<crate>/migrations/` vs ARCHITECTURE's `migrations/sqlite/`).
   - Recommendation: in-crate. Raise a doc wording fix with the owner (CLAUDE.md: don't silently diverge).

6. **Discovery document advertising unimplemented endpoints.**
   - Tension: discovery must list `authorization_endpoint`/`token_endpoint`/`jwks_uri`, but those don't exist in M0.
   - Recommendation: advertise them and have each return an explicit 501 error. Document this in the spike summary as M0-only behavior that M1 replaces. If the doc owner prefers, the alternative is a minimal discovery (issuer + jwks_uri) with more expected failures.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness (`cargo test`) + `#[tokio::test]`; testcontainers-modules 0.15 for Postgres; shell checks for CI-only criteria |
| Config file | none (Wave 0 creates `Cargo.toml` workspace, `justfile`, `.cargo/config.toml`) |
| Quick run command | `cargo test --workspace --locked` (or `just test`) |
| Full suite command | `just ci` (fmt-check, clippy -D warnings, cargo deny, check-deps, all tests incl. Postgres via Docker) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FND-01 | Workspace builds/lints/tests with one command | smoke | `just ci` | ❌ Wave 0 (justfile, workspace) |
| FND-01 | CI runs fmt/clippy/deny/tests on PRs | CI config | `.github/workflows/ci.yml` jobs green on the PR that adds them | ❌ Wave 0 |
| FND-02 | Forbidden deps fail the check | unit-ish (script) | `just deps` (passes on clean tree) | ❌ |
| FND-02 | Checker rejects bad input (negative test) | negative | `just deps-selftest` (injects tokio into anvil-core and anvil-storage-sqlite into anvil-web; expects exit≠0) | ❌ |
| FND-03 | Tenant create/get/slug conflict, both backends | integration (contract) | `cargo test -p anvil-storage-sqlite --test contract` / `cargo test -p anvil-storage-postgres --test contract` | ❌ |
| FND-03 | consume_code once → Consumed then AlreadyConsumed; expired → NotFound | integration (contract) | same as above (`consume_code_once`, `consume_code_expired`) | ❌ |
| FND-03 | Tenant isolation (wrong tenant cannot consume) | negative (contract) | `consume_code_wrong_tenant` | ❌ |
| FND-03 | N parallel consumes → exactly one winner | concurrency (contract) | `consume_code_concurrent_single_winner` (SQLite memory, SQLite file, Postgres) | ❌ |
| FND-03 | `.sqlx/` offline data current for both crates | CI check | `just sqlx-check` | ❌ |
| FND-04 | Static musl binaries amd64+arm64 | CI build | `release-build.yml` matrix; `file` output asserts "static" (step fails otherwise) | ❌ |
| FND-04 | Embedded asset served from binary outside repo dir | smoke | `scripts/measure-idle.sh` compares sha256 of `/assets/anvil.css` with the repo file | ❌ |
| FND-04 | Size + idle RSS reported | CI report | `scripts/measure-idle.sh` → `$GITHUB_STEP_SUMMARY` + JSON artifact | ❌ |
| FND-05 | Suite runs end to end against fresh binary | e2e (CI) | `tests/conformance/run.sh` → `run-test-plan.py … --expected-failures-file tests/conformance/expected-failures-m0.json` exits 0 | ❌ |
| (support) | Discovery doc generated from issuer; unimplemented endpoints return 501 | integration | `cargo test -p anvil-web` (in-process router tests) | ❌ |

### Sampling Rate
- **Per task commit:** `cargo test --workspace --locked` (+ `cargo clippy --workspace --all-targets -- -D warnings` for code tasks)
- **Per wave merge:** `just ci`
- **Phase gate:** `just ci` green locally; ci.yml, release-build.yml and conformance.yml green on GitHub; spike summaries (duplication cost, size/RSS table, conformance artifact) recorded before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] Root `Cargo.toml` (virtual workspace, resolver 3, workspace deps/lints), `rust-toolchain.toml`, `.cargo/config.toml`, `Cargo.lock`
- [ ] 9 crate skeletons per §4 (empty `lib.rs` for anvil-jose, anvil-cache, anvil-mail)
- [ ] `justfile` with `ci`, `test`, `lint`, `fmt-check`, `deny`, `deps`, `deps-selftest`, `sqlx-prepare`, `sqlx-check`, `db-up`, `musl`, `conformance`
- [ ] `deny.toml`, `scripts/check-deps.sh`
- [ ] `crates/anvil-storage/src/contract/` + feature `contract`; `crates/anvil-storage-{sqlite,postgres}/tests/{contract.rs,support/mod.rs}`
- [ ] Per-crate `sqlx.toml`, `migrations/`, `build.rs`, `.sqlx/`
- [ ] Tool installs: just 1.59, sqlx-cli 0.9.1 (replace local 0.8.6), cargo-deny ≥0.21 (0.22.1 in CI)
- [ ] `tests/conformance/{run.sh,compose.override.yml,config-m0.json,expected-failures-m0.json}`; `scripts/measure-idle.sh`
- [ ] `.gitignore`: `target/`, `suite/`, `mongo/`, `conformance-results/`, `*.db`, `.cargo-home/`

## Sources

### Primary (HIGH confidence)
- crates.io API (queried 2026-11-25): versions and `rust_version` for sqlx/sqlx-core/sqlx-sqlite/sqlx-postgres 0.9.1 (MSRV 1.94.0), aws-lc-rs 1.19.0, aws-lc-sys 0.47.0, testcontainers 0.28.0 / 0.27.3, testcontainers-modules 0.15.0, mimalloc 0.1.52, rust-embed 8.14.0, tokio 1.54.1, axum 0.8.9, cargo-deny 0.22.1 (MSRV 1.95.0), libsqlite3-sys 0.40.0, just 1.59.0, cargo_metadata 0.23.1
- `https://static.rust-lang.org/dist/channel-rust-stable.toml`: stable = 1.100.0 (2026-11-09)
- sqlx 0.9.1 crate sources (downloaded): `Cargo.toml` features, `CHANGELOG.md` (0.9.0/0.9.1), `sqlx-core/src/config/reference.toml`, `sqlx-macros-core/src/query/{mod.rs,metadata.rs}`, `sqlx-cli/src/prepare.rs`, `sqlx-cli/src/opt.rs`, `sqlx-sqlite/src/types/uuid.rs`, `sqlx-sqlite/src/options/{parse.rs,mod.rs}`
- testcontainers 0.27.3/0.28.0 and testcontainers-modules 0.15.0 sources: features, re-export, postgres default tag, `ReuseDirective`
- aws-lc-sys 0.47.0 sources (builder/main.rs pre-generated bindings for musl) and https://aws.github.io/aws-lc-rs/requirements/linux.html, https://aws.github.io/aws-lc-rs/platform_support.html
- OpenID conformance suite repo (GitLab API + raw files at master and tag release-v5.3.5): `docker-compose-prebuilt.yml`, `Dockerfile`, `scripts/run-test-plan.py`, `scripts/conformance.py`, `scripts/requirements.txt`, `.gitlab-ci/run-tests.sh`, `OIDCCConfigTestPlan.java`, `OIDCCDiscoveryEndpointVerification.java`, `.gitlab-ci/expected-failures-oidcc.json`; registry tag listing (release-v5.3.5 for server and nginx)
- actions/runner-images readmes (Ubuntu2404 and Ubuntu2404-Arm64, image 20261116): Docker 28.0.4, Compose 2.38.2, Python 3.12.3
- **Local empirical verification (this session):** probe workspace resolved with sqlx sqlite+postgres+rustls-aws-lc-rs etc.: `cargo tree -i ring` empty in the resolved graph; `cargo deny check bans` and `licenses` ok; `rust:1.100-alpine` musl release build → static-pie, 3,504,240 bytes, 1m53s; idle VmRSS 9100 kB / Pss 9340 kB; `cargo tree -p` vs `cargo metadata` feature-unification difference demonstrated

### Secondary (MEDIUM confidence)
- [GitHub changelog: arm64 hosted runners for public repositories GA (2025-08-07)](https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/)
- [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Rustup 1.28.0 announcement](https://blog.rust-lang.org/2025/03/02/Rustup-1.28.0/), [Rustup 1.28.1](https://blog.rust-lang.org/2025/03/04/Rustup-1.28.1/), [Rustup 1.28.2](https://blog.rust-lang.org/2025/05/05/Rustup-1.28.2/)
- [Updating Rust's Linux musl targets to 1.2.5](https://blog.rust-lang.org/2025/12/05/Updating-musl-1.2.5)
- cargo-deny CHANGELOG (main branch) for 0.18–0.22 changes; `cargo deny init` template (v0.21.0 local)
- [sqlx 0.9 announcement discussion](https://github.com/transact-rs/sqlx/discussions/4271)
- [sqlx issue #1923 (UPDATE … RETURNING nullability workaround)](https://github-redirect.dependabot.com/launchbadge/sqlx/issues/1923)

### Tertiary (LOW confidence, validate during execution)
- SQLite WAL multi-writer `SQLITE_BUSY_SNAPSHOT` behavior under autocommit (reasoning from SQLite semantics; it does not change the recommendation)
- [reproducible-builds list post on aws-lc-sys static musl link failures (2026-04)](https://lists.reproducible-builds.org/pipermail/rb-general/2026-April/004086.html): unconfirmed. The Alpine probe did not reproduce it
- Conformance suite behavior with an http (non-TLS) discovery URL (Open Question 3)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH. Versions/MSRVs from crates.io; feature names from crate sources; banned-crate absence verified with cargo tree + cargo-deny.
- Architecture (sqlx dual backend, contract macro, CI layout): HIGH for sqlx mechanics (source-verified), MEDIUM for the exact testcontainers sharing pattern (API verified, not executed).
- Static build: HIGH for x86_64 (built and run locally); MEDIUM for aarch64 (same image/toolchain on a native arm runner, aws-lc docs list full support, not executed).
- Conformance pipeline: MEDIUM. Images, compose file, driver script, plan contents and exit semantics verified from source at the pinned tag; end-to-end run not executed (local attempt blocked by permissions).
- Pitfalls: HIGH for sqlx/testcontainers/cargo-tree items (source or empirical); MEDIUM for SQLite busy semantics and Alpine user/permission details.

**Research date:** 2026-11-25
**Valid until:** 2026-12-25 (fast-moving items: conformance suite releases roughly every 2–4 weeks, Rust stable every 6 weeks; re-check tags/versions when planning starts)
