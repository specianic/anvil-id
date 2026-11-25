---
phase: 03-release-0-2-secure-by-default
plan: 24
subsystem: binary
tags: [config, trusted-proxies, rate-limit, key-rotation, audit, jobs, job-lease, cli]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: "AuditMirror/install_mirror (03-02), LimiterConfig (03-07/03-13), TrustedProxies (03-08), KeyRotationService (03-10), outbox worker construction (03-15), Migrations (03-16), ensure_console_client (03-21)"
provides:
  - "Operator config keys: trusted_proxies, trusted_proxy_header, rate_limit_enabled, rate_limit_{auth_per_minute,token_per_second,token_client_per_second,admin_per_second,default_per_second}, key_rotation_days, audit_retention_days"
  - "Startup reconciliation: ensure_console_client(public_url) + KeyRotationService::ensure_tenant for every tenant"
  - "jobs.rs LeaseRunner: rotation 1 h, purge 5 min, audit retention 24 h under job_lease; outbox worker unchanged"
  - "`anvilid keys rotate [--tenant] [--alg] [--immediate]`"
  - "Audit JSON lines on stdout (dedicated tracing layer for target `audit`, independent of RUST_LOG)"
  - "startup::open_for_cli shared by `admin setup-url` and `keys rotate`"
affects: [03-25, 03-29, docs]
tech-stack:
  added: [ipnet (workspace dep, now also used by anvilid)]
  patterns:
    - "jobs.rs has no crate:: imports so tests/jobs.rs includes it with #[path]"
    - "Per-layer tracing filters: stderr layer = RUST_LOG minus target audit; stdout layer = target audit at info"
key-files:
  created:
    - crates/anvilid/src/keys.rs
    - crates/anvilid/tests/config_phase3.rs
    - crates/anvilid/tests/jobs.rs
    - crates/anvilid/tests/keys_cli.rs
  modified:
    - crates/anvilid/src/config.rs
    - crates/anvilid/src/startup.rs
    - crates/anvilid/src/main.rs
    - crates/anvilid/src/jobs.rs
    - crates/anvilid/Cargo.toml
    - Cargo.lock
decisions:
  - "Audit stdout lines are the raw event_json (one JSON object per line), not wrapped in a tracing JSON envelope; audit events never appear in the stderr log"
  - "key_rotation_days 1..3650; prepublish = min(7 d, period/2), at least the 1 h JWKS max-age; retire grace stays the default"
  - "audit_retention_days 0..36500, 0 = keep forever (no retention job scheduled)"
  - "Login quota burst = max(1, auth_per_minute / 2); per-second quotas burst = their count; a quota of 0 is rejected (use rate_limit_enabled = false)"
  - "trusted_proxies accepts CIDRs or single IPs (host routes), comma-separated or a TOML array; an explicit empty value trusts none even in dev mode; errors name the key and the entry position, never the value"
  - "Job leases are 15 min and released after each run; jobs are idempotent so a run longer than the lease can only cause duplicate work"
  - "keys rotate accepts RS256, ES256, Ed25519 (PS256 rejected at the CLI); the algorithm must be enabled for the tenant"
metrics:
  duration: 25min
  completed: 2026-11-25
---

# Phase 3 Plan 24: Binary wiring for Phase 3 Summary

**Operator configuration for trusted proxies, rate limits, key rotation and audit retention; startup reconciliation of the console client and signing keys; key rotation, purge and audit retention as background jobs under `job_lease`; `anvilid keys rotate`; and audit events streamed as raw JSON lines on stdout regardless of `RUST_LOG`.**

## What was built

### Configuration keys (for the docs)

All keys follow CLI flag > `ANVILID_<KEY>` env > `anvilid.toml` > default, and `config show` lists each one with its source.

| Key | CLI flag | Env | Default | Validation |
|-----|----------|-----|---------|------------|
| `trusted_proxies` | `--trusted-proxies` | `ANVILID_TRUSTED_PROXIES` | dev mode: `127.0.0.0/8, ::1/128`; otherwise none | Comma-separated string or TOML array of CIDRs or single IPs. Any invalid entry fails with `trusted_proxies: entry N is not an IP address or CIDR`. An empty value trusts none. |
| `trusted_proxy_header` | `--trusted-proxy-header` | `ANVILID_TRUSTED_PROXY_HEADER` | `x-forwarded-for` | `x-forwarded-for` or `forwarded` (case-insensitive) |
| `rate_limit_enabled` | `--rate-limit-enabled <BOOL>` | `ANVILID_RATE_LIMIT_ENABLED` | `true` | bool; `false` logs a warning on start |
| `rate_limit_auth_per_minute` | `--rate-limit-auth-per-minute` | `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE` | `10` (burst 5) | ≥ 1; burst = max(1, n/2) |
| `rate_limit_token_per_second` | `--rate-limit-token-per-second` | `ANVILID_RATE_LIMIT_TOKEN_PER_SECOND` | `50` | ≥ 1; burst = n |
| `rate_limit_token_client_per_second` | `--rate-limit-token-client-per-second` | `ANVILID_RATE_LIMIT_TOKEN_CLIENT_PER_SECOND` | `100` | ≥ 1; burst = n |
| `rate_limit_admin_per_second` | `--rate-limit-admin-per-second` | `ANVILID_RATE_LIMIT_ADMIN_PER_SECOND` | `20` | ≥ 1; burst = n |
| `rate_limit_default_per_second` | `--rate-limit-default-per-second` | `ANVILID_RATE_LIMIT_DEFAULT_PER_SECOND` | `50` | ≥ 1; burst = n |
| `key_rotation_days` | `--key-rotation-days` | `ANVILID_KEY_ROTATION_DAYS` | `90` | 1..=3650. Prepublish = min(7 d, period/2), never below 1 h. |
| `audit_retention_days` | `--audit-retention-days` | `ANVILID_AUDIT_RETENTION_DAYS` | `365` | 0..=36500; `0` keeps events forever |

Backoff settings (`free_attempts`, `base`, `cap`, `loose_threshold_per_hour`, `max_tracked_keys`) keep the `LimiterConfig::default` values and are not exposed as config keys.

### Startup (`startup.rs`)

The order is: `ensure_installed`, then `ensure_console_client(&cfg.public_url)`, then `ensure_signing_keys`. The last step pages through all tenants and calls `KeyRotationService::ensure_tenant` with the configured policy. A tenant that fails is logged at error level and does not stop startup. Startup then maps `trusted_proxies` and `rate_limits` onto `AppConfig`.

`open_for_cli(cfg)` holds the "existing database, no migrations, no lock, KEK must exist" logic that used to live in `admin setup-url`. Both CLI commands now use it.

### Audit stdout (`main.rs`)

- `TracingMirror` is installed through `install_mirror`. It emits `tracing::info!(target: "audit", event = %json)`.
- The `AuditStdout` layer has a per-layer filter `Targets(audit=info)` and writes the `event` field as one raw JSON line on stdout.
- The stderr layer uses the `RUST_LOG` filter (default `info`) with `target != audit` added, so audit events never reach stderr. With `RUST_LOG=warn`, the stdout audit lines still appear (tested).
- The JSON is `event_json`: typed fields only, with no secrets.

### Jobs (`jobs.rs`)

- `LeaseRunner { storage, clock, node_id, lease }`:
  - `run_once` does `try_lease(name, node, now+lease, now)`, then `run`, then `release`.
  - `schedule` waits a jitter of up to min(interval/10, 30 s), then runs on a tokio interval (`Delay` on missed ticks) until shutdown.
  - The node id is a random `node-<uuidv7>` per process.
- Jobs:
  - `RotationJob` runs `run_once`. It logs every `RotationReport.failures` entry at error level and logs a summary when anything changed.
  - `PurgeJob` runs `purge_expired`.
  - `AuditRetentionJob` runs `purge_before(now − retention)` and is only scheduled when retention is set.
- `JobIntervals::default()` is 1 h / 5 min / 24 h. Tests pass short intervals to `spawn_periodic`; production configuration has no switch for this.
- The outbox worker construction from 03-15 is kept unchanged.

### `anvilid keys rotate` (`keys.rs`)

- Flags: `--tenant <slug>` (default `default`), `--alg RS256|ES256|Ed25519` (default RS256), `--immediate`, plus all the usual config flags.
- It calls `rotate_now(..., AuditActor::system())`, which audits `key_rotation_requested`, and prints the kid that signs next.
- Errors exit non-zero: unknown tenant, an algorithm not enabled for the tenant, no installation yet.

### `config show` smoke (release binary)

Run with `ANVILID_TRUSTED_PROXIES="10.0.0.0/8, 192.168.0.0/16" anvilid config show --key-rotation-days 30`:

```
trusted_proxies = 10.0.0.0/8, 192.168.0.0/16 (env ANVILID_TRUSTED_PROXIES)
trusted_proxy_header = x-forwarded-for (default)
rate_limit_enabled = true (default)
rate_limit_auth_per_minute = 10 (default)
rate_limit_token_per_second = 50 (default)
rate_limit_token_client_per_second = 100 (default)
rate_limit_admin_per_second = 20 (default)
rate_limit_default_per_second = 50 (default)
key_rotation_days = 30 (cli --key-rotation-days)
audit_retention_days = 365 (default)
```

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | Configuration, startup reconciliation, audit JSON on stdout | 3d54783 |
| 2 | Leased jobs and `keys rotate` | 7714cd3 |

## Verification

- All verification ran in worktree `target/wt-03-24` with its own `CARGO_TARGET_DIR`, because 03-23's in-progress anvil-web edits broke the shared tree's build at the time. Both were removed afterwards.
- `cargo test -p anvilid`: all pass.
  - 32 unit tests (5 new config tests).
  - cli: 15. config_phase3: 5. jobs: 3. keys_cli: 2. serve: 6. zero_config: 1.
- `cargo clippy -p anvilid --all-targets -- -D warnings`: clean. `cargo fmt --check`: clean.
- `cargo build --release -p anvilid`: OK. The `config show` smoke output is above.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `crates/anvilid/Cargo.toml` + `Cargo.lock`: added `ipnet.workspace = true`**
- **Issue:** Building `TrustedProxies { cidrs: Vec<IpNet> }` from operator input requires the `ipnet` crate, which anvil-web does not re-export.
- **Fix:** Added the existing workspace dependency to anvilid. This is a one-line change in each file.
- **Commit:** 3d54783

**2. [Rule 2 - Correctness] `admin setup-url` logic moved into `startup::open_for_cli`**
- **Issue:** `keys rotate` needs the same storage/KEK opening. Copying it would create a second implementation of the same concern.
- **Fix:** Moved it into `open_for_cli`, which both commands call. Behaviour is unchanged, and the zero_config test (which covers `admin setup-url`) passes.
- **Commit:** 3d54783

### Notes

- Task 1 left `Config.audit_retention` unread until Task 2 wired the retention job. That caused one transient dead-code warning between the two commits. HEAD is clippy-clean.
- TDD: tests and implementation were written together in each task rather than as separate RED/GREEN commits. Every behaviour listed in the plan has a test.
- `JobsConfig` (defined in jobs.rs) replaced `&Config` as the input to `jobs::spawn`. This keeps jobs.rs free of `crate::` imports so tests/jobs.rs can include it with `#[path]`, since anvilid has no lib target.

## Next Phase Readiness

- 03-25 / docs: use the config table above. Audit stdout is one raw JSON object per line, interleaved with other command output only for `serve` in JSON log mode (the setup-URL line) and the `keys rotate` result line.
- `TenantService` still builds `KeyRotationService` with `RotationPolicy::default()` (it only calls `ensure_tenant`, which does not depend on the policy).

## Self-Check: PASSED
