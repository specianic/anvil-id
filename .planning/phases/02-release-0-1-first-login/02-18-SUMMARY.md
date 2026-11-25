---
phase: 02-release-0-1-first-login
plan: 18
subsystem: binary-wiring
tags: [anvilid, cli, figment, config, kek, sqlite, postgres, rustls, tls, bootstrap, jobs, conformance]
requires:
  - phase: 02-10
    provides: BootstrapService (ensure_installed, new_setup_url)
  - phase: 02-11
    provides: OutboxWorker, SmtpTransport::from_url, EmailRenderer
  - phase: 02-12
    provides: anvil_web::app(AppConfig, AppDeps), Argon2Pool, breach_checker
  - phase: 02-13
    provides: discovery with RS256 + userinfo, JWKS from stored keys
  - phase: 02-15
    provides: /setup page
  - phase: 02-16
    provides: management API
  - phase: 02-22
    provides: sealed outbox payloads (one shared KEK)
provides:
  - "anvilid serve | migrate | config show | config validate | admin setup-url"
  - "Zero-config start: ./anvilid-data/{anvilid.db,kek (0600),serve.lock}, 127.0.0.1:8080, public_url http://localhost:8080, one-time `Setup URL:` log line"
  - "figment config: CLI > ANVILID_* env > anvilid.toml > defaults, per-key source report, secret redaction"
  - "Built-in TLS listener (--tls-cert/--tls-key; rustls + aws-lc-rs; ALPN h2/http1.1) with graceful shutdown"
  - "Background jobs: purge_expired every 5 min; outbox worker when smtp_url is set"
  - "anvil_web::AppConfig.insecure_http (dev cookie policy and banner on a plain-http non-loopback URL)"
  - "Conformance harness on the release 0.1 binary; ratchet = 7 http-only entries"
affects: [02-19, 02-20, 02-21, tests/e2e]
tech-stack:
  added: []
  patterns:
    - "Config layers kept as separate figment dicts; source = highest layer containing the key (no metadata parsing)"
    - "Secrets (kek, smtp_url) are env/file only, never CLI flags; resolved into SecretString"
    - "Startup order: scheme check -> data dir -> serve.lock -> KEK -> storage -> bootstrap -> router -> bind"
    - "One watch channel drives the HTTP server, TLS connections and both jobs on shutdown"
key-files:
  created:
    - crates/anvilid/src/config.rs
    - crates/anvilid/src/datadir.rs
    - crates/anvilid/src/startup.rs
    - crates/anvilid/src/server.rs
    - crates/anvilid/src/jobs.rs
    - crates/anvilid/tests/cli.rs
    - crates/anvilid/tests/zero_config.rs
  modified:
    - crates/anvilid/src/main.rs
    - crates/anvilid/src/storage.rs
    - crates/anvilid/tests/serve.rs
    - crates/anvil-web/src/lib.rs
    - crates/anvil-web/src/config.rs
    - tests/conformance/run.sh
    - tests/conformance/expected-failures-m0.json
    - tests/conformance/README.md
  deleted:
    - crates/anvil-web/src/discovery.rs
    - crates/anvil-web/src/not_implemented.rs
    - crates/anvil-web/tests/router.rs
key-decisions:
  - "Logs always go to stderr; stdout carries command output only (config show, admin setup-url). With json logs, the setup URL is also printed as a plain `Setup URL:` line on stdout"
  - "kek and smtp_url have no CLI flags (process list exposure); env or config file only"
  - "The serve lock is taken before the KEK can be generated, so two concurrent first starts cannot write two KEKs"
  - "Postgres never creates a data dir and never generates a KEK; an existing kek_file is accepted"
  - "admin setup-url refuses to run when the SQLite file does not exist (never creates an empty DB) and takes no lock and runs no migrations"
  - "An invalid smtp_url refuses startup; no smtp_url logs one warning and emails stay queued"
  - "Env values are read with figment extract_lossy so ANVILID_INSECURE_HTTP=1/true both work"
requirements-completed: []
requirements-addressed: [OPS-05, OPS-02, ADM-03, OIDC-08]
duration: 45min
completed: 2026-11-25
---

# Phase 2 Plan 18: Binary Wiring Summary

**`anvilid serve` now starts with zero configuration: SQLite in `./anvilid-data/`, a generated 0600 KEK, a serve lock and a one-time setup URL. It serves the full Phase 2 router over http or rustls TLS, runs the purge and outbox jobs, and shuts down cleanly. Configuration is layered with figment (CLI > env > toml > defaults), `config show` reports the source of each value and redacts secrets, and the conformance ratchet now matches the release 0.1 discovery.**

## Performance

- **Duration:** about 45 min
- **Completed:** 2026-11-25
- **Tasks:** 3
- **Files:** 7 created, 8 modified, 3 deleted

## Accomplishments

- `config.rs`: `CliOverrides` (clap, every field optional), `Layers` (cli/env/file dicts), `RawConfig` -> `Config::resolve` with validation (public_url scheme, plain http on a non-loopback host needs `--insecure-http`, listen, database scheme, TLS pair, breach_check, log_format, smtp scheme) and derived defaults (`sqlite://{data_dir}/anvilid.db`, `{data_dir}/kek`, `AnvilID <no-reply@{host}>`, pretty logs in dev mode and json otherwise). `show()` prints `key = value (source)` and redacts kek, smtp_url and database passwords (userinfo and `password` query params).
- `datadir.rs`: data dir 0700, KEK resolution (configured -> file -> generate 0600 / refuse for Postgres / refuse for setup-url), `serve.lock` via `File::try_lock`.
- `startup.rs`: data dir/lock/KEK -> `open_storage(url, migrate)` -> Argon2 pool (available_parallelism permits, OWASP params), breach checker, SystemClock -> `BootstrapService::ensure_installed` -> `anvil_web::app`. A single `Arc<Kek>` goes to the web layer and to the outbox worker.
- `server.rs`: plain `axum::serve`, or a TLS accept loop (`TlsAcceptor` + hyper-util auto builder + `TowerToHyperService`) with a handshake timeout, per-connection graceful shutdown and a 10 s drain.
- `jobs.rs`: purge loop every 5 min; `OutboxWorker::run` when smtp_url is set (`SmtpTransport::from_url` is built inside the runtime).
- Phase 1 router (`router(WebConfig)`, discovery.rs, not_implemented.rs, tests/router.rs) removed. `AppConfig.insecure_http` added (`dev_mode() = is_dev_mode || insecure_http`).

## Task Commits

1. **Task 1: config, CLI, data dir, KEK, lock, storage default**: `4b270d7` (feat)
2. **Task 2: startup, TLS server, jobs, Phase 1 router removal, zero-config tests**: `caf7a59` (feat)
3. **Task 3: conformance harness + ratchet refresh**: `617b88c` (test)

## Conformance ratchet diff

`just conformance` exits 0. `oidcc-discovery-endpoint-verification` now runs to the end (FINISHED, 23 SUCCESS, 7 FAILURE, all expected).

| Condition | Before | After |
|-----------|--------|-------|
| OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported | failure (ES256 only) | **removed** (RS256 advertised) |
| FetchServerKeys | failure (501 /jwks; module INTERRUPTED) | **removed** (JWKS serves keys) |
| CheckDiscEndpointUserinfoEndpoint | warning (absent) | failure (advertised but http) until 02-19 |
| CheckDiscEndpointAllEndpointsAreHttps | (not reached) | failure (http) until 02-19 |
| CheckDiscEndpointDiscoveryUrl, CheckDiscEndpointIssuerIsValidUrl, CheckDiscEndpointAuthorizationEndpoint, CheckDiscEndpointTokenEndpoint, CheckJwksUri | failure (http) | unchanged, until 02-19 |

No new non-http failures surfaced. No defects were found.

## Verification

- `cargo clippy --workspace --all-targets -- -D warnings`: clean (also with `--locked`)
- `cargo test --workspace`: 790 passed, 0 failed
- `ANVILID_TEST_DB=postgres cargo test -p anvil-web -p anvilid`: 298 passed, 0 failed
- `scripts/check-deps.sh`: dependency rules OK
- `just conformance`: exit 0 (Docker available locally)

## Deviations from Plan

### Design choices within scope

**1. Logs go to stderr rather than stdout**
- **Found during:** Task 2
- **Issue:** The plan assumed logs on stdout ("also print it to stderr when log_format is json"). The binary previously logged to stdout. That would mix log lines into `config show` and `admin setup-url` output.
- **Fix:** tracing writes to stderr (ANSI only on a terminal). With json logs, the plain `Setup URL:` line goes to **stdout**, so scripts can still grep it from either stream. The e2e `parseSetupUrl` regex matches the pretty line and the plain line.
- **Files:** crates/anvilid/src/main.rs, crates/anvilid/src/startup.rs

**2. One dev-mode warning instead of two**
- The web layer (`AppState::new`) already logs the development-mode warning, so the binary does not add its own. The zero-config test asserts the warning is present.

**3. `Config::dev_mode()` not added on the binary side**
- The binary passes `insecure_http` into `AppConfig`, and `AppConfig::dev_mode()` is the single definition.

### Auto-fixed Issues

None.

## Issues Encountered

- A first `ANVILID_TEST_DB=postgres` run, made while the conformance suite was also running, failed 7 userinfo tests in the shared Postgres test harness (`connect_admin` retries exhausted while the container started). A rerun on its own passed 298/298. This is load-related flakiness in the existing harness, not something this plan changed.

## Notes for downstream plans

- 02-19: switch `ANVILID_ARGS` to `--public-url https://host.docker.internal:$PORT --tls-cert … --tls-key …` (drop `--insecure-http`), then remove all 7 entries from `expected-failures-m0.json`.
- e2e (`tests/e2e`): start the binary with `--data-dir <tmp>` and grep `Setup URL:` from stderr (pretty) or stdout (json).

## Self-Check: PASSED
