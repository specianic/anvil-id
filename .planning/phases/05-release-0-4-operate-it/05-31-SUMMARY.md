---
phase: 05-release-0-4-operate-it
plan: 31
subsystem: crypto, binary, deploy
tags: [hmac, anvil-jose, limiter, outbound, ssrf, shutdown, webhooks, compose, gap-closure]

requires:
  - phase: 05-14
    provides: webhook delivery worker, WEBHOOK_TIMEOUT, policy/webhook_event.rs
  - phase: 05-16
    provides: Redis limiter key hasher (RATELIMIT_KEY_INFO)
  - phase: 05-20
    provides: tenant export/plan/apply CLI (duplicated outbound setup)
provides:
  - "anvil_jose::hmac_sha256(key, parts): the one HMAC-SHA-256 of the workspace (RFC 4231 cases 2 and 6)"
  - "startup::outbound_client: the one config -> OutboundClient builder (serve + tenant CLI)"
  - "JOBS_SHUTDOWN_TIMEOUT = WEBHOOK_TIMEOUT + 5 s (20 s); Compose stop_grace_period 40 s"
affects: [05-28]

tech-stack:
  added: []
  patterns:
    - "Keyed SHA-256 MACs go through anvil_jose::hmac_sha256; tests keep aws-lc-rs as an independent oracle"
    - "Shutdown budgets are derived from the timeouts they must cover (const arithmetic + unit test)"

key-files:
  created:
    - crates/anvil-jose/src/hmac.rs
  modified:
    - crates/anvil-jose/src/lib.rs
    - crates/anvil-jose/src/email_code.rs
    - crates/anvil-jose/src/recovery_code.rs
    - crates/anvil-jose/src/webhook.rs
    - crates/anvilid/src/limiter.rs
    - crates/anvilid/src/startup.rs
    - crates/anvilid/src/tenant_config.rs
    - crates/anvilid/src/config.rs
    - crates/anvilid/src/main.rs
    - crates/anvil-web/src/state.rs
    - crates/anvil-core/src/policy/webhook_event.rs
    - deploy/compose/postgres/compose.yml
    - deploy/compose/ha/compose.yml
    - deploy/README.md
    - docs/OPERATIONS.md

key-decisions:
  - "hmac_sha256 takes message parts (&[&[u8]]) so multi-update callers (email code, webhook signature) keep their exact byte order without concatenating"
  - "JOBS_SHUTDOWN_TIMEOUT is derived from WEBHOOK_TIMEOUT (+5 s margin), not a literal"
  - "Helm unchanged: its 40 s grace with a 10 s drain already covers drain + 20 s jobs"

requirements-completed: [OPS-03, OPS-09, ADM-05, ADM-06]

duration: ~25min
completed: 2026-11-26
---

# Phase 5 Plan 31: Binary and crypto hygiene Summary

**One HMAC-SHA-256 (`anvil_jose::hmac_sha256`) for rate-limit keys, email codes, recovery codes and webhook signatures, every output byte-identical to before; one outbound-client builder shared by `serve` and the tenant CLI; a jobs shutdown timeout long enough for a webhook request, with Compose grace periods to match.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-11-26
- **Tasks:** 3/3
- **Files modified:** 16 (1 created)

## Accomplishments

- `crates/anvil-jose/src/hmac.rs`: `pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32]` (aws-lc-rs), re-exported from
  lib.rs. Tests: RFC 4231 test case 2 (moved from limiter.rs, same name), test case 6 (131-byte key), multi-part == concatenated.
- email_code, recovery_code and webhook call it with the same bytes in the same order. Their tests were not changed: they
  still compute expectations with `aws_lc_rs::hmac` directly, and the Standard Webhooks spec vector still passes.
- limiter.rs `key_hasher` is `anvil_jose::hmac_sha256(secret, &[bytes])` with the zeroizing derived secret in the closure;
  `sha256_suite`, the `OkmBlock`/`SupportedCipherSuite`/`Tls13CipherSuite` imports and the TLS-provider doc paragraph are
  gone. `key_hasher_is_hmac_under_the_derived_ratelimit_key` now compares against `anvil_jose::hmac_sha256`.
- `startup::outbound_client(cfg, &mut app_config)` holds the allow-list/CA/allow_http logic; `start` and
  `tenant_config::service` call it (tenant_config keeps its `insecure_http` assignment first). Two unit tests (dev mode with
  an explicit list -> that list + plain http; production -> empty list, https only, no extra CA).
- Stale notes: the config.rs redis note points to `limiter::build_limiter`, no dead_code allow on `redis_failure`; state.rs
  has no dead_code allow on `cimd_fetch_permits` (or `unknown_hosts`, see deviations); webhook_event.rs says `data.tenant` is
  the tenant id, with parameters renamed `tenant_id`.
- `JOBS_SHUTDOWN_TIMEOUT = WEBHOOK_TIMEOUT + JOBS_SHUTDOWN_MARGIN` (20 s), plus the unit test
  `jobs_shutdown_timeout_covers_a_webhook_request`. Compose `stop_grace_period` is 40 s in both files; deploy/README.md
  and OPERATIONS.md give the sizing rule (drain + 20 s + margin).

## Task Commits

1. **Task 1: One HMAC-SHA-256 in anvil-jose, used by the limiter**: `ed4155b` (feat)
2. **Task 2: Shared outbound client builder and stale comments**: `6c46526` (refactor)
3. **Task 3: Jobs shutdown timeout covers a webhook request**: `fc0eabd` (fix)

## Verification

- Byte identity: the email-code, recovery-code and webhook tests (unchanged aws-lc-rs oracles, Standard Webhooks spec
  vector `signature_matches_spec_test_vector`) are green. For the rate-limit key, a temporary test (run, then removed)
  compared the new `key_hasher` with the old rustls `hkdf_provider.hmac_sign` path for 16 KEKs x IPv4/IPv6 canonical keys:
  identical.
- `cargo test -p anvil-jose -p anvilid`: all green (104 anvil-jose unit tests, 54 anvilid bin tests, all anvilid
  integration tests incl. `tenant_config` and `serve`).
- anvil-web: `webhooks`, `security_webhooks`, `flow_email_code`, `security_email_code`, `flow_recovery`, `flow_mfa` green.
- `cargo test -p anvil-core --lib policy::webhook_event` green.
- `cargo clippy -p anvilid -p anvil-web -p anvil-core -p anvil-jose --all-targets -- -D warnings` clean.
- `scripts/check-deps.sh` OK, `--self-test` OK, `cargo deny check` OK (no new dependency; base64 and HMAC stay in anvil-jose).
- All of the plan's automated grep checks pass.

## Not run

- Full-workspace `just lint` (I ran clippy on the four touched crates instead), the Postgres backend tests, and the Compose
  smoke/HA runs (Docker). These are left for CI and the 05-28 gate.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Stale code] Removed the `unknown_hosts` dead_code allow in state.rs**
- **Found during:** Task 2
- **Issue:** `AppState::unknown_hosts` still had `#[allow(dead_code, reason = "pre-declared for 05-18")]` and an "unused
  until it lands" doc, but `crate::tenant` uses it. This is the same kind of stale note as `cimd_fetch_permits`, in a file
  this plan owns.
- **Fix:** Removed the allow and corrected the doc. Clippy is clean.
- **Files modified:** crates/anvil-web/src/state.rs
- **Commit:** 6c46526

**2. Unused import:** `tenant_config.rs` no longer imports `OutboundClient`. This follows directly from moving the builder.

No files outside files_modified were touched. Builds broke for a while because of other wave-8 plans' in-progress edits
(anvil-core `SecondFactorMethods.passkey`, anvil-web account_attributes). Both cleared on retry; I made no workaround.

## Next Phase Readiness

- The 05-31 rows of deferred-items.md (8, 11, 15, 17, and the timeout half of 18) are closed. The `security_webhooks.rs`
  map half of 18 stays with 05-28.

## Self-Check: PASSED
