---
phase: 03-release-0-2-secure-by-default
plan: 10
subsystem: signing-keys, token, jwks
tags: [key-rotation, jwks, es256, ed25519, id-token, at_hash, etag, audit]
requires:
  - phase: 03-01
    provides: anvil-jose Alg::{RS256, ES256, Ed25519}, generate(alg), token_hash(alg, value)
  - phase: 03-02
    provides: KeyRepo::{list, promote, delete_expired}, TenantSettings::effective_signing_algs, Client.id_token_signed_response_alg, AuditService, AuditAction::Key*
  - phase: 03-05/03-06
    provides: backends implementing promote/delete_expired and the client alg column
provides:
  - "service::key_rotation: RotationPolicy (90 d / 7 d / 1 h 5 min), JWKS_MAX_AGE (1 h), RETIRE_SKEW, KeyAction, plan_rotation (pure), enabled_algs(tenant), RotationReport"
  - "KeyRotationService { storage, kek, clock, policy }::{run_once, ensure_tenant(&Tenant), rotate_now(&Tenant, Alg, immediate, AuditActor)}"
  - "KeyService::signer_for(tenant, alg); signer(tenant) = RS256"
  - "service::tenant::seal_new_key_for(kek, tenant, alg, now, state); seal_new_key delegates (signature unchanged)"
  - "service::token::id_token_alg(tenant, client); family_id_token_input takes the ID-token alg for at_hash"
  - "/jwks: Cache-Control public, max-age=3600, strong ETag (quoted hex SHA-256 of the body), If-None-Match -> 304"
affects: [03-18, 03-21, 03-23, 03-24, 03-25]
tech-stack:
  added: []
  patterns:
    - "Rotation = pure planner + thin applier; concurrency handled by storage (active-key unique index, promote returns false on stale ids)"
    - "ID-token alg never falls back: unknown / not enabled / no active key -> server_error"
key-files:
  created:
    - crates/anvil-web/tests/jwks_rotation.rs
    - crates/anvil-web/tests/id_token_alg.rs
  modified:
    - crates/anvil-core/src/service/key_rotation.rs
    - crates/anvil-core/src/service/key.rs
    - crates/anvil-core/src/service/tenant.rs
    - crates/anvil-core/src/service/token.rs
    - crates/anvil-web/src/protocol/jwks.rs
    - crates/anvil-web/tests/discovery.rs
key-decisions:
  - "RotationPolicy defaults: period 90 d, prepublish 7 d, retire_grace = max(ID token TTL 1 h, AT TTL 10 min) + 5 min skew = 1 h 5 min; new() rejects prepublish < JWKS_MAX_AGE, period <= prepublish, and retire_grace below token lifetime + skew"
  - "rotate_now takes an AuditActor (admin API / CLI identify the requester); immediate=false is idempotent (returns the existing next key); immediate=true retires the old key with expires_at = now"
  - "Generate of an Active key that hits Conflict, a promote returning false or Conflict are 'another runner won' and count as no-ops; worst concurrent outcome is an extra Next key (removed by the 03-24 lease)"
  - "run_once collects per-tenant failures in RotationReport.failures (core has no logging); 03-24 logs them"
  - "If-None-Match uses RFC 9110 weak comparison (as assets.rs already does), our ETag is always strong"
patterns-established:
  - "Integration tests drive core services with a Frozen clock built from the harness clock per step (TestApp exposes no Arc<dyn Clock>)"
duration: 40min
completed: 2026-11-25
---

# Phase 3 Plan 10: Key rotation, multi-algorithm ID tokens and JWKS caching Summary

**A pure rotation planner with a KeyRotationService that rotates every tenant on a 90-day schedule with a 7-day JWKS prepublish and a 1 h 5 min retirement window. ID tokens are signed with the client's RS256, ES256 or Ed25519 key, with per-algorithm at_hash. /jwks is cached for 1 h with a strong ETag and answers 304 when it matches.**

## Performance

- **Duration:** about 40 min
- **Tasks:** 2
- **Files:** 8 (2 created, 6 modified)

## Accomplishments

- `plan_rotation(keys, algs, now, policy)` is pure. For each enabled algorithm: no active key → generate an active key. Active key at least `period − prepublish` old and no next key → generate a next key. Next key published at least `prepublish` and active key at least `period` old → promote (retire the active key with `expires_at = now + retire_grace`, then activate the next key). Then expired retired keys are deleted. Algorithms that are disabled are left alone, and an active key is never deleted. A 400-day simulation test checks that there is exactly one active key at all times and that no key signs before it has been published for `prepublish` (≥ `JWKS_MAX_AGE`).
- `KeyRotationService`:
  - `run_once` pages all tenants and audits `key_generated`, `key_activated` and `key_retired` with the system actor. A failure for one tenant is recorded in the report and does not stop the others.
  - `ensure_tenant` generates an active key for each enabled algorithm that has none.
  - `rotate_now` supports scheduled rotation or immediate rotation after a compromise, and audits `key_rotation_requested`.
- Token endpoint: the ID-token signer comes from `id_token_alg(tenant, client)` (the client's alg or RS256, and it must be enabled for the tenant) through `KeyService::signer_for`. `at_hash` uses `anvil_jose::token_hash(signer.alg(), ..)`. Access tokens stay RS256. The refresh grant uses the same alg.
- `/jwks` sends `Cache-Control: public, max-age=3600` (from the core `JWKS_MAX_AGE` constant, not `AppConfig`), a strong ETag, and returns 304 with an empty body when `If-None-Match` matches. The ETag changes after rotation.

## Policy defaults (for docs)

| Setting | Default | Constraint |
| --- | --- | --- |
| period | 90 days | > prepublish |
| prepublish | 7 days | ≥ JWKS max-age (1 h) |
| retire_grace | 1 h 5 min | ≥ max token TTL (ID token 1 h) + 5 min skew |
| JWKS max-age | 3600 s | core constant `JWKS_MAX_AGE` |

## EdDSA / Ed25519 interop note (for docs)

AnvilID uses the RFC 9864 fully-specified name: Ed25519 ID tokens have `"alg":"Ed25519"`, and the JWKS publishes `{"kty":"OKP","crv":"Ed25519","alg":"Ed25519"}`. `EdDSA` is never emitted or accepted (03-01). Relying-party libraries that only know `EdDSA` cannot verify these tokens. Those clients should keep the default RS256 (or use ES256) until their library supports RFC 9864. Ed25519 `at_hash` is the left half of SHA-512 (43 base64url characters).

## Task Commits

1. **Task 1: Pure rotation planner and KeyRotationService:** `a2eed50`
2. **Task 2: Per-client ID-token alg, per-alg at_hash, JWKS cache headers, integration tests:** `71b18b2`

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] discovery.rs asserted the old JWKS max-age**
- **Found during:** Task 2
- **Issue:** `tests/discovery.rs::jwks_lists_published_public_keys` asserted `public, max-age=300`. That file is not in files_modified, and the plan's verification runs `--test discovery`.
- **Fix:** Changed the one assertion to `max-age=3600`. No concurrent plan touches this file.
- **Commit:** 71b18b2

**2. [Rule 2 - Correctness] rotate_now takes an `AuditActor`**
- **Issue:** The plan signature `rotate_now(tenant, alg, immediate)` would always record the system actor, including for admin-initiated rotations.
- **Fix:** Added an `actor: AuditActor` parameter. 03-24 (CLI) passes `AuditActor::system()`; the admin API passes the admin.

**3. [Rule 1 - Spec] If-None-Match uses weak comparison**
- **Issue:** The plan says "strong comparison", but RFC 9110 §13.1.2 requires weak comparison for If-None-Match. `assets.rs` already does it that way (recorded in Phase 01).
- **Fix:** Weak comparison, with our own ETag always strong. `W/"<tag>"` and `*` also return 304.

**4. [Rule 2 - Correctness] RotationPolicy::new checks two more invariants**
- `period > prepublish` and `retire_grace ≥` longest token TTL + 5 min, in addition to `prepublish ≥ JWKS_MAX_AGE`.

### Notes / follow-ups

- `service/authorize.rs` (`id_token_hint`) still calls `verify_op_token` (RS256 only). A hint signed with ES256 or Ed25519 would be rejected. That file is not in this plan; the owner of authorize.rs or 03-18 should switch it to `verify_op_token_algs(.., &enabled_algs(tenant), ..)` (`enabled_algs` is in `service::key_rotation`).
- `jwks.rs` has its own small hex/If-None-Match helpers because `assets.rs` keeps them private and was outside files_modified. 03-22 touches assets.rs and could make them `pub(crate)` so jwks.rs can reuse them.
- 03-24: run `KeyRotationService::run_once` hourly under the job lease, log `RotationReport.failures`, call `ensure_tenant` at startup, and wire `keys rotate` to `rotate_now`.
- 03-21: call `ensure_tenant` when a tenant enables an algorithm.
- 03-18: publish `id_token_signing_alg_values_supported` from `enabled_algs`.
- TDD: each task's tests and implementation went into one commit.

## Issues Encountered

- Another plan's in-progress `ui/account_security.rs` broke the main-tree anvil-web lib build for clippy. Verified in the temporary worktree `target/wt-03-10` at 71b18b2 (removed afterwards): `cargo check --workspace --all-targets` clean; clippy `-D warnings` clean for anvil-core (all targets) and the anvil-web lib plus this plan's tests. In that worktree, the committed `tests/security_ratelimit.rs` (03-13) fails clippy (`cloned_ref_to_slice_refs`, lines 393-394). That is out of scope here.

## Verification

- `cargo test -p anvil-core`: 264 passed
- `cargo test -p anvil-web --lib --test jwks_rotation --test id_token_alg --test token --test token_client_credentials --test userinfo --test discovery` (SQLite): all pass
- Same suites with `ANVILID_TEST_DB=postgres`: all pass

## Self-Check: PASSED
