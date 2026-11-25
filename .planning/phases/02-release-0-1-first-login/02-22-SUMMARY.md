---
phase: 02-release-0-1-first-login
plan: 22
subsystem: security
tags: [kek, aes-256-gcm, email-outbox, secrets-at-rest, gap-closure]
requires:
  - phase: 02-05
    provides: SQLite outbox + plaintext row inspection test
  - phase: 02-06
    provides: Postgres outbox + plaintext row inspection test
  - phase: 02-09
    provides: FlowService (verification/recovery/password-changed emails)
  - phase: 02-11
    provides: anvil-mail OutboxWorker
provides:
  - "anvil_core::model::{seal_payload, open_payload, OUTBOX_PAYLOAD_PURPOSE, SEALED_PAYLOAD_KEY}"
  - "FlowService.kek / UserService.kek / OutboxWorker.kek: Arc<Kek>"
  - "anvil_mail::worker::PAYLOAD_DECRYPT_ERROR"
affects: [02-15, 02-16, 02-18]
tech-stack:
  added: []
  patterns:
    - "Outbox payload = single {\"sealed\": b64url(Kek::seal(purpose, tenant id bytes, json))} entry; no plaintext fallback"
key-files:
  created: []
  modified:
    - crates/anvil-core/src/model/outbox.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/service/user.rs
    - crates/anvil-mail/src/worker.rs
    - crates/anvil-mail/tests/worker.rs
    - crates/anvil-mail/tests/support/mod.rs
    - crates/anvil-storage-sqlite/tests/plaintext.rs
    - crates/anvil-storage-postgres/tests/plaintext.rs
    - docs/ARCHITECTURE.md
key-decisions:
  - "Sealing happens in the builders (self_service_email, password_changed_email, build_invitation), so no NewEmail with a plaintext payload can be constructed by core services; build_invitation/build_user_plan now take &Kek and are fallible"
  - "Worker decrypt failures follow the normal failure/backoff path with last_error = \"payload could not be decrypted\" (an operator fixing the KEK lets the row succeed later); worker-local DeliveryError avoids touching MailError in lib.rs"
  - "Password-changed notices are sealed too (one rule: every outbox payload is sealed), even though they carry no token"
duration: 25min
completed: 2026-11-25
---

# Phase 2 Plan 22: Seal email outbox payloads at rest Summary

**Outbox template variables (verification, recovery and invitation links with single-use tokens) are sealed with the KEK envelope (AES-256-GCM, purpose `anvilid/outbox-payload/v1`, tenant-id AAD) when the email is built, and opened only by the outbox worker right before rendering.**

## Performance

- Duration: ~25 min
- Tasks: 2 (TDD; 3 commits)
- Files modified: 9

## Accomplishments

- `model/outbox.rs`: `seal_payload` / `open_payload`. `open_payload` accepts only a map of exactly one `sealed` entry; any failure (unsealed map, mixed map, bad base64, wrong KEK, wrong tenant, tampered ciphertext) yields the generic `CoreError::Internal("outbox payload could not be decrypted")` with no value echoed.
- `FlowService` and `UserService` gain `pub kek: Arc<Kek>`; every `NewEmail` they build is sealed (verification, recovery, password_changed, invitation).
- `OutboxWorker` gains `pub kek: Arc<Kek>`; a row that cannot be opened is marked failed with `PAYLOAD_DECRYPT_ERROR` and is never handed to the transport.
- SQLite and Postgres `secrets_never_stored_plaintext` seed a sealed email whose link carries a marker token and assert the marker, and any `token=` string, is absent from every column; positive controls check that the outbox row exists as a sealed envelope. A mutation check (storing the plaintext payload) made the SQLite test fail.
- ARCHITECTURE.md §6.2 has the new "Email outbox payloads" row.

## Downstream wiring (new constructor fields)

No code in `crates/anvil-web` or `crates/anvilid` constructs these types yet, so nothing broke. Wave-3 plans (02-15, 02-16) and binary wiring (02-18) must set:

| Type | New field | Pass |
|---|---|---|
| `anvil_core::service::flow::FlowService` | `kek: Arc<Kek>` | `AppState::kek_arc()` |
| `anvil_core::service::user::UserService` | `kek: Arc<Kek>` | `AppState::kek_arc()` |
| `anvil_mail::OutboxWorker` | `kek: Arc<Kek>` | the same KEK as the services (`AppState::kek_arc()`) |

Also changed: `build_invitation(kek, now, tenant, issuer, user_id, email) -> Result<Invitation, CoreError>` and `build_user_plan(kek, now, tenant, issuer, policy, input)`. Both services and the worker **must share one KEK**. With a different one, every email fails with "payload could not be decrypted".

## Task Commits

1. Task 1 RED: `460385c` test(02-22): add failing tests for sealed outbox payload helpers
2. Task 1 GREEN: `433a141` feat(02-22): seal email outbox payloads with the KEK at every construction site
3. Task 2: `5047e3a` feat(02-22): outbox worker opens sealed payloads; plaintext tests cover email links

## Deviations from Plan

None. The plan was executed as written. anvil-mail already depended directly on anvil-jose, so no manifest change was needed.

## Deferred Issues

- `cargo fmt --all -- --check` reports formatting drift in already-committed `crates/anvil-web` files (adapters/argon2.rs, cookies.rs, errors.rs, layers/csrf.rs, tenant.rs, tests/*). These files are outside this plan's scope and were left untouched. Owner: the anvil-web plans (02-12 follow-up).

## Verification

- `cargo test --workspace`: green (anvil-core 199 unit tests, anvil-mail 9 worker tests, both plaintext tests)
- `ANVILID_TEST_DB=postgres cargo test -p anvil-storage-postgres --test plaintext`: green (testcontainers)
- `cargo clippy -p anvil-core -p anvil-mail -p anvil-storage-sqlite -p anvil-storage-postgres --all-targets -- -D warnings`: clean

## Self-Check: PASSED
