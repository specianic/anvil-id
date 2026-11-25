---
phase: 03-release-0-2-secure-by-default
plan: 02
subsystem: core-domain-and-storage-contract
tags: [model, ports, audit, contract-tests, passkeys, totp, consent, keys]
requires:
  - phase: 02-release-0-1-first-login
    provides: intent-method storage ports, contract suite, TRANSITIONAL pending.rs pattern, sealed outbox payloads
provides:
  - Every Phase 3 domain type (credentials, consent, audit, mail settings, job names, client/session/tenant additions)
  - Every Phase 3 storage port method plus AuditRepo, MailSettingsRepo, JobRepo
  - Non-storage ports PasskeyCeremonies, EmailTemplateCheck, SmtpTester, AuditMirror
  - AuditService (record + query) with a process-wide JSON mirror hook
  - Shared contract tests for every new method, incl. four concurrency guarantees
  - TRANSITIONAL Unsupported shims on both backends
affects: [03-05, 03-06, 03-09, 03-10, 03-12, 03-13, 03-14, 03-15, 03-17, 03-21, 03-23, 03-24]
tech-stack:
  added: []
  patterns:
    - "Typed AuditDetails: built only from secret-free constructors; storage rebuilds with from_stored"
    - "Backends refuse non-default Phase 3 client/session values with Unsupported instead of dropping them"
    - "fixtures::race(n, f): barrier-released concurrency helper shared by contract tests"
key-files:
  created:
    - crates/anvil-core/src/model/{credential,consent,audit,mail_settings,job}.rs
    - crates/anvil-core/src/service/audit.rs
    - crates/anvil-core/src/service/{account,consent,introspect,key_rotation,mail_settings,revoke}.rs (doc only)
    - crates/anvil-core/src/flow/{settings,consent}.rs, crates/anvil-core/src/oauth/response_mode.rs (doc only)
    - crates/anvil-storage-{sqlite,postgres}/src/pending.rs
    - crates/anvil-storage/src/contract/{credentials,consent,audit,mail_settings,jobs,access_tokens}.rs
  modified:
    - crates/anvil-core/src/ports.rs
    - crates/anvil-core/src/error.rs
    - crates/anvil-core/src/model/{client,session,flow,grant,tenant,outbox,ids,mod}.rs
    - crates/anvil-core/src/flow/engine.rs, crates/anvil-core/src/service/flow.rs
    - crates/anvil-storage-{sqlite,postgres}/src/{lib,users,clients,sessions,grants,keys,flows}.rs
    - crates/anvil-storage/src/contract/{mod,fixtures,users,clients,sessions,keys,flows,tenants}.rs
key-decisions:
  - "Audit events are appended right after the state change commits (intent methods take no audit rows); an append failure is returned to the caller"
  - "anvil-core cannot depend on tracing: AuditService mirrors through a process-wide AuditMirror installed once (install_mirror); the binary's mirror emits tracing::info!(target: \"audit\") (03-24)"
  - "Open Question 2: Client.can_introspect lets a client introspect any tenant token; a confidential client may always introspect tokens issued to itself"
  - "Open Question 4: the access-token family pointer claim is the existing `fid`"
  - "Open Question 6: passkey amr = [hwk|swk by backup eligibility, user, mfa]; password+TOTP or recovery code = [pwd, otp, mfa]; both acr urn:anvilid:acr:mfa"
  - "complete_recovery takes Option<&RecoveryNotice>; storage addresses it to the consumed token's email inside the recovery transaction (SQLite via RETURNING, Postgres via a TRANSITIONAL runtime query)"
  - "KeyRepo::promote returns bool (false = stale/unknown ids, nothing changed); Conflict when a second active key would result"
  - "FlowState::initial returns Result: Settings/Consent flows are an explicit error until their plans implement them"
duration: 110min
completed: 2026-11-25
---

# Phase 3 Plan 02: Phase 3 domain model, ports, audit and storage contract Summary

**All Phase 3 types, storage and non-storage ports, AuditService with a JSON mirror hook, and 47 new shared contract tests (including the TOTP-step, recovery-code, passkey-counter and job-lease concurrency guarantees), with explicit Unsupported shims on both backends until 03-05/03-06**

## Performance

- **Duration:** about 110 min
- **Tasks:** 3
- **Files:** 68 planned plus 6 compile-fix files (see Deviations)

## Accomplishments

- Domain model: `CredentialKind`, `PasskeyCredential`/`NewPasskey`, `TotpCredential`/`NewTotp` (Debug-redacted), `CredentialSummary`, `RecoveryCodeHash`, `CounterOutcome`, `TOTP_SEED_PURPOSE`, `credential_aad`; `ConsentGrant`/`NewConsent`; `RequestContext` (UA truncated to 256 chars), `ActorKind`, `AuditActor`, `AuditOutcome`, `AuditAction` (41 variants incl. `passkey_clone_suspected`), `AuditDetails` (typed constructors only), `NewAuditEvent`, `AuditEvent`, `AuditQuery`; `EmailKind`, `EmailTemplate`, `SmtpTls`, `SmtpSettings` (redacted), `SMTP_PASSWORD_PURPOSE`; `JobName`; `TokenFormat`/`ConsentMode` and the client fields `token_format`, `consent_mode`, `id_token_signed_response_alg`, `can_introspect`; session `ip`/`user_agent`; `ACR_MFA`, `AMR_HWK/SWK/USER/OTP/MFA`; `FlowKind::{Settings, Consent}`; `RevokeReason::{ConsentRevoked, SessionRevoked, TokenRevoked}`; `AccessTokenRecord`/`NewAccessToken`; `TenantSettings.signing_algs` (default `["RS256"]`, `effective_signing_algs()` always includes RS256) and `captcha` (`CaptchaSettings`, `CaptchaProvider`, `CAPTCHA_SECRET_PURPOSE`). A unit test checks that tenant settings JSON written by 0.1 still parses.
- `CoreError::ConsentRequired` (`consent_required`, 400) and `CoreError::UnsupportedTokenType` (`unsupported_token_type`, 400) are in the single mapping table and its test.
- Pre-declared doc-only modules: `service::{account, consent, introspect, key_rotation, mail_settings, revoke}`, `flow::{settings, consent}`, `oauth::response_mode`.
- `AuditService { storage, clock }`: `record(...)` builds a UUIDv7 id and `at`, calls `storage.audit().append`, then mirrors `event_json`. `query(...)` normalises the limit with `admin_page`. A unit test checks that the mirrored `login_failed` JSON has exactly the typed keys.

### New port methods

- **UserRepo:** `list_credentials`, `create_passkey` (Conflict if the credential id exists anywhere in the tenant), `passkeys`, `find_passkey`, `update_passkey` → `CounterOutcome` (single conditional UPDATE; 0/0 accepted), `totp`, `create_totp` (one tx with the recovery-code set; Conflict on a second TOTP), `advance_totp_step` (CAS), `delete_credential` (TOTP takes its recovery codes with it; passwords cannot be deleted this way), `replace_recovery_codes`, `consume_recovery_code` (single UPDATE plus a notice only on success), `recovery_codes_remaining`. `complete_recovery(.., notice: Option<&RecoveryNotice>)`.
- **GrantRepo:** `create_family`, `create_access_token`, `find_access_token`, `revoke_access_token`, `consent`, `list_consents`, `upsert_consent` (scope union; a revoked grant is re-activated with exactly the new scopes), `revoke_consent` (one tx: grant plus families of (user, client), reason ConsentRevoked).
- **SessionRepo:** `get` (any state), `list_for_user` (active, newest first), `list` (tenant-wide, paged), `revoke_with_families`, `revoke_all_for_user(except)`.
- **KeyRepo:** `list`, `promote(retire, activate, now) -> bool` (two statements in order), `delete_expired`.
- **FlowRepo:** `swap_state` (compare-and-swap).
- **AuditRepo:** `append`, `query` (id DESC, `before` cursor), `purge_before` (installation-wide). **MailSettingsRepo:** `template`, `list_templates`, `put_template`, `delete_template`, `smtp`, `put_smtp`, `delete_smtp`. **JobRepo:** `try_lease`, `release`. **Storage:** `audit()`, `mail_settings()`, `jobs()`. The `purge_expired` docs now include opaque access tokens.
- **Non-storage ports:** `PasskeyCeremonies` (with `RelyingParty`, `PasskeyUser`, `Challenge`, `RegisteredPasskey`, `AssertionIdentity`, `VerifiedAssertion`, `PasskeyError`), `EmailTemplateCheck`/`TemplateIssue`, `SmtpTester`/`SmtpConnection` (SecretString password), `AuditMirror`. The dyn-compatibility test covers all of them.

### Contract tests added (registered in `storage_contract_tests!`)

`client_phase3_fields_round_trip`, `session_request_context_round_trip`, `recovery_notice_not_enqueued_for_invalid_token`, `passkey_create_list_find`, `passkey_duplicate_credential_id_conflicts`, `passkey_update_counter_compare_and_swap`, `passkey_concurrent_updates_never_move_counter_backwards`, `totp_create_get_and_conflict`, `totp_step_accepted_once`, `totp_step_concurrent_single_winner`, `recovery_code_consumed_once`, `recovery_code_concurrent_single_winner`, `recovery_code_notice_enqueued_only_on_success`, `delete_totp_removes_recovery_codes`, `delete_credential_only_own_and_never_password`, `list_credentials_summarises_every_kind`, `credentials_isolated_by_tenant`, `consent_upsert_unions_scopes`, `consent_revoked_is_ignored_and_reactivated`, `consent_revoke_revokes_only_that_clients_families`, `consent_isolated_by_tenant`, `access_token_create_find_with_and_without_family`, `access_token_found_in_any_state`, `access_token_revoke`, `create_family_without_code`, `key_list_returns_every_state`, `key_promote_retires_then_activates`, `key_promote_stale_ids_change_nothing`, `key_delete_expired_removes_only_expired_retired`, `session_get_in_any_state`, `session_list_for_user_active_newest_first`, `session_list_tenant_wide_paging`, `session_revoke_with_families_only_its_own`, `session_revoke_all_for_user_keeps_except`, `flow_swap_state_compare_and_swap`, `flow_swap_state_concurrent_single_winner`, `audit_append_and_query_newest_first`, `audit_query_filters`, `audit_cursor_pages_without_gaps`, `audit_isolated_by_tenant`, `audit_purge_before_deletes_only_older`, `mail_template_put_get_list_delete`, `mail_smtp_put_get_delete`, `mail_settings_isolated_by_tenant`, `job_lease_exclusive_renew_and_release`, `job_expired_lease_taken_over`, `job_lease_concurrent_single_holder`. The existing recovery test now uses a `RecoveryNotice` and asserts recipient = token email. `tenant_update_settings_round_trip` covers `signing_algs` and `captcha`.

**Current results:** SQLite (memory + file) 136 pass / 92 fail. Postgres 68 pass / 46 fail. Every failure is `StorageError::Unsupported` from a TRANSITIONAL shim. All 67 pre-existing tests pass, plus the new `recovery_notice_not_enqueued_for_invalid_token`.

## Task Commits

1. **Task 1: Domain model additions and pre-declared core modules:** `b6e09e6`
2. **Task 2: Ports, AuditService, TRANSITIONAL backend shims:** `a59b179`
3. **Task 3: Contract suite for every new port method:** `aadda38`

## Decisions Made

See `key-decisions` in the frontmatter. Notes for later plans:

- 03-05/03-06: remove `pending.rs` and the `// TRANSITIONAL(03-05|03-06)` methods in users/grants/sessions/keys/flows. Remove the client/session guards (`ensure_phase3_defaults`, `ensure_phase3_update_absent`, `ensure_no_request_context`) once the columns exist. On Postgres, return `email` from the consuming UPDATE in `complete_recovery`, which replaces the runtime query.
- 03-12: `FlowService` can now pass `Some(&RecoveryNotice)` to `complete_recovery` (closes the 02-09 follow-up). `SessionService::create` currently passes `ip/user_agent: None`.
- 03-23: `admin/dto.rs` maps tenant settings wire → core with `..CoreTenantSettings::default()`, so a wire update would reset `signing_algs`/`captcha`. When those wire fields arrive, merge them with the current settings.
- 03-24: install the mirror once at startup: `anvil_core::service::audit::install_mirror(Box::new(TracingMirror))`, where `emit` does `tracing::info!(target: "audit", event = %json)`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] anvil-core cannot use `tracing`**
- **Found during:** Task 2
- **Issue:** The plan specifies `tracing::info!(target: "audit", ..)` in `service/audit.rs`. The dependency rules (scripts/check-deps.sh) and 03-01 forbid new anvil-core dependencies, and anvil-core has no tracing.
- **Fix:** Added an `AuditMirror` port plus a process-wide `install_mirror` (OnceLock), so `AuditService` keeps its `{ storage, clock }` shape for later plans. `event_json` is a pure function and has a unit test. The tracing adapter belongs to the binary (03-24).
- **Commit:** a59b179

**2. [Rule 3 - Blocking] Compile fixes outside files_modified**
- **Found during:** Tasks 1 to 3
- **Issue:** New trait methods and enum variants did not compile without changes to files not listed in the plan.
- **Fix:** Minimal edits:
  - `flow/engine.rs`, `flow/verification.rs`, `service/flow.rs`: `FlowState::initial` returns `Result` because `FlowKind::{Settings, Consent}` have no engine state yet. It returns an explicit error, never a stub.
  - `anvil-storage-{sqlite,postgres}/src/{grants,keys,flows}.rs`: TRANSITIONAL Unsupported methods. A trait impl cannot span files.
  - `contract/clients.rs`: `..ClientUpdate::default()` and the new `client_phase3_fields_round_trip` test.
- **Commits:** b6e09e6, a59b179, aadda38

**3. [Rule 2 - Correctness] Backends refuse new client/session values instead of dropping them**
- **Issue:** The plan says to map the new fields to defaults. Silently ignoring a non-default `token_format`, `consent_mode`, ID-token alg, `can_introspect` or session ip/UA would be a success stub.
- **Fix:** Reads return the defaults. Inserts and updates carrying non-default values return `StorageError::Unsupported` (TRANSITIONAL).
- **Commits:** b6e09e6

**4. [Rule 2 - Correctness] complete_recovery enqueues the notice now instead of dropping it**
- **Issue:** The plan says existing impls "keep enqueuing nothing". The pre-existing contract test requires the notice to be enqueued, and dropping it would be a silent no-op.
- **Fix:** SQLite uses the email already returned by the consuming UPDATE. Postgres uses a runtime-checked `SELECT email` in the same transaction, marked TRANSITIONAL(03-06), because changing the macro query would need regenerated `.sqlx` metadata, which is outside this plan. Both backends pass the recipient assertion.
- **Commit:** a59b179

## Issues Encountered

- 03-01's in-progress anvil-jose sources broke the main-tree build during Tasks 1 and 2. I verified in the temporary worktree `target/wt-03-02` (removed afterwards). The final main-tree build at HEAD is clean.

## Next Phase Readiness

- 03-05 (SQLite) and 03-06 (Postgres) can implement against the contract. Every new test currently fails only with Unsupported.
- Parallel plans can use the types and ports without editing `model/`, `ports.rs` or `AuditAction`.

## Self-Check: PASSED
