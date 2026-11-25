---
phase: 03-release-0-2-secure-by-default
plan: 23
subsystem: management-api
tags: [admin-api, openapi, sessions, credentials, audit, email-templates, smtp, captcha, signing-algs, consent]
requires:
  - phase: 03-14
    provides: AccountService::admin_list/admin_remove
  - phase: 03-15
    provides: MailSettingsService, anvil_mail::{TemplateChecker, LettreSmtpTester, check::variables}
  - phase: 03-17
    provides: consent_mode semantics (API clients default to required)
  - phase: 03-19
    provides: SessionService::admin_list_user/admin_list_tenant/admin_revoke/admin_revoke_all
  - phase: 03-21
    provides: ClientOptions/ClientOptionsPatch, CaptchaChange, plan_settings, admin scopes Sessions/Audit/Settings, AdminAuth::actor
provides:
  - "Management API 0.2: client options, tenant signing_algs + CAPTCHA, sessions, credentials, audit-events, email templates, SMTP + test send (31 operations)"
  - "TenantService refuses disabling a signing algorithm used by a client (Conflict naming the client ids)"
  - "docs/openapi/admin-v1.json regenerated; admin-ui/src/api/schema.d.ts regenerated"
  - "e2e createClient / conformance static clients default to consent_mode=skip_first_party"
affects: [03-24, 03-25, 03-26, 03-27, 03-28, 03-29]
tech-stack:
  added: []
  patterns:
    - "Wire PATCH settings are partial (TenantSettingsPatch.merge onto the current settings); core TenantPatch keeps full-replacement semantics"
    - "Admin service constructors live in the module that uses them (impl AppState in sessions.rs, audit.rs, email.rs)"
key-files:
  created:
    - crates/anvil-web/src/admin/sessions.rs
    - crates/anvil-web/src/admin/audit.rs
    - crates/anvil-web/src/admin/email.rs
    - crates/anvil-web/tests/admin_api_v02.rs
    - crates/anvil-web/tests/security_admin_v02.rs
  modified:
    - crates/anvil-web/src/admin/{mod,dto,clients,tenants,users}.rs
    - crates/anvil-core/src/service/tenant.rs
    - crates/anvil-web/tests/openapi_drift.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
    - tests/e2e/lib/anvil.ts
    - tests/conformance/setup.sh
key-decisions:
  - "03-23: Tenant settings PATCH is field-wise: absent fields keep their value; settings.captcha null clears, an object {provider, site_key, secret} sets; captcha and signing_algs live under settings and need the tenants write scope"
  - "03-23: Disabling a signing algorithm that a client uses as id_token_signed_response_alg is refused in TenantService::update with Conflict (409); the problem detail names the algorithms and every affected client id"
  - "03-23: ClientView.id_token_signed_response_alg is the effective algorithm (RS256 when unset); PATCH null resets it"
  - "03-23: Credentials list includes the password summary (kind password); DELETE refuses passwords (404, from AccountService)"
  - "03-23: DELETE email-templates/{kind} and DELETE smtp are idempotent 204; GET smtp without tenant settings is 404"
  - "03-23: Template 422 problems carry errors[{field, line, message}] (FieldError gained an optional line)"
  - "03-23: Theme defaults for GET email-templates come from {theme_dir}/emails then the embedded themes/default/emails, in override form (first text line = subject)"
requirements-completed: []
duration: 75min
completed: 2026-11-25
---

# Phase 3 Plan 23: Management API 0.2 and regenerated OpenAPI Summary

**The management API now covers everything the 0.2 console needs: client token format, consent mode, ID-token algorithm and introspection; tenant signing algorithms and a write-only CAPTCHA secret (merged updates, 409 when disabling an algorithm in use); session and credential administration; a filtered, cursor-paged audit-log query; and email templates plus SMTP settings with a synchronous test send. Every route is scope-protected, documented in the regenerated OpenAPI 3.1 file and tested on SQLite and Postgres.**

## Endpoints (for 03-25)

All paths are below `/api/admin/v1`; `{slug}` is the tenant slug. Every response is `Cache-Control: no-store`; errors are RFC 9457 problem JSON.

| Method | Path | Scope (or admin:read / admin:write) | Notes |
|---|---|---|---|
| GET/POST | `/tenants/{slug}/clients` | clients read / write | create accepts `token_format` (jwt\|opaque), `consent_mode` (required\|skip_first_party), `id_token_signed_response_alg`, `can_introspect` |
| GET/PATCH/DELETE | `/tenants/{slug}/clients/{client_id}` | clients | PATCH accepts the same four fields; `id_token_signed_response_alg: null` resets to RS256 |
| GET/PATCH | `/tenants/{slug}` | tenants | `settings: {registration?, require_verified_email?, signing_algs?, captcha?}` merged with the current settings; view: `signing_algs`, `captcha: {provider, site_key, configured: true} \| null` |
| GET | `/tenants/{slug}/sessions?after&limit` | sessions read | paged, active sessions |
| DELETE | `/tenants/{slug}/sessions/{session_id}` | sessions write | 204; 404 unknown/inactive |
| GET | `/tenants/{slug}/users/{user_id}/sessions` | sessions read | `{items, next_cursor: null}` |
| DELETE | `/tenants/{slug}/users/{user_id}/sessions` | sessions write | 200 `{revoked: n}` |
| GET | `/tenants/{slug}/users/{user_id}/credentials` | users read | `{items: [{id, kind: password\|webauthn\|totp, label, created_at, last_used_at}]}` |
| DELETE | `/tenants/{slug}/users/{user_id}/credentials/{credential_id}` | users write | passkey or TOTP (with its recovery codes); password → 404 |
| GET | `/tenants/{slug}/audit-events?from&to&actor&action&outcome&target&cursor&limit` | audit read | newest first; `{items: [{id, at, actor{kind,id}, action, target, outcome, ip, user_agent, trace_id, details}], next_cursor}`; pass `next_cursor` as `cursor`; tenant lifecycle events are under `/tenants/system/audit-events` |
| GET | `/tenants/{slug}/email-templates` | settings read | one item per kind |
| GET/PUT/DELETE | `/tenants/{slug}/email-templates/{kind}` | settings | `{kind, customized, subject, body_html, body_text, variables, updated_at}`; PUT 422 → `errors[{field, line, message}]` |
| GET/PUT/DELETE | `/tenants/{slug}/smtp` | settings | `{host, port, username, password_set, from, tls, updated_at}`; PUT `password` is write-only (absent/empty keeps the stored one); GET 404 when the installation SMTP is used |
| POST | `/tenants/{slug}/smtp/test` `{to}` | settings write | 200 `{delivered, error?}` even when SMTP fails; 422 field `smtp` without tenant settings |

Wire enums: `AuditAction` (41 snake_case names), `AuditOutcome`, `ActorKind`, `EmailKind`, `SmtpTls`, `CredentialKind`, `CaptchaProvider`, `TokenFormat`, `ConsentMode`.

## Task Commits

1. **Task 1: New client/tenant fields, sessions and credentials endpoints:** `eb22388`
2. **Task 2: Audit query and email/SMTP endpoints:** `a004129`
3. **Task 3: API/security tests and regenerated OpenAPI:** `2cc3421`
4. **Extra item 5: first-party e2e/conformance clients skip consent:** `b9f3033`

## Orchestrator extra items

1. Client DTOs expose `consent_mode`, `token_format`, `can_introspect`, `id_token_signed_response_alg`; tenant DTOs expose `signing_algs` and the CAPTCHA change (eb22388).
2. Settings updates merge with the current settings; `tenant_settings_updates_merge_with_the_current_settings` checks that signing_algs, the sealed CAPTCHA secret and the other fields survive single-field and display-name-only updates.
3. `TenantService::update` refuses to disable an algorithm in use: Conflict (409), detail lists the algorithms and client ids, nothing is stored or audited (`disabling_a_signing_algorithm_in_use_is_refused_with_the_client_ids`).
4. `admin:read` / `admin:write` descriptions in `admin/mod.rs` now name all resources.
5. `tests/e2e/lib/anvil.ts` `createClient(token, body, tenant = 'default', consentMode = 'skip_first_party')`; `tests/conformance/setup.sh` static clients send `consent_mode: skip_first_party`. `scripts/qual04.sh` creates its client through `createClient` (qual04.spec.ts), so it needed no change.
6. Email templates and SMTP are tested end to end (HTTP, MailSettingsService, real storage, audit events) on both backends: invalid template → 422 with field and line, nothing stored; GET after PUT; DELETE; SMTP password sealed in storage and absent from every response; test send against a closed port → `delivered: false` with an error and a `smtp_test_sent` failure event.

## Verification

- SQLite: `cargo test -p anvil-web --test admin_api --test admin_api_v02 --test security_admin --test security_admin_v02 --test openapi_drift --test admin_audit --test console_client`: all pass (9, 9, 6, 6, 3, 6, 4). Full `cargo test -p anvil-web -p anvil-core`: 53 test binaries, all pass.
- Postgres (`ANVILID_TEST_DB=postgres`): the same binaries except openapi_drift (backend-independent): all pass.
- `cargo clippy -p anvil-web -p anvil-core --lib --test admin_api_v02 --test security_admin_v02 --test openapi_drift -D warnings`: clean; `cargo fmt`: clean.
- OpenAPI: 31 operations; every `$ref` resolves; `npm run gen:api` + `npm run typecheck` in admin-ui pass.
- QUAL-04: `scripts/qual04.sh sqlite` and `postgres` pass with a freshly built image.
- e2e: `tests/e2e/run.sh sqlite specs/nojs.spec.ts` passes (sample RP authorization-code flow reaches `/me` without a consent stop). The full suite has 7 failures unrelated to this plan (see Issues).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `tests/openapi_drift.rs` operation count 16 → 31**
- The drift test pins the number of operations; the new routes change it. One-line change.
- **Commit:** 2cc3421

**2. [Rule 3 - Blocking] `admin-ui/src/api/schema.d.ts` regenerated**
- `just console-check` diffs the generated types against the committed spec; without regeneration the console CI job would fail until 03-25. Generated with `npm run gen:api`; `npm run typecheck` passes.
- **Commit:** 2cc3421

**3. [Rule 2 - Correctness] Wire tenant settings split into view / create / patch types**
- The 0.1 `TenantSettings` was both input and output with full-replacement semantics (a PATCH reset `signing_algs`). Now `TenantSettings` (view, with `captcha` view), `NewTenantSettings` (create, no CAPTCHA: the core refuses CAPTCHA on create) and `TenantSettingsPatch` (partial, merged in the handler onto the current settings). The core `TenantPatch` is unchanged, so 03-21's tests keep working.
- **Commit:** eb22388

**4. [Rule 2 - Correctness] Default email templates read in the web layer**
- anvil-mail exposes no accessor for the embedded default sources (and is not in this plan's files). `email.rs` embeds `themes/default/emails/` read-only (rust-embed, as the outbox renderer does) and prefers `{theme_dir}/emails/`. Rendering still happens only in anvil-mail.
- **Commit:** a004129

### Notes

- Task 1 was committed with `mod.rs` temporarily omitting the audit/email modules so that each commit compiles; the drift test was red between Task 1 and Task 3 (spec regenerated in Task 3).
- TDD: tests were written after the handlers in Task 3, as the plan's task order prescribes; all pass.

## Issues Encountered

- Full e2e suite (`tests/e2e/run.sh sqlite`): 12 passed, 7 failed. The failures are not caused by consent or the admin API: `keyboard.spec.ts` expects the login tab order without the 03-20 passkey button, and login/recovery specs run into the default Auth-class rate limit (all from 127.0.0.1). Logged in `deferred-items.md` for the e2e plans.
- None blocking. After rebuilding `anvilid:ci` (`scripts/docker-image.sh`, smoke test passed), `scripts/qual04.sh sqlite` (4 s) and `scripts/qual04.sh postgres` (7 s) both pass: the RP login completes without a consent stop.

## Self-Check: PASSED

- FOUND: admin/{sessions,audit,email}.rs, tests/admin_api_v02.rs, tests/security_admin_v02.rs (371 lines), docs/openapi/admin-v1.json
- FOUND: eb22388, a004129, 2cc3421, b9f3033
