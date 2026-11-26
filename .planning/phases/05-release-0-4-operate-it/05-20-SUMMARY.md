---
phase: 05-release-0-4-operate-it
plan: 20
subsystem: declarative-config
tags: [declarative-config, yaml, serde-saphyr, json-schema, openapi, cli, rbac, last-administrator, fuzz]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 TenantConfigDocument/SecretInput, 05-10 plan/plan_excluding/render, 05-12 RoleService guards, 05-14 WebhookService, 05-17 open_for_cli CLI pattern, 05-19 AttributeService
provides:
  - ConfigService (load, export, apply with dry_run/prune) and pure validate_document / normalize_document / StoredConfig::document
  - Admin API GET /tenants/{slug}/config, POST /config/plan, POST /config/apply
  - anvilid tenant export|plan|apply (YAML, {env}/{file} secret references)
  - docs/schemas/tenant-config-v1.json and docs/CONFIG-YAML.md
  - fuzz target tenant_config_parse
  - ClientService::create_static/set_secret, WebhookService::set_secret, role::guard_roles_losing_admin
affects: [05-23, 05-24, 05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "Validate everything first (pure document checks, then stored-state checks and batch role guards), then write object by object through the owning services"
    - "Normalize the desired document the way services store it, so a re-applied document plans empty"
    - "Secret references are resolved only by the CLI; the API refuses them by position"

key-files:
  created:
    - crates/anvilid/src/tenant_config.rs
    - crates/anvil-web/tests/admin_config.rs
    - crates/anvil-web/tests/security_admin_config.rs
    - crates/anvilid/tests/tenant_config.rs
    - docs/CONFIG-YAML.md
    - docs/schemas/tenant-config-v1.json
    - fuzz/fuzz_targets/tenant_config_parse.rs
  modified:
    - crates/anvil-core/src/service/config.rs
    - crates/anvil-web/src/admin/config.rs
    - crates/anvilid/src/main.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
    - fuzz/Cargo.toml
    - crates/anvil-core/src/service/{client,role,tenant,mail_settings,webhook}.rs (forced, additive)
    - crates/anvil-web/tests/openapi_drift.rs (forced: operation count 60 -> 63)

key-decisions:
  - "Plan and apply require admin:write on every tenant (export: admin:read or admin:write); system-tenant role changes additionally go through RoleService's escalation check with the caller's scope"
  - "The last-administrator guard runs for the whole batch before any write (role::guard_roles_losing_admin over every role that stops granting admin:write); RoleService still checks each change"
  - "CAPTCHA (its secret) and logos are not part of the version 1 document; a document with settings.captcha is refused"
  - "Export normalizes the system tenant's DCR/CIMD policy to disabled (the only value in force); a system document with anything else is a validation error"
  - "Clients keep their client_id across instances (ClientService::create_static); provided client secrets must be 32-512 chars (SHA-256 hash storage)"
  - "Missing secrets: clients and webhooks get a generated secret (returned once); connections and SMTP passwords must be provided (validation error)"
  - "A document for a missing tenant creates it; email_otp/magic_link are turned on in a final settings write once the document's SMTP is in place"
  - "The OpenAPI document describes the request/response document as Object and points to the published JSON Schema (mirroring every model type as DTOs was not feasible); plan/apply results are typed DTOs"
  - "Microsoft connections with trust_email_verified: true in a document accept the nOAuth risk (explicit in the document, recorded by the connection audit event)"
  - "CLI applies are audited with the system actor (like keys rotate and admin recover)"

patterns-established:
  - "Batch guard + per-change guard: preflight the whole batch, keep the service guard as defense in depth (mutation-checked)"

requirements-completed: [ADM-06, ADM-07]

duration: ~60min
completed: 2026-11-26
---

# Phase 5 Plan 20: Declarative tenant configuration (export, plan, apply) Summary

**A tenant exports as a versioned `TenantConfig` document (natural keys, secrets as `{configured}`), validates completely before any write, applies idempotently through the existing services (RoleService guards included), and round-trips as YAML through `anvilid tenant` into a fresh instance with `{env}`/`{file}` secrets resolved on the operator's machine.**

## Performance

- **Duration:** about 60 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Commits:** 3 (Task 2 split into the OpenAPI-owning admin API commit and the CLI/docs commit)

## Document shape

`version: 1`, `kind: TenantConfig`, `tenant {slug, display_name, host, settings}`, `clients[]` (static only, key `client_id`), `connections[]` (slug), `branding[]` (`client_id`, absent = tenant-wide), `roles[]` (name), `attributes[]` (name), `email_templates[]` (kind), `smtp`, `webhooks[]` (name). Not included: users, role assignments, dynamic/CIMD clients, the system `anvil-console` client, CAPTCHA, logos. Secret fields (`clients[].secret`, `connections[].secret`, `webhooks[].secret`, `smtp.password`): `{configured: bool}` / `{value}`; CLI also `{env: NAME}` / `{file: path}`. Full reference: docs/CONFIG-YAML.md; schema: docs/schemas/tenant-config-v1.json.

## Core API (`anvil_core::service::config`)

- `validate_document(&doc, &Validators) -> Result<(), Vec<ConfigIssue{path, message}>>` (pure; services' validators; paths like `clients[2].redirect_uris[0]`)
- `normalize_document(&doc) -> TenantConfigDocument`
- `StoredConfig::document()` (export), `ConfigService::{load, export, apply(ApplyRequest{actor, caller, document, prune, dry_run, ctx})}` -> `ApplyOutcome{plan, applied, pruned, generated}`; `ConfigError::{Invalid(issues), Core(e)}`
- Apply order: tenant (create or update), roles, attributes, connections, clients, branding, (branding/client/connection deletes), email templates, SMTP, SMTP-dependent settings, webhooks; `tenant_config_applied` with counts only. Partial-failure convergence rule in the module docs.

## Admin API

| Route | Scope | Result |
|---|---|---|
| `GET /api/admin/v1/tenants/{slug}/config` | admin:read / admin:write | the document |
| `POST …/config/plan` | admin:write | `ConfigPlanDto` (creates/updates/deletes, `empty`, `text`) |
| `POST …/config/apply[?prune=true]` | admin:write | `ConfigApplyResult` (plan, applied, pruned, `generated_secrets` shown once) |

422 lists every issue by path; system-tenant lockout is 409; `{env}`/`{file}` references are 422 naming the field.

## CLI usage

```sh
anvilid tenant export acme -o acme.yaml
anvilid tenant plan -f acme.yaml
anvilid tenant apply -f acme.yaml [--prune] [--yes]
```

`apply` prints the plan, needs `--yes` or an interactive "y" (refused on a non-terminal stdin), prints `No changes.` / `Nothing to apply without --prune.` / `Applied: N created, N updated, N deleted.` and each generated secret once.

## Security tests (security_admin_config.rs)

`config_apply_never_reads_server_env_or_files`, `config_export_contains_no_secrets_or_hashes`, `config_apply_requires_admin_write`, `config_apply_invalid_document_changes_nothing`, `config_apply_cannot_lock_out_system_admins`, `system_document_keeps_registration_disabled_and_the_console_client_out`.

Mutation check: with the batch guard (`guard_roles_losing_admin` call in `check_roles`) removed, `config_apply_cannot_lock_out_system_admins` fails (the plan returns 200 and the new role would be created before RoleService refuses the edit).

## Other tests

- anvil-core `service::config` (27, 13 new): exact path for the 3rd client's redirect URI, every issue reported, duplicate keys, secret rules per kind, system tenant rules, CAPTCHA/version refused, branding client reference, export of static-only clients with `{configured}` secrets and no ids, system export (console omitted, DCR/CIMD disabled), normalisation makes re-apply empty, SMTP-dependent settings, stored-state checks.
- anvil-web `admin_config` (7): export shape, apply through services with per-service audit + `tenant_config_applied {creates:7,updates:0,deletes:0}`, re-apply of document and of export = no writes and no audit rows, prune-only deletes, inline secrets compared (equal = no change; different = rotated, values never in the plan; webhook previous secret kept for the window), only changed fields updated (`client_updated` fields = `[redirect_uris]`), a document creating a missing tenant, `json_schema_matches_the_document_types` (published schema is valid 2020-12, validates input and exports of default and system, lists every settings field, rejects unknown keys/versions/malformed secrets).
- anvilid `tenant_config` (4): `round_trip_into_fresh_instance`, `apply_without_yes_on_a_non_terminal_refuses`, `deletions_need_prune`, `invalid_documents_are_reported_by_path`; bin unit tests (3): reference resolution at secret positions only, newline stripping, the documented YAML example parses.
- anvil-web lib (1): reference detection at secret positions only.

## Task Commits

1. **Task 1: ConfigService export, validate, apply:** `a21db87` (feat)
2. **Task 2a: admin routes, security tests, OpenAPI + console types:** `727b19a` (feat)
3. **Task 2b: CLI, JSON Schema, docs, fuzz target:** `e1f8628` (feat)

## Verification run

- `cargo test -p anvil-core --lib service::config` (27) and full `anvil-core --lib` (800): pass.
- `cargo test -p anvil-web --test admin_config --test security_admin_config --test openapi_drift`: 7 + 6 + 3 pass.
- `cargo test -p anvilid --test tenant_config --test cli`: 4 + 18 pass; `--bin anvilid` unit tests pass.
- `cd admin-ui && npm run check:api`: up to date. `cargo check --manifest-path fuzz/Cargo.toml --locked --bins`: OK (no lockfile change).
- Regression: anvil-web `security_rbac` (12), `admin_roles` (6), `webhooks` (13), `admin_api` (9), `admin_api_v03` (4), `security_admin` (10), `registration_dcr` (6): pass.
- `cargo clippy -p anvil-core -p anvil-web -p anvilid` on the touched targets: no warnings. `rustfmt --edition 2024` on every touched Rust file.
- `grep -rn "std::env::var\|std::fs::read" crates/anvil-core/src/service/config.rs crates/anvil-web/src/admin/config.rs`: empty.

## Not run

- Postgres variants (`ANVILID_TEST_DB=postgres`) of admin_config/security_admin_config: need Docker, left for CI.
- The fuzz target was type-checked only (needs nightly + cargo-fuzz; `just fuzz-smoke` in CI).
- Full workspace test suite (targeted runs only, per the shared rules).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] ClientService could not keep a client_id or take a provided secret**
- Added `ClientService::create_static` (caller-chosen `client_id`, optional provided secret, same `insert` path as create/create_dynamic) and `set_secret`, plus `validate_client_id` / `validate_client_secret`. Waited for 05-21 to commit its in-progress client.rs first. **Forced extra file:** `crates/anvil-core/src/service/client.rs`.

**2. [Rule 3 - Blocking] Webhook rotation to a provided secret**
- `WebhookService::set_secret` (shares `rotate_to` with `rotate_secret`; same grace window and audit). **Forced extra file:** `service/webhook.rs`.

**3. [Rule 2 - Correctness] Batch last-administrator guard**
- Per-change guards alone would leave earlier writes in place before a later role change is refused. Added `role::guard_roles_losing_admin` (generalizes `other_admin_exists` to a set of excluded roles) and `validate_description` visibility. **Forced extra file:** `service/role.rs`.

**4. [Rule 3 - Blocking] Validators not reachable from config.rs**
- `pub(crate)` on `tenant::validate_host`, `mail_settings::plan_template` and `plan_smtp` (no behaviour change). **Forced extra files:** `service/tenant.rs`, `service/mail_settings.rs`.

**5. [Rule 3 - Blocking] openapi_drift operation count**
- 60 -> 63. **Forced extra file:** `crates/anvil-web/tests/openapi_drift.rs`.

**6. Plan interpretation**
- Logos: the plan suggested sha256 + inline base64; the 05-01 document model has no logo field (and config_doc.rs is not owned here), so logos stay out of version 1 (documented).
- Stateful behaviours listed under Task 1 (dynamic/CIMD exclusion against storage, zero writes on re-apply, prune, inline webhook secret, lockout) are tested in anvil-web integration tests: anvil-core has no storage implementation for unit tests. The pure parts are unit-tested in core.
- The JSON Schema test uses `jsonschema` directly in an anvil-web test, not the attribute adapter (the adapter caps schemas at 16 KiB / depth 32, which a whole-document schema exceeds).
- TDD order: tests and implementation landed per commit; the lockout guard was checked by mutation instead.

### Deferred (logged in deferred-items.md)

- Admin API body limit (64 KiB) also applies to `/config/apply`; large documents go through the CLI.
- DCR/CIMD settings validation: when 05-23 adds it to TenantService, `validate_document` should call the same function.
- The CLI repeats the outbound-policy wiring of `startup::start` (startup.rs not owned).
- Add the security_admin_config test names to `scripts/check-security-tests.sh` (05-28).

## Self-Check: PASSED
