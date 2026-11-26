---
phase: 07-release-1-0-certification
plan: 15
subsystem: user-export
tags: [export, gdpr, cli, audit, ADM-09]
requires:
  - "07-03: AuditAction::UserExported"
  - "07-04: service::user_export module, CLI skeleton with the final flags"
  - "07-08: GrantRepo::families_for_user, UserRepo::pending_self_service_tokens"
provides:
  - "UserExportService { storage, clock }: export_user, bulk_without_hashes (HTTP), bulk(ExportOptions) (CLI), gdpr_bundle"
  - "BulkExport page iterator: next_page, with_page_size, count, includes_password_hashes, mark_failed, finish (audits)"
  - "DTOs: UserExportRecord, GdprBundle and their parts; rfc3339 helper"
  - "AuditDetails::user_export(mode, count, include_password_hashes)"
  - "anvilid users export (bulk NDJSON, --user JSON, --user --gdpr bundle, --include-password-hashes, --out 0600)"
affects: [07-17 (admin HTTP export routes, docs/IMPORT-EXPORT.md export section), 07-11 (Postgres families_for_user / pending_self_service_tokens needed for the GDPR bundle on Postgres)]
tech-stack:
  added: []
  patterns:
    - "Allow-list export DTOs in the service module; storage models are never serialised for export"
    - "Async page iterator instead of a Stream (anvil-core has no futures dependency)"
    - "Role labels instead of other people's identities in the GDPR audit section"
key-files:
  created:
    - crates/anvil-web/tests/export_redaction.rs
    - crates/anvilid/tests/users_export_cli.rs
  modified:
    - crates/anvil-core/src/service/user_export.rs
    - crates/anvilid/src/users_export.rs
    - crates/anvil-core/src/model/audit.rs (forced extra, one typed constructor)
    - crates/anvilid/src/main.rs (forced extra, users_export wrapper only)
  deleted:
    - crates/anvilid/tests/users_export_skeleton.rs
key-decisions:
  - "Bulk export is an async page iterator (BulkExport::next_page -> Option<Vec<UserExportRecord>>), not a Stream: anvil-core has no futures dependency and its manifest is not this plan's. 07-17 wraps it with futures::stream::unfold for the NDJSON body"
  - "HTTP gets bulk_without_hashes(tenant), which has no options parameter; only bulk(tenant, ExportOptions) can set include_password_hashes, and only the CLI calls it"
  - "The service audits: export_user and gdpr_bundle record user_exported (target = user id) on success; BulkExport::finish records mode bulk with the count and the hash flag, outcome failure when the export ended early, with an error or after mark_failed"
  - "CLI actor is AuditActor { kind: System, id: Some(\"cli\") } (ActorKind has no cli variant)"
  - "Export without --out runs with no tracing subscriber: the audit mirror writes JSON lines to stdout and corrupted the NDJSON (found by the CLI test). The event is still stored in the audit log; with --out logs and the mirror stay on"
  - "GDPR audit section: actor becomes subject / administrator / another_user / system / client (client id kept: an application, not a person); a target that is another user of the tenant becomes another_user; IP and user agent only on the subject's own events; detail strings under *user*/*email*/*actor* keys other than the subject's id become redacted"
metrics:
  duration: ~20min
  completed: 2026-11-26
requirements: [ADM-09 (not ticked; the gate 07-23 ticks it)]
---

# Phase 7 Plan 15: User export (single, bulk, GDPR) Summary

One `UserExportService` exports a user, a tenant's users page by page, or a user's GDPR data-subject
bundle. Each shape is an allow-list DTO, and other people's identities are redacted in the bundle.
Secrets are never exported. Password hashes come out only through the audited CLI bulk flag.

## DTO field lists

**UserExportRecord** (single export and each bulk NDJSON line): `id, email, email_verified,
username, status, claims, attributes, created_at, updated_at, last_login_at, roles (tenant-wide
{id,name}), organizations [{org_id, slug, display_name, roles}], identity_links [{connection_id,
connection (slug or null), subject}], credentials [{id, kind, label, created_at, last_used_at}]`.
`password_hash` is present only in the CLI bulk export with `--include-password-hashes`, and only
for users who have a password. The field is omitted otherwise.

`claims` lists the OIDC standard claims field by field (`ClaimsExport`, with `address` as
`AddressExport`). Timestamps are RFC 3339 UTC with milliseconds (`2026-11-25T12:00:00.000Z`).

**GdprBundle**: `export_format_version (1), generated_at, subject {id, email, email_verified,
username, status, claims, created_at, updated_at, last_login_at}, attributes, credentials {items
[metadata], password_set, totp_enrolled, recovery_codes_remaining}, sessions [{id, created_at,
last_seen_at, auth_time, expires_at, authentication_methods, ip, user_agent}], consents [{client_id,
scopes, resources, created_at, updated_at, revoked_at}], token_families [{id, client_id, scope,
resources, created_at, expires_at, revoked_at, revoked_reason}], identity_links [{connection_id,
connection, subject, email_at_link, metadata, created_at, last_used_at}], roles, organizations,
audit_events [{id, at, action, outcome, actor, actor_client_id, target, ip, user_agent, details}],
pending_self_service_tokens [{kind, expires_at}], operator_statement (always null)`. The type has
no password field.

## GDPR inventory (port per category)

| Category | Port |
| --- | --- |
| profile, claims | `UserRepo::get` |
| attributes | `AttributeRepo::user_values` |
| credential metadata | `UserRepo::list_credentials`, `recovery_codes_remaining` |
| sessions (active) | `SessionRepo::list_for_user(now)` |
| consents | `GrantRepo::list_consents` |
| token families (every state) | `GrantRepo::families_for_user` |
| identity links + connection slug | `ConnectionRepo::links_for_user`, `ConnectionRepo::get` |
| tenant roles / org memberships and roles | `RoleRepo::roles_for_user`, `OrgRepo::memberships_of_user`, `RoleRepo::roles_for_user_in_org` |
| audit about / by the user | `AuditRepo::query` with `target` and `actor_id` (paged, 200 at a time, merged by id, newest first) |
| pending self-service tokens | `UserRepo::pending_self_service_tokens` (kind + expiry only) |
| excluded | webhook deliveries (operational copies of the audit events) |

`operator_statement` is reserved for `{purposes, recipients, retention}`. The software always leaves it
`null`, and operators fill it in.

## CLI

`anvilid users export [--tenant SLUG=default] [--user UUID] [--gdpr] [--include-password-hashes] [--out PATH]`

- With no `--user`, prints NDJSON for every user in id order, in pages of 100.
- `--user` prints one JSON document. `--user --gdpr` prints the bundle.
- `--include-password-hashes`: the parser refuses it with `--gdpr`, and `run` refuses it with
  `--user` (`run` checks both again). It prints a stderr warning that the output contains hashes.
- `--out` creates the file with mode 0600, or truncates an existing file and tightens it to 0600.
- Every successful run is audited as `user_exported` with the actor `system`/`cli`. The details are
  `{mode: single|bulk|gdpr, count, include_password_hashes}`. Refused runs and unknown users write
  no event.

## Tests

- `crates/anvil-web/tests/export_redaction.rs` (8 tests, SQLite; Postgres via `ANVILID_TEST_DB` in CI):
  - `single_export_has_exactly_the_allowed_fields`
  - `bulk_stream_pages_every_user_once_in_order` (7 users, page size 3, so 3 pages)
  - `gdpr_bundle_contains_every_inventory_category`
  - `gdpr_export_redacts_other_actors`
  - `export_dto_contains_no_secrets`: all three modes. Absent: `$argon2`, `$2a$`, `$2b$`, `$anvil-`, the passkey marker, the pending address, the admin's email, a `"password_hash"` key, `secret`, `token_hash`, and the base64/base64url/hex forms of the sealed TOTP seed, the sealed connection secret, the session, client and self-service token hashes and the recovery-code hashes.
  - `gdpr_bundle_has_no_password_field_even_with_flag`
  - `bulk_hashes_only_with_explicit_option`
  - `single_and_gdpr_exports_are_audited_with_target`
- `crates/anvil-core` unit tests (4): `rfc3339_is_utc_with_millis`, `actor_labels_never_name_other_people`, `details_drop_other_user_refs`, `export_options_default_has_no_hashes`.
- `crates/anvilid/tests/users_export_cli.rs` (7 tests):
  - `users_export_help_lists_every_flag`
  - `bulk_export_streams_every_user_without_hashes` (130 users, more than one page)
  - `bulk_export_with_hashes_is_opt_in_and_audited` (file mode 0600; stdout holds only the audit mirror line)
  - `single_and_gdpr_exports` (an existing 0644 file is tightened to 0600; an unknown user is an error with no audit event)
  - `cli_hash_flag_refused_with_gdpr`
  - `unknown_tenant_is_an_error`
  - `missing_database_is_refused_without_creating_data`
- Mutation check: when the administrator's id was leaked as `actor_client_id`, `gdpr_export_redacts_other_actors` and `export_dto_contains_no_secrets` both failed. Reverted afterwards.

## Verification

- `cargo test -p anvil-web --test export_redaction`: 8 passed.
- `cargo test -p anvil-core --lib service::user_export`: 4 passed.
- `cargo test -p anvilid --test users_export_cli`: 7 passed. `--test cli --test users_import_skeleton`: 18 + 3 passed.
- `cargo clippy -p anvil-core -p anvilid --all-targets --locked -- -D warnings`: clean.
- `scripts/check-release-graph.sh`: OK.
- `crates/anvilid/tests/users_export_skeleton.rs` is deleted. `grep -rn 'TRANSITIONAL(07-15)' crates/` finds nothing.
- Not run: `cargo test --workspace --locked` (the shared tree holds other wave-3 plans' in-progress work, and the rules ask for targeted runs), and the Postgres run of export_redaction. On Postgres the GDPR bundle needs `families_for_user` and `pending_self_service_tokens`, which return `TRANSITIONAL(07-11)` until 07-11 lands.

## Notes for docs/IMPORT-EXPORT.md (07-17)

- Explain the three modes, the field lists above and the RFC 3339 UTC timestamps.
- Bulk output is NDJSON in user id order.
- Hashes are exported only through the CLI flag. The output then holds secrets and should be stored like a backup.
- The GDPR bundle is machine-readable data only. The operator adds purposes, recipients and retention (`operator_statement`). Webhook deliveries are excluded.
- The bundle names other people only by role: `administrator`, `another_user`, `system`, `client`.
- Sessions are the active ones. Token families appear in every state.
- Audit events are stored for every export. Without `--out`, the CLI prints no audit mirror line, because stdout carries the export.

## Deviations from Plan

**1. [Rule 3 - Blocking] `AuditDetails::user_export` in model/audit.rs (forced extra)**
- The plan requires details `{mode, count, include_password_hashes: true}`, and `AuditDetails` can
  only be built through typed constructors (`from_stored` is for storage backends only). I added
  one constructor (12 lines). No other wave-3 plan lists audit.rs.
- Commit: ebda2ce

**2. [Rule 1 - Bug] main.rs `users_export` wrapper: no tracing when exporting to stdout (forced extra)**
- `init_tracing` installs the audit mirror, which writes JSON lines to stdout. The export's own
  `user_exported` line was appended to the NDJSON or JSON output and corrupted it. The CLI test
  caught this. Without `--out`, the wrapper now skips tracing. With `--out`, logs and the mirror
  stay on. The audit event is stored in both cases.
- Commit: 37c9282

**3. Bulk export is a page iterator, not a Stream.** The plan allowed either. anvil-core has no
futures dependency, and its manifest belongs to another plan.

**4. `BulkExport::mark_failed`** (beyond the plan) makes sure a failed output write is audited as a failure.

## Self-Check: PASSED
