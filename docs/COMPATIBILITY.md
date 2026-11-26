# Compatibility policy

AnvilID follows semantic versioning from 1.0.0 on. Within a major version (1.x) every public
surface changes **additively only**: what worked on 1.0 keeps working on every later 1.x release.
Breaking changes happen only in a new major version (2.0), and that release ships a migration
guide in [UPGRADING.md](UPGRADING.md).

This page lists the public surfaces, how each is versioned, what counts as a breaking change, how
something is deprecated, and how the rules are enforced.

## Public surfaces

| Surface | Version marker | Rule within 1.x |
|---|---|---|
| Management API | path `/api/admin/v1`, OpenAPI `info.version: v1` ([admin-v1.json](openapi/admin-v1.json)) | Additive only: new operations, new optional request fields, new response fields, new enum values, new scopes. Removing or renaming an operation, field, enum value or scope, making an optional input required, or narrowing a type means `/api/admin/v2` |
| Headless flow API | path `/api/flows/v1` ([flows-v1.json](openapi/flows-v1.json)) | The same rule. New steps, form ids, field kinds, method kinds, message keys and problem codes are additive; clients must ignore the ones they do not know ([HEADLESS.md](HEADLESS.md#versioning-rules)) |
| Protocol endpoints | the OAuth 2.0 / OpenID Connect specifications and RFCs | Follow the specifications. Discovery advertises what is built; a feature is removed from discovery only together with the feature, in a major version |
| Tenant configuration YAML | document `version: 1`, `kind: TenantConfig` ([CONFIG-YAML.md](CONFIG-YAML.md)) | Version 1 is the only document version in 1.x. New optional keys may be added; unknown keys stay refused; a missing or other `version` is refused. A new document version only arrives with 2.0 |
| CLI commands and flags, environment variables, operator config keys | the release notes and [OPERATIONS.md](OPERATIONS.md) | New commands, flags and keys are additive, with defaults that keep the previous behaviour. A renamed or deprecated name keeps working for the rest of the major version and logs a warning at startup |
| Database schema | migrations and `scripts/released-migrations.sha256` | Forward-only and automatic. Released migrations never change. Upgrades between consecutive releases are tested on SQLite and Postgres. Destructive migrations only behind `--allow-destructive-migrations` (rules below) |
| Webhook payloads | the event `type` and the documented payload ([WEBHOOKS.md](WEBHOOKS.md)) | Additive only: new event types and new payload fields. Receivers must ignore unknown types and fields |
| Token claims | the documented claim set | Additive: new claims may appear. Reserved claim names are never repurposed, and a documented claim keeps its meaning |

The management API scopes are part of the management API surface: a scope that grants an
operation in 1.0 keeps granting it in every 1.x release. A new operation may come with a new
scope, which full administrators receive through `admin:write`.

Not public, and free to change in any release: the database schema itself (only the migration
path is a contract), the HTML and CSS of the built-in pages, the engine's internal form
description, log line formats (the access-log fields and metric names in OPERATIONS.md are kept
stable on a best-effort basis), and anything marked experimental (SAML 2.0 while
`saml_experimental` exists).

## What counts as breaking

For the HTTP APIs, any of these against the 1.0 document:

- an operation (method and path) is removed or renamed;
- a response, a response field or a response enum value is removed;
- a response field may take a new type, including `null`;
- a request field, parameter or enum value that was accepted is no longer accepted, or its type
  is narrowed;
- a new required request field or parameter, an optional one becoming required, or an optional
  request body becoming required;
- a security alternative (a scope that grants the operation) or a declared scope is removed.

Behaviour changes that keep the shape but change a meaning (for example what a field controls)
are breaking too, even though no tool detects them; review catches those.

## Deprecation process

No surface is deprecated in 1.0. When something is deprecated in a 1.x release:

1. **Announce** it in the release notes (the GitHub release for that version) and in [UPGRADING.md](UPGRADING.md), with the
   replacement and the earliest major version that removes it.
2. **Warn at runtime:**
   - HTTP APIs answer the deprecated operation with a `Deprecation` header (RFC 9745) and, once a
     removal date is known, a `Sunset` header (RFC 8594), plus a `Link` to the replacement
     documentation. The OpenAPI document marks the operation or field `deprecated: true`.
   - Configuration keys, flags and environment variables keep working and add a startup warning
     (the warnings the configuration loader already logs on start).
   - Tenant YAML keys keep working, and `anvilid tenant plan` / `apply` print a warning for them.
3. **Remove** it only in the next major version.

The helper that sets the `Deprecation`/`Sunset` headers arrives with the first deprecation; it is
not in 1.0, because there is nothing to deprecate and unused code would be dead code.

## Database migrations

- Migrations run automatically at startup and are **forward-only**. There are no down migrations;
  a downgrade means restoring the backup taken before the upgrade.
- A released migration never changes. `scripts/check-migrations.sh` compares every released file
  with `scripts/released-migrations.sha256`, which grows at every release.
- Migrations are expand/contract: a release never drops or renames a column that the previous
  minor release still reads. A destructive step (a migration named `NNNN_destructive_*.sql`) is
  refused at startup unless `--allow-destructive-migrations` (`ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS`)
  is set, and an unreleased migration with destructive SQL fails the lint unless it is named so or
  carries the reviewed `-- anvil:non-destructive-rebuild` annotation (SQLite table rebuilds that
  copy every row). See [ARCHITECTURE.md](ARCHITECTURE.md), section 7.3.
- Upgrade between consecutive minor releases. Migrations always apply in order, but only
  upgrades from the previous release are tested.

## How the rules are enforced

- **API breaking-change check.** `crates/anvil-web/tests/api_compat.rs` compares the documents
  generated from the handlers with the committed 1.0 baselines,
  [admin-v1.baseline-1.0.json](openapi/admin-v1.baseline-1.0.json) and
  [flows-v1.baseline-1.0.json](openapi/flows-v1.baseline-1.0.json). The tests
  `api_compat_admin_has_no_breaking_change` and `api_compat_flows_has_no_breaking_change` fail on
  every change listed under "What counts as breaking" and pass for additive changes. Self-tests run
  the comparator on mutated copies of the baselines (`api_compat_detects_removed_operation`,
  `api_compat_detects_removed_response_field`, `api_compat_detects_new_required_request_field`,
  `api_compat_detects_removed_scope`, `api_compat_allows_added_optional_field`). The baselines are
  never edited in 1.x; a 2.0 release adds new ones.
- **Contract drift.** `openapi_drift.rs` and `openapi_flows_drift.rs` keep the published
  `admin-v1.json` and `flows-v1.json` equal to what the handlers serve.
- **Tenant configuration version.** `config_doc_version_1_accepted` and
  `config_doc_unknown_version_refused` (in `anvil-core`) pin version 1 as the only accepted
  document version.
- **Upgrade tests** in `crates/anvil-storage-sqlite/tests/upgrade.rs` and
  `crates/anvil-storage-postgres/tests/upgrade.rs` build a populated database at an earlier
  schema, upgrade it to the current one, compare every row and run the full storage contract
  suite on the result:
  - 0.4 to 1.0: `upgrade_from_0_4_keeps_every_row` and `upgrade_from_0_4_is_idempotent_on_restart`
    on both backends, plus `upgrade_from_0_4_keeps_identity_links_after_connection_rebuild` on
    SQLite;
  - 1.0.0-beta.1 to 1.0: `upgrade_from_1_0_beta1_keeps_every_row_and_defaults_new_columns` and
    `upgrade_from_1_0_beta1_is_idempotent_on_restart` on both backends, and the contract suite on
    the upgraded database (module `upgraded_beta1_contract`);
  - the earlier steps (0.1 to 0.2, 0.2 to 0.3, 0.3 to 0.4) stay in the same files.
