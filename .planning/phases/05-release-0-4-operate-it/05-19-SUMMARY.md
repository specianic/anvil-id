---
phase: 05-release-0-4-operate-it
plan: 19
subsystem: attributes
tags: [attributes, json-schema, account-page, self-service, i18n, auth-14]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 AttributeDefinition model and audit actions, 05-02 AttributeRepo / AttributeSchemaCheck ports and the pre-declared modules, 05-06/05-07 storage, 05-10 JsonSchemaCheck and claims_mapping (RESERVED_CLAIMS, validate_mapping)
provides:
  - AttributeService (define/delete/list/get, effective_schema, set_user_values Replace/SelfService, update_own, check_own_binding)
  - Pure check_definition / plan_values / effective_schema in core
  - AppState::attribute_service() (pub(crate), for 05-23 admin routes and 05-20 config apply)
  - GET/POST /ui/account/attributes with typed no-JS inputs
  - Conditional "Attributes" account nav entry (account_attributes_nav)
affects: [05-12, 05-20, 05-23, e2e account navigation]

tech-stack:
  added: []
  patterns:
    - "Attribute values are validated per definition fragment (not via the assembled document), so the 16 KiB / depth-32 caps apply per definition and #/$defs refs resolve inside the fragment"
    - "Stored keys without a definition are carried over on every write (schema change or delete never rewrites data)"
    - "Account-page settings-flow binding for non-reauth edits composed from flow::check_binding + SettingsState in the attribute service"

key-files:
  created:
    - crates/anvil-web/tests/account_attributes.rs
    - crates/anvil-web/tests/security_attributes.rs
    - themes/default/templates/account_attributes.html
    - themes/default/locales/en/account_attributes.ftl
    - themes/default/locales/de/account_attributes.ftl
  modified:
    - crates/anvil-core/src/service/attribute.rs
    - crates/anvil-web/src/ui/account_attributes.rs
    - themes/default/templates/account_base.html

key-decisions:
  - "define() is create-or-replace (PUT semantics, matching 05-23's PUT /attributes/{name}); there is no separate update()"
  - "Attribute names may not collide with any reserved protocol or OIDC standard claim (is_reserved_claim), e.g. sub, email, name, website"
  - "WriteMode::Replace replaces every defined value; WriteMode::SelfService patches only submitted keys, refuses non-user_editable ones (NotEditable), null removes a value; both keep orphaned stored keys"
  - "Value errors are AttributeError::Invalid(Vec<JSON pointer>) (/name, /name/0), never values; a stale stored value that no longer validates blocks further writes until corrected"
  - "Account-page attribute edits need the settings-flow binding but no recent sign-in (like profile edits)"
  - "user_attributes_updated details = count of changed attributes (no dynamic field-name constructor exists in AuditDetails; values never logged); a no-op write is neither stored nor audited"
  - "Only user_editable attributes appear on the account page; editable attributes outside the supported shapes are shown read-only and refused if posted"

requirements-completed: [AUTH-14]

duration: ~75min
completed: 2026-11-26
---

# Phase 5 Plan 19: Custom user attributes Summary

**AttributeService validating tenant attribute definitions offline (meta-validated, 16 KiB / depth-32 caps, remote $ref refused, reserved-claim names refused, claim mapping collision-checked) and every value write against the definitions with JSON-pointer field errors, plus a no-JS account page that edits the user-editable attributes through typed inputs.**

## Performance

- **Duration:** about 75 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Files:** 8 (plus the phase deferred-items note)

## Accomplishments

### Task 1: AttributeService (commit 400d020)

`crates/anvil-core/src/service/attribute.rs`:

- `AttributeService { storage, clock, check: Arc<dyn AttributeSchemaCheck> }` (audit derived from storage + clock like the other services).
- `list`, `get` (NotFound), `effective_schema(tenant)`, `define(tenant, actor, &def, ctx)` (upsert; audited `attribute_defined`, target and details = name), `delete` (NotFound if absent; audited `attribute_deleted`; values kept), `user_values` (NotFound outside the tenant), `set_user_values(tenant, actor, user, &values, WriteMode, ctx)`, `check_own_binding(tenant, session, binding)`, `update_own(tenant, session, binding, &values, ctx)`.
- Pure functions: `check_definition(def, others, claims, check)`, `plan_values(defs, stored, submitted, mode, check) -> PlannedValues { values, changed }`, `effective_schema(defs)` (`type: object`, `additionalProperties: false`, `required`, each fragment given `$id: urn:anvilid:attribute:{name}` when absent; compiles with JsonSchemaCheck, asserted).
- `AttributeError { Invalid(Vec<String>), NotEditable(Vec<String>), FlowExpired, Core(CoreError) }`.

### Task 2: Account page (commit d83b1d1)

`crates/anvil-web/src/ui/account_attributes.rs`, `account_attributes.html`, the nav entry in `account_base.html`, en/de `account_attributes.ftl`.

**Supported input shapes** (annotations title, description, $comment, $schema, examples, default allowed):

| Schema | Input |
|---|---|
| `type: string` + `enum` of strings (non-empty) | `<select>` with an empty "Not set" option |
| `type: string` (+ minLength, maxLength, pattern, format email / uri / date) | `<input type=text / email / url / date>` (minlength/maxlength attrs) |
| `type: boolean` | checkbox, unchecked = false |
| `type: integer / number` (+ minimum, maximum, exclusiveMinimum, exclusiveMaximum, multipleOf) | `<input type=number>` (step 1 / any, min/max attrs) |

Anything else that is user-editable is shown read-only (JSON value); non-editable attributes are not shown. Field names `attr.{name}`, ids `attr-{name}`, errors `attr-{name}-error`, read-only values `attr-{name}-value`, form `attributes-form`, submit `attributes-form-submit`, empty state `attributes-none`, nav `account-nav-attributes`. Labels come from the schema `title` (else the name).

Page behaviour: no session = 303 to sign-in; POST needs the settings-flow binding (flow id, CSRF token, flow cookie; otherwise the `csrf` page, 403) and passes the Fetch-Metadata layer; valid = 200 `attributes.saved`; invalid = 400 `attributes.invalid` with marked fields and the typed text shown again; non-editable or read-only attribute posted = 400 `attributes.not_editable`, nothing saved (binding is checked first); expired flow = 400 `account.flow_expired` with a fresh flow. `Cache-Control: no-store`, no script.

## Security tests (security_attributes.rs)

- `attribute_schema_remote_ref_refused`: https/http-metadata/file/nested/`$id`-relative refs refused fast, nothing stored or audited; a local `#/$defs` ref works and validates.
- `attribute_schema_size_capped`: >16 KiB, depth > 32, meta-invalid (bad type, negative minLength, bad pattern, draft-07, non-object) refused; reserved/malformed names (sub, email, name, email_verified, Dept, 1x, empty) refused.
- `attribute_pattern_is_linear_time`: `^(a+)+$` against 50 KiB in < 1 s; look-ahead pattern refused.
- `attribute_values_validated_on_write`: enum violation `/department`, unknown key `/shoe_size`, missing required `/cost_center`, wrong type; self-service non-editable refused; nothing stored/audited on refusal; schema narrowing and deletion keep stored values; orphaned key kept on later writes and refused if written; effective schema compiles.
- `attribute_other_tenant_user_refused`: writes/reads of a user via another tenant are NotFound, nothing audited; definitions isolated per tenant.

Core unit tests (service::attribute, 11): definition acceptance, bad/reserved names, schema issues and size, claim collisions (and replacing a definition does not collide with itself), field pointers, unknown keys (pointer escaping), required, self-service non-editable and null removal, orphan keys kept, nested pointer prefixing and no-op detection, effective schema assembly.

Web lib tests (ui::account_attributes, 5): supported shapes, complex shapes not editable, typed submission parsing, read-only shapes locked, pointer-to-field mapping.

account_attributes.rs (9): sign-in redirect, nav entry only with user-editable attributes (seven others unchanged), typed inputs, valid saves + audit (actor/target = user, no values in details) + clearing + no-op, invalid values with field errors, non-editable refusal, CSRF binding (missing/wrong token, missing flow id, missing flow cookie, cross-site Fetch-Metadata), expired flow, German page.

## Task Commits

1. **Task 1: AttributeService** - `400d020` (feat)
2. **Task 2: Account page editing** - `d83b1d1` (feat)
3. Deferred item note - `4f965c1` (docs)

## Verification run

- `cargo test -p anvil-core --lib service::attribute`: 11 passed.
- `cargo test -p anvil-web --test security_attributes`: 5 passed.
- `cargo test -p anvil-web --test account_attributes`: 9 passed.
- `cargo test -p anvil-web --test i18n_catalogs --test security_csrf --test render --test account_profile`: 15 + 4 + 13 + 9 passed (en/de parity, template compile).
- `cargo test -p anvil-web --lib account_attributes`: 5 passed.
- `cargo clippy -p anvil-core -p anvil-web --lib --tests --locked`: no warnings in this plan's files.
- `rustfmt --edition 2024` on all Rust files of this plan.
- All runs on the default SQLite backend. Postgres (`ANVILID_TEST_DB`) and e2e not run here (left for CI).

## Decisions Made

See key-decisions in the frontmatter. The main ones: per-fragment validation instead of validating the assembled document (the adapter's caps would otherwise reject tenants whose combined schema exceeds 16 KiB / depth 32, and `#/$defs` refs inside fragments would break); orphaned values are carried over; PUT-style `define`.

## Deviations from Plan

### Auto-fixed / design adjustments

**1. [Rule 3 - Blocking] Binding check composed in the attribute service**
- **Issue:** AccountService's binding check without re-auth (`open_with`) is private, and account.rs is not in this plan's files. The only public check (`check_link_start`) requires a recent sign-in.
- **Fix:** `AttributeService::check_own_binding` composes the public `service::flow::check_binding` and `SettingsState` (flow kind, tenant, cookie + CSRF, owner) exactly like `open_with(reauth = false)`. `check_binding` stays the single implementation of the token comparison.
- **Commit:** 400d020

**2. [Rule 1 - Correctness] Per-fragment validation, still "against the effective schema"**
- **Issue:** Validating the assembled document through `JsonSchemaCheck::validate` would fail closed once the combined schema exceeds the per-schema caps, and nested fragments' `#/$defs` refs would resolve against the wrong root.
- **Fix:** object-level rules (unknown keys, required) checked in the service, each value against its fragment; `effective_schema` (with per-fragment `$id`) is exposed and asserted to compile.

**3. Plan field naming:** the plan sketched `set_user_values(actor, user, values, editable_only: bool)`; implemented as `WriteMode::{Replace, SelfService}` plus `update_own` for the account page.

**4. TDD order:** tests and implementation were written in the same commit per task (no separate failing-test commit).

### Deferred

- The "Attributes" nav entry needs `account_attributes_nav` from each account handler; only the attributes page sets it (other account handlers are not owned by 05-19). Logged in deferred-items.md.

## Issues Encountered

- Another wave-4 plan's in-progress `service/role.rs` (05-12) and `protocol/token.rs` (missing `metrics_util`) briefly broke the core lib-test and web lib-test builds; both were fixed by their owners before re-runs. Nothing worked around.
- A test fixture named `website` was correctly refused as a reserved standard claim; renamed to `homepage`.

## Self-Check: PASSED
