---
phase: 05-release-0-4-operate-it
plan: 10
subsystem: foundation
tags: [claims, rbac, webhooks, standard-webhooks, hmac, declarative-config, json-schema, attributes]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 model (ClaimRule, ClaimMappingSettings, AttributeDefinition, WebhookEvent, config_doc), 05-02 ports and skeletons (AttributeSchemaCheck, AppState::attribute_check)
provides:
  - policy::claims_mapping (mapped_claims, validate_mapping, RESERVED_CLAIMS)
  - policy::webhook_event (webhook_event, test_event): AuditAction to ids-only payloads
  - anvil_jose::webhook (signature_v1, generate_webhook_secret, parse_webhook_secret)
  - service::config (plan, plan_excluding, check_unique_keys, render, SecretRef)
  - adapters::attribute_schema::JsonSchemaCheck and a live AppState::attribute_check()
affects: [05-12, 05-14, 05-16, 05-19, 05-20, 05-23]

tech-stack:
  added: []
  patterns:
    - "Pure policy functions take caller-supplied predicates for anything needing I/O or secrets (attribute validity, secret equality, runtime-client test)"
    - "Exhaustive match on AuditAction in webhook_event::classify: a new action does not compile until someone decides whether it is a webhook event"

key-files:
  created:
    - crates/anvil-jose/src/webhook.rs
  modified:
    - crates/anvil-jose/src/lib.rs
    - crates/anvil-core/src/policy/claims_mapping.rs
    - crates/anvil-core/src/policy/webhook_event.rs
    - crates/anvil-core/src/service/config.rs
    - crates/anvil-web/src/adapters/attribute_schema.rs

key-decisions:
  - "Reserved claims are compared case-insensitively, and claim names must be unique case-insensitively (avoids Sub/sub confusion in consumers)"
  - "mapped_claims skips reserved or already-taken claim names at runtime as well, so stored configuration that bypassed validate_mapping can never override sub/iss/aud"
  - "UserAttributesUpdated maps to user.updated (an attribute patch is a profile change); EmailChangeRequested does not emit"
  - "webhook_event takes (tenant_slug, &NewAuditEvent): target is a user id or session id per action; ids are copied only if bounded, without '@' or whitespace"
  - "Config plan: an omitted secret (None) keeps the current one; {configured:false} clears; inline values go through the caller's secrets_equal(SecretRef, &SecretInput)"
  - "ConfigPlan.deletes is the prune-only list (ConfigChange has no flag and config_doc.rs is not owned by this plan); render() labels each delete '(prune only)'"
  - "Dynamic/CIMD clients are excluded through plan_excluding(.., is_runtime_client) because ClientSection carries no registration source"
  - "JsonSchemaCheck refuses $schema values other than draft 2020-12 and non-object schemas (boolean schemas included); validate() fails closed with [\"\"] when the schema no longer passes the checks"

patterns-established: []

requirements-completed: []

duration: ~40min
completed: 2026-11-26
---

# Phase 5 Plan 10: Pure claim mapping, webhook events and signature, config diff, JSON Schema adapter Summary

**Claim mapping with collision validation, an ids-only AuditAction-to-webhook mapping, the Standard Webhooks v1 signature (checked against the spec's example vector), a pure tenant-config plan diff, and the offline draft 2020-12 JSON Schema adapter. AppState::attribute_check() now returns it.**

## Function signatures

### anvil-core `policy::claims_mapping`
- `pub const RESERVED_CLAIMS: &[&str]`, `pub const MAX_CLAIM_NAME_LEN: usize = 256`
- `pub struct ClaimInputs<'a> { roles: &'a [String], permissions: &'a [String], attribute_values: &'a Map<String, Value>, attributes: &'a [AttributeDefinition] }`
- `pub fn is_reserved_claim(claim: &str) -> bool`
- `pub fn mapped_claims(inputs: &ClaimInputs<'_>, settings: &ClaimMappingSettings, granted: &Scope, target: TokenTarget, is_valid: &dyn Fn(&AttributeDefinition, &Value) -> bool) -> Map<String, Value>`
- `pub fn validate_mapping(settings: &ClaimMappingSettings, attributes: &[AttributeDefinition]) -> Result<(), CoreError>` (`CoreError::Validation { field: "claim", .. }`)

### anvil-core `policy::webhook_event`
- `pub fn webhook_event(tenant_slug: &str, e: &NewAuditEvent) -> Option<WebhookEvent>`
- `pub fn test_event(tenant_slug: &str, at: OffsetDateTime) -> WebhookEvent`
- Payload: `{"type", "timestamp" (RFC 3339), "data": {"tenant", "user_id"?, "session_id"?, "client_id"?, "actor": {"kind", "id"?}}}`

### anvil-jose `webhook`
- `pub fn signature_v1(secret: &[u8], msg_id: &str, ts: i64, body: &[u8]) -> String` (returns `v1,<base64>`)
- `pub fn generate_webhook_secret() -> Zeroizing<String>` (`whsec_` + base64 of 32 random bytes)
- `pub fn parse_webhook_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>, JoseError>` (prefix, canonical base64, 24 to 64 bytes)
- Re-exported at the crate root.

### anvil-core `service::config`
- `pub struct SecretRef<'a> { kind: ConfigObjectKind, key: &'a str, field: &'static str }`
- `pub fn plan(current, desired, secrets_equal: &dyn Fn(&SecretRef<'_>, &SecretInput) -> bool) -> ConfigPlan`
- `pub fn plan_excluding(current, desired, secrets_equal, is_runtime_client: &dyn Fn(&str) -> bool) -> ConfigPlan`
- `pub fn check_unique_keys(doc: &TenantConfigDocument) -> Result<(), CoreError>`
- `pub fn render(plan: &ConfigPlan) -> String`
- Consts `TENANT_BRANDING_KEY = "(tenant)"`, `SMTP_KEY = "smtp"`. Field diffs use dotted paths (`settings.claims.permissions`); secret diffs have `before`/`after` = `None`.

### anvil-web `adapters::attribute_schema`
- `pub struct JsonSchemaCheck` (`new()`, `Default`), `impl AttributeSchemaCheck`
- `pub const MAX_SCHEMA_DEPTH: usize = 32`; size cap is `anvil_core::model::MAX_SCHEMA_BYTES` (16 KiB)
- `AppState::attribute_check()` returns `Some(Arc::new(JsonSchemaCheck::new()))`. The TRANSITIONAL(05-10) marker is gone.

## Negative tests (reject bad input)

- claims_mapping: `roles_are_gated_by_their_scope`, `ungated_permissions_go_to_the_access_token_only`, `arrays_are_deduplicated_sorted_and_omitted_when_empty`, `attribute_values_respect_validity_scope_and_target`, `missing_and_null_attribute_values_are_not_emitted`, `validate_mapping_rejects_reserved_claims`, `validate_mapping_rejects_role_attribute_collision`, `validate_mapping_rejects_two_attributes_with_the_same_claim`, `validate_mapping_rejects_malformed_names_and_scopes`, `mapping_never_overrides_reserved_or_earlier_claims_at_runtime`, proptest `output_never_contains_protocol_claims`
- webhook_event: `failures_never_emit`, `payloads_never_carry_personal_data` (no `@`, IP, user agent or trace id; only the allowed keys), `every_action_maps_as_specified` (all 80 actions)
- webhook: `signature_matches_spec_test_vector`, `signature_changes_with_every_input`, `signature_uses_the_decoded_key_not_the_string`, `parse_rejects_bad_secrets`
- config: `configured_secret_on_both_sides_is_unchanged`, `inline_secret_uses_the_supplied_equality_and_never_prints_it`, `inline_secret_against_an_unset_secret_is_an_update_without_asking`, `runtime_clients_are_excluded_from_both_sides`, `duplicate_natural_keys_are_rejected`
- attribute_schema: `remote_ref_is_refused_without_network`, `retriever_refuses_everything`, `redos_pattern_runs_in_linear_time`, `backtracking_only_patterns_are_refused`, `oversized_schema_is_refused`, `deeply_nested_schema_is_refused`, `email_format_is_validated`, `non_object_and_meta_invalid_schemas_are_refused`, `errors_never_echo_instance_values`

## Task Commits

1. **Task 1: claim mapping, webhook event mapping, webhook signature:** `1cbfb70` (feat)
2. **Task 2: config plan diff and JSON Schema adapter:** `d78d203` (feat)

## Verification run

- `cargo test -p anvil-jose --lib webhook`: 5 passed. Full `anvil-jose --lib`: 101 passed.
- `cargo test -p anvil-core --lib policy::claims_mapping` / `policy::webhook_event`: 21 passed (14 + 7, including the proptest). `service::config`: 14 passed. Full `anvil-core --lib`: 721 passed.
- `cargo test -p anvil-web --lib attribute_schema`: 10 passed. The 50 KiB `(a+)+$` instance validates well under 100 ms in a debug build.
- **Spec vector:** `signature_v1` reproduces the Standard Webhooks published example (`whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw`, `msg_p5jXN8AQM9LWM0D4loKWxJek`, `1614265330`, `{"test": 2432232314}` gives `v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=`). The research cites the spec but does not copy the vector. The values come from the spec's example and were also checked with an independent Python HMAC computation.
- `scripts/check-deps.sh`: OK.
- `cargo clippy -p anvil-core -p anvil-jose -p anvil-web --lib --tests --locked`: no warnings in this plan's files. The remaining warnings belonged to other wave-3 plans' in-progress files (oauth/cimd.rs, oauth/registration.rs, service/key.rs).
- `rustfmt --edition 2024 --check` on all six files: OK. `grep -rn "TRANSITIONAL(05-10)" crates`: none.
- The anvil-web build was blocked for about 3 minutes by 05-07's in-progress Postgres queries (no sqlx offline cache). It passed on the 4th retry without any change from this plan.

## Not run

- The full workspace test suite and clippy across the workspace (targeted runs only, per the shared rules).
- Postgres and Docker-backed tests (none touch this plan's code).

## Deviations from Plan

### Auto-fixed Issues

None beyond the interpretation choices listed in key-decisions:
- `SecretRef` did not exist; it is defined in service/config.rs.
- `render` is a free function, `service::config::render(&ConfigPlan)`, because ConfigPlan lives in config_doc.rs, which this plan does not own.
- `plan_excluding` was added for the dynamic/CIMD client exclusion. `plan` delegates to it.
- `RESERVED_CLAIMS` is a new list in claims_mapping. The ID-token protocol list in service/claims.rs is private and not owned by this plan. The new list is a superset (protocol, RFC 9068 and OIDC standard claims).

### Notes
- `grep -rn "base64::" crates` finds encoding.rs and also `crates/anvil-jose/src/kek.rs`, which predates this plan and is inside anvil-jose. Not touched (out of scope).

## Self-Check: PASSED
- All 5 implementation files exist (webhook.rs created; the four skeletons filled). Commits 1cbfb70 and d78d203 are present in `git log`.
