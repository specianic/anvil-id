---
phase: 06-release-1-0-orgs-and-sso
plan: 13
subsystem: oauth-tokens
tags: [organizations, org-claims, authorize, token, refresh, userinfo, introspection, org-admin, discovery]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-02 AuthorizationParams.organization, OrgClaims, OrgClientPolicy, code/family org_id; 06-04 OrgRepo + RoleRepo::roles_for_user_in_org; 06-05 resolve_active_org, org_claims_json, bound_org_admin_scope; 06-07/06-08 storage on both backends"
provides:
  - "`organization` authorization parameter (validate step 13, MAX_ORGANIZATION_LEN = 128)"
  - "service::authorize::bind_active_org + OrgRefusal; active org bound to code and token family"
  - "UserClaimSource::load(.., active_org) with `org: Option<OrgClaims>`, lost_active_org(), org_claims(), bound_org_admin()"
  - "claims::merge_org_claims; token::sign_access_token_with(.., extra, org), token::sign_id_token_with"
  - "membership re-check at code exchange and every refresh (invalid_grant + family revoked)"
  - "IntrospectionResponse.claims (flattened) and IntrospectionService.attribute_check; introspection::introspection_claims"
  - "discovery claims_supported: org_id, org_slug, org_roles, org_permissions"
  - "test helpers token_support::{register_with, issue_code_in_org}"
affects: [06-14, 06-19, 06-21, 06-26]

tech-stack:
  added: []
  patterns:
    - "Org claims are inserted by the token builders (merge_org_claims) before mapped extras; mapped extras can never set reserved names, so org claims only ever come from org_claims_json"
    - "One UserClaimSource load per issuance/read feeds tenant claims, org claims and scope bounding"

key-files:
  created:
    - crates/anvil-web/tests/org_claims.rs
    - crates/anvil-web/tests/snapshots/discovery__claims_supported.snap
  modified:
    - crates/anvil-core/src/oauth/authorize_request.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-core/src/service/role.rs
    - crates/anvil-core/src/service/token.rs
    - crates/anvil-core/src/service/claims.rs
    - crates/anvil-core/src/service/userinfo.rs
    - crates/anvil-core/src/service/introspect.rs
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/src/protocol/introspect.rs
    - crates/anvil-web/tests/token_support/mod.rs
    - crates/anvil-web/tests/discovery.rs

key-decisions:
  - "The active org is resolved after the session, step-up and consent decisions, right before the code is issued, in both the direct path and continue_request (after the stored request is deleted)"
  - "A grant whose org vanished or which the user left: token endpoint revokes the family (reason Admin) and answers the single invalid_grant; UserInfo answers invalid_token; introspection answers {\"active\":false}"
  - "The code exchange also refuses a code whose org_id differs from its family's (invalid_grant)"
  - "Introspection recomputes roles/permissions/attributes/org claims at introspection time for JWT and opaque tokens alike (like UserInfo), gated by the token's scope with the access-token target"
  - "client_credentials strips org:admin silently (200 without it, never invalid_scope), so a client allowed org:admin cannot obtain it on its own behalf"
  - "build_code keeps its signature (anvilid tests use it); AuthorizeService::issue sets org_id on the built code and family"
  - "No new fields on AccessTokenInput/IdTokenInput (admin_support constructs them); org claims travel as a separate map to sign_access_token_with / sign_id_token_with"

requirements-completed: []

duration: ~45min
completed: 2026-11-26
---

# Phase 6 Plan 13: Org claims in the grant Summary

**Tokens now say which customer org the user acts for. `/authorize` takes `organization` (id or slug). After sign-in the org is resolved from the client's policy, the parameter and the user's memberships, and bound to the code and token family, never to a cookie or the session. The ID token, JWT access token, UserInfo and introspection carry `org_id`, `org_slug`, `org_roles` and `org_permissions`, recomputed at every refresh. A removed member's refresh gets invalid_grant, `org:admin` is bounded per org, and client credentials never get it. Opaque tokens and introspection now carry the same role and org claims as JWTs (05-12 carry-over closed).**

ORG-02 is delivered for tokens but not ticked. Only the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 45 min (reading from about 11:35; commits 12:09 and 12:16 +01:00)
- **Tasks:** 2/2
- **Files:** 2 created, 11 modified

## Task Commits

1. **Task 1: organization parameter, active org on code and family, UserClaimSource org dimension** `7b86095` (feat). This commit also has the token.rs, claims.rs and userinfo.rs changes, because `UserClaimSource::load` changed signature and its callers had to compile with it.
2. **Task 2: introspection claims, discovery, org claim tests** `067be84` (feat)

## Claim rules

| Surface | org_id / org_slug | org_roles (default rule) | org_permissions (default rule) | Tenant roles/permissions |
|---|---|---|---|---|
| ID token | yes | with scope `roles` | no | unchanged (0.4 rules) |
| JWT access token | yes | with scope `roles` | yes | unchanged |
| UserInfo (JWT or opaque token) | yes | with scope `roles` | no | unchanged |
| Introspection (JWT or opaque user token) | yes | with scope `roles` | yes | roles/permissions/attributes as in the access token (new) |
| client_credentials token | never | never | never | none |

- Without an active org, no surface carries anything org-related.
- Renamed org rules (tenant claim mapping) are honoured through `org_claims_json`.
- Org claims are inserted by the builders first. Mapped extras skip reserved names (`org_*` are reserved) and keys that are already set, so a mapped attribute can never set or override `org_id`. That holds in the access token, the ID token (protocol-claim filter), UserInfo (org claims are applied last) and introspection.
- Org roles are the roles held in the org only (`roles_for_user_in_org`): tenant roles assigned in the org plus org-owned roles. Tenant-wide claims stay tenant-wide.

## Error mapping

| Situation | Answer |
|---|---|
| `organization` repeated | `invalid_request` (duplicated parameter), redirected |
| `organization` > 128 bytes or with control characters | `invalid_request`, redirected |
| `organization` sent to a client with policy `off` (also if the policy changed while the user signed in) | `invalid_request`, redirected |
| requested org is not one of the user's memberships (by id or slug, unknown org included) | `access_denied`, redirected |
| policy `required`, user in no org | `access_denied` |
| policy `required`, several orgs, `prompt=none` | `interaction_required` |
| policy `required`, several orgs, no `prompt=none` | error page `invalid_request`, detail "organization selection required" (**TRANSITIONAL(06-19)**) |
| `prompt=none` without a session | `login_required` (decided before the org) |
| code exchange or refresh, org gone or user no longer a member | `invalid_grant` (single description), family revoked with reason `admin` |
| code `org_id` differs from its family's | `invalid_grant` |
| UserInfo with a token whose org the user left | `invalid_token` |
| introspection of such a token | `{"active":false}` |

**TRANSITIONAL(06-19) site:** `crates/anvil-core/src/service/authorize.rs`, `AuthorizeService::active_org`, the `OrgRefusal::SelectionRequired` arm. The test `org_claims::prompt_none_multi_org_required_is_interaction_required` asserts that page and also carries a TRANSITIONAL(06-19) comment, so 06-19 has to update the test when it adds the switcher.

## org:admin (decision Q1)

`issued_scope` applies `bound_admin_scope` (system tenant, unchanged) and then `UserClaimSource::bound_org_admin` in every tenant. `org:admin` stays only when the user's permissions in the active org include `org:admin`. The refresh token keeps the full grant, so the scope tracks role changes at each refresh in both directions, never beyond the grant. `client_credentials` applies `bound_org_admin_scope(scope, None)`.

## Negative tests (for the 06-26 security map)

crates/anvil-web/tests/org_claims.rs:
- `removed_member_refresh_is_invalid_grant`: refresh gives invalid_grant, then UserInfo invalid_token, introspection inactive
- `grant_bound_to_an_org_the_user_is_not_in_is_invalid_grant`: belt and braces, a family that was never revoked
- `org_admin_scope_only_with_org_admin_permission`: dropped, kept, dropped at refresh
- `org_admin_scope_never_without_active_org`: a tenant-wide role carrying the string does not count either
- `client_credentials_never_grants_org_admin`: JWT and opaque; explicit, alone and default scope
- `mapped_attribute_cannot_spoof_org_claims`: the admin API answers 422 for `org_id`/`org_slug`/`ORG_ID`; a definition stored directly never wins
- `organization_parameter_refused_for_off_client`: also before sign-in, repeated and oversized values
- `nonmember_organization_is_access_denied`: by slug, by id, unknown; required without membership
- `prompt_none_multi_org_required_is_interaction_required`: also login_required without a session, and no silent pick
- `no_org_claims_without_active_org`

Positive tests: `org_claims_in_id_token_access_token_userinfo_introspection`, `opaque_token_introspection_and_userinfo_carry_roles_and_org_claims`, `refresh_recomputes_org_roles`.

Unit tests:
- `oauth::authorize_request`: `organization_is_parsed_for_org_clients`, `repeated_organization_is_invalid_request`, `oversized_or_control_organization_is_invalid_request`, `organization_is_refused_for_clients_without_organizations`
- `service::authorize::active_org_binding`
- `service::role`: `org_admin_scope_follows_the_active_org_permissions`, `org_claims_only_with_an_active_org`
- `service::claims::org_claims_never_replace_protocol_claims`
- `service::introspect::introspection_claims_never_shadow_response_members`
- `discovery::claims_supported_lists_the_org_claims` (insta snapshot `discovery__claims_supported.snap`)

## Files Created/Modified (beyond files_modified)

- `crates/anvil-web/src/protocol/introspect.rs`: one line, `attribute_check: self.attribute_check()` in `introspection_service()`. It was needed because `IntrospectionService` got the attribute check, so attribute claims in introspection match the access token.
- `crates/anvil-web/tests/snapshots/discovery__claims_supported.snap`: a new snapshot. The plan's "update the insta snapshot" assumed a discovery snapshot already existed, and there was none.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Reserved org claims would have been dropped by the existing merge rules**
- **Found during:** Task 2
- **Issue:** `org_id` and the other org claims are in `RESERVED_CLAIMS`. `merge_access_token_extras` and the ID token's protocol-claim filter would therefore have discarded them if they were passed as mapped extras.
- **Fix:** `claims::merge_org_claims`, plus a separate `org` map on `sign_access_token_with` and the new `sign_id_token_with`. `AccessTokenInput` and `IdTokenInput` keep their fields, because `tests/admin_support` (not this plan's file) constructs them.
- **Commit:** 7b86095

**2. [Rule 2 - Critical] Membership lost at issuance**
- Besides answering invalid_grant, the token endpoint revokes the family, so a lost membership cannot be retried. A code whose `org_id` differs from its family's is also refused.
- **Commit:** 7b86095

**3. [Process] TDD commits**
- Tests were written together with each change and run before committing. Each task is one `feat` commit, with no separate RED commit, because peers build the same tree.

**4. [Scope note] Task split**
- token.rs, claims.rs and userinfo.rs landed in the Task 1 commit (see Task Commits).

## Verification

- `cargo test -p anvil-core --lib`: 964 passed
- `cargo test -p anvil-web --test org_claims`: 13 passed
- `cargo test -p anvil-web` with `--test discovery --test token --test userinfo --test rbac_claims --test security_introspect_revoke --test authorize --test authorize_prompt --test access_token_format --test attribute_claims --test security_refresh --test security_userinfo --test security_rbac --test resource_indicators --test consent`: all green (14/8/7/9/16/13/18/5/1/8/11/12/17/19)
- `cargo build --workspace --all-targets`: OK
- `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean
- `scripts/check-release-graph.sh`: OK
- rustfmt (edition 2024) on every touched file

## Not run here

- `cargo clippy -p anvil-web --all-targets -- -D warnings` stops in `crates/anvil-web/src/admin/auth.rs` (two `manual_contains` lints). That is a peer's uncommitted wave-4 file, so clippy never reached this plan's web files.
- Postgres, e2e and conformance runs were left for CI. The org storage paths these tests use are covered on Postgres by 06-08's contract suite.
- `scripts/check-security-tests.sh`: the map belongs to 06-26. The names are listed above.

## Next Phase Readiness

- 06-19: replace the `OrgRefusal::SelectionRequired` arm with `AuthorizeOutcome::SelectOrganization`. The chosen org goes into the stored request's `params.organization`, and `active_org` then resolves it as usual. Wire `effective_policy_for` into `mfa_context`. Update `prompt_none_multi_org_required_is_interaction_required`.
- 06-14/06-21 (org admin routes): tokens now carry `org:admin` only together with `org_id` of an org where the user holds it. Check both on the route.
- deferred-items (06-09 note): putting the org claim mapping on the admin DTO is still open. This plan does not own `admin/tenants.rs`.

## Self-Check: PASSED
