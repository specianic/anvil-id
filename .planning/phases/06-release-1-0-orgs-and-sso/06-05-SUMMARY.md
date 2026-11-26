---
phase: 06-release-1-0-orgs-and-sso
plan: 05
subsystem: core-policy
tags: [organizations, saml, domains, home-realm, mfa, claims, pure-core]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-01 psl/idna in anvil-core; 06-02 Organization, OrgClaims, OrgClientPolicy, SamlConfig, SamlAssertionData, SamlIdentity, ORG_ADMIN_SCOPE"
provides:
  - policy::home_realm (normalize_domain, DomainError, email_domain, RoutedDomain, Route, route)
  - policy::domain_verification (record_name, record_value, new_token, token_bytes, matches)
  - policy::org_claims (ActiveOrg, resolve_active_org, org_claims_json, bound_org_admin_scope)
  - policy::mfa::effective_policy_for (tenant, org, client)
  - saml::request (request_id, AuthnRequestParams, authn_request, relay_state, split_relay_state, sp_metadata)
  - saml::validate (SamlExpected, SamlReject, check, replay_key, replay_expiry)
  - SamlAssertionData.has_conditions
affects: [06-09, 06-10, 06-13, 06-15, 06-16, 06-17, 06-18, 06-19]

tech-stack:
  added: []
  patterns:
    - "Security decisions as pure functions taking caller bytes and caller `now`"
    - "One reason code per SAML check (str_enum), used as the audit reason"

key-files:
  created:
    - crates/anvil-core/src/policy/home_realm.rs
    - crates/anvil-core/src/policy/domain_verification.rs
    - crates/anvil-core/src/policy/org_claims.rs
    - crates/anvil-core/src/saml/mod.rs
    - crates/anvil-core/src/saml/request.rs
    - crates/anvil-core/src/saml/validate.rs
  modified:
    - crates/anvil-core/src/policy.rs
    - crates/anvil-core/src/policy/mfa.rs
    - crates/anvil-core/src/policy/claims_mapping.rs
    - crates/anvil-core/src/lib.rs
    - crates/anvil-core/src/model/saml.rs
    - crates/anvil-core/src/model/mod.rs

key-decisions:
  - "SamlAssertionData gains has_conditions: bool so a missing Conditions element and a Conditions without NotOnOrAfter get separate reason codes (06-09 must set it)"
  - "Optional org policy without a requested org resolves to NoOrg even for a single membership (plan behaviour table, not the looser Pattern 3 wording)"
  - "Requested org matches the canonical lowercase hyphenated UUID first, then the exact slug; an id match wins over a lookalike slug"
  - "Domains: one trailing root dot is accepted and dropped; numeric last labels (1.2.3, 0x7f) count as IP literals; a private-section suffix (github.io) is refused but names under it (acme.github.io) are accepted"
  - "Challenge tokens use the uppercase RFC 4648 base32 alphabet; token_bytes accepts only the canonical 26-character form"

requirements-completed: []

duration: ~20min
completed: 2026-11-26
---

# Phase 6 Plan 05: Pure core (org policy, SAML validation rules, domain rules) Summary

**Every ORG-02/03/04 decision now exists as a pure, tested function in anvil-core. This covers domain normalisation and home-realm routing, the DNS TXT challenge format, active-org resolution with org claims and `org:admin` bounding, strictest-wins MFA with the org, and the SAML AuthnRequest/RelayState/metadata builders with one reason code per assertion check.**

Requirements ORG-02, ORG-03 and ORG-04 are prepared, not ticked. Only the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 20 min (09:37Z to 09:47Z, plus reading beforehand)
- **Tasks:** 3/3
- **Files:** 6 created, 6 modified

## Task Commits

1. **Task 1, domain rules, routing, verification record:** `977cee4`
2. **Task 2, active org, org claims, org:admin bounding, MFA with org:** `634cbe5`
3. **Task 3, SAML request, RelayState, SP metadata, assertion validation:** `0b45ee0`

## Function signatures

```rust
// policy::home_realm
pub fn normalize_domain(input: &str) -> Result<String, DomainError>;
pub enum DomainError { Empty, Scheme, Port, Path, Wildcard, IpLiteral, Idna, TooFewLabels,
                       LabelLength, TooLong, Reserved, PublicSuffix, UnknownSuffix } // From<_> for CoreError (Validation "domain")
pub fn email_domain(email: &str) -> Option<String>;
pub struct SsoTarget { pub org_id: OrgId, pub connection_id: ConnectionId }
pub struct RoutedDomain { pub domain: String, pub target: SsoTarget }
impl RoutedDomain { pub fn from_org_domain(d: &OrgDomain) -> Option<Self> } // verified && routing && connection
pub enum Route { Sso(SsoTarget), Local }
pub fn route(email: &str, routed: &[RoutedDomain]) -> Route;

// policy::domain_verification
pub const RECORD_LABEL: &str = "_anvilid-challenge";
pub const VALUE_PREFIX: &str = "anvilid-domain-verification=";
pub fn record_name(domain: &str) -> String;            // "_anvilid-challenge.{domain}."
pub fn record_value(token: &str) -> String;
pub fn new_token(bytes: [u8; 16]) -> String;          // 26 chars, base32, no padding
pub fn token_bytes(token: &str) -> Option<[u8; 16]>;
pub fn matches(records: &[Vec<Vec<u8>>], expected: &str) -> bool;

// policy::org_claims
pub enum ActiveOrg { NoOrg, Selected(Organization), NeedsChoice, Denied, Refused }
pub fn resolve_active_org(policy: OrgClientPolicy, requested: Option<&str>, memberships: &[Organization]) -> ActiveOrg;
pub fn org_claims_json(claims: Option<&OrgClaims>, settings: &ClaimMappingSettings, target: TokenTarget, granted: &Scope) -> Map<String, Value>;
pub fn bound_org_admin_scope(requested: &Scope, active_org_permissions: Option<&[String]>) -> Scope;

// policy::mfa
pub fn effective_policy(tenant: MfaPolicy, client: Option<MfaPolicy>) -> MfaPolicy; // unchanged signature, delegates
pub fn effective_policy_for(tenant: MfaPolicy, org: Option<MfaPolicy>, client: Option<MfaPolicy>) -> MfaPolicy;

// saml (mod.rs): NS_PROTOCOL, NS_ASSERTION, NS_METADATA, BINDING_HTTP_POST, saml_instant(t) -> String
// saml::request
pub fn request_id(bytes: [u8; 16]) -> String;          // "_" + 32 hex
pub struct AuthnRequestParams<'a> { sp_entity_id, acs_url, destination, request_id, issue_instant, name_id_format, force_authn }
pub fn authn_request(p: &AuthnRequestParams<'_>) -> String;
pub fn relay_state(flow: FlowId, nonce: [u8; 16]) -> String;               // 59 bytes
pub fn split_relay_state(value: &str) -> Option<(FlowId, [u8; 16])>;      // canonical form only, <= 80 bytes
pub fn sp_metadata(entity_id: &str, acs_url: &str, name_id_format: NameIdFormat) -> String;

// saml::validate
pub const DEFAULT_SKEW: Duration = 90 s; MAX_ISSUE_AGE = 1 h; MAX_REPLAY_TTL = 1 h;
pub const STATUS_SUCCESS: &str; pub const CM_BEARER: &str;
pub struct SamlExpected { sp_entity_id, acs_url, request_id, idp_entity_id, attributes: SamlAttributeMapping, skew: Duration }
pub fn check(data: &SamlAssertionData, expected: &SamlExpected, now: OffsetDateTime) -> Result<SamlIdentity, SamlReject>;
pub fn replay_key(idp_entity_id: &str, assertion_id: &str) -> SecretHash;  // sha256(idp || 0x00 || id)
pub fn replay_expiry(not_on_or_after: OffsetDateTime, now: OffsetDateTime) -> OffsetDateTime; // min(nooa, now+1h), >= now+90s
```

## SamlReject reason codes (check order)

| Code | Check |
|---|---|
| `destination_mismatch` | Response Destination missing or not the ACS URL |
| `in_response_to_mismatch` | Response InResponseTo missing or not the request ID |
| `status_not_success` | StatusCode is not Success |
| `response_issuer_mismatch` | Response Issuer present and not the IdP entity ID |
| `issue_instant_invalid` | IssueInstant missing, later than now+skew, or earlier than now-1h |
| `missing_assertion_id` | empty assertion ID (replay guard needs it) |
| `assertion_issuer_mismatch` | assertion Issuer is not the IdP entity ID |
| `empty_name_id` | NameID empty or whitespace |
| `transient_name_id` | NameID Format is the SAML 2.0 transient URN |
| `no_bearer_confirmation` | no SubjectConfirmation, or its method is not bearer |
| `recipient_mismatch` | SubjectConfirmationData Recipient missing or not the ACS URL |
| `confirmation_in_response_to_mismatch` | SubjectConfirmationData InResponseTo missing or wrong |
| `confirmation_missing_not_on_or_after` | SubjectConfirmationData without NotOnOrAfter |
| `confirmation_expired` | SubjectConfirmationData NotOnOrAfter <= now-skew |
| `missing_conditions` | no Conditions element |
| `conditions_missing_not_on_or_after` | Conditions without NotOnOrAfter |
| `not_yet_valid` | NotBefore > now+skew |
| `conditions_expired` | Conditions NotOnOrAfter <= now-skew |
| `missing_audience_restriction` | no AudienceRestriction |
| `audience_mismatch` | some AudienceRestriction (including an empty one) lacks the SP entity ID |
| `missing_authn_statement` | no AuthnStatement |

Identity: `subject` = NameID. Email, given name, family name and name each come from the first value of the mapped attribute, and an empty value maps to `None`.

## Tests

- `policy::home_realm` (28): `normalises_case_and_whitespace`, `normalises_to_a_label`, one `refuses_*` test per rule (empty, scheme, port, path, wildcard, single_label, localhost, local, internal, test, example, invalid, ipv4, ipv6, icann_public_suffix, private_public_suffix, long_label, empty_label, long_domain at 254/253 bytes, unknown_suffix, bad_idna), `domain_errors_map_to_validation`, `email_domains`, `routes_exact_domain_only`, `routes_to_the_matching_domain`, `only_verified_routed_domains_with_a_connection_route`.
- `policy::domain_verification` (6, one proptest): `record_name_and_value`, `token_known_vectors`, `token_bytes_refuses_non_canonical`, `matches_an_exact_record`, `matches_refuses_near_misses` (prefix, suffix, whitespace, case, empty token, split over two RRs, empty RRset), proptest `token_is_26_base32_chars_and_round_trips`.
- `policy::org_claims` (16): `off_without_request_has_no_org`, `off_with_request_is_refused`, `optional_without_request_has_no_org`, `requested_membership_is_selected_by_id_or_slug`, `requested_non_member_is_denied`, `request_matching_is_exact_and_never_by_display_name`, `id_match_wins_over_a_lookalike_slug`, `required_without_request`, `no_org_emits_nothing`, `id_and_slug_are_always_emitted`, `default_org_roles_are_gated_by_the_roles_scope`, `default_org_permissions_go_to_the_access_token_only`, `empty_org_roles_are_omitted`, `renamed_org_rules_are_used_but_never_shadow_reserved_claims`, `org_admin_scope_needs_the_permission_in_the_active_org`, `bounding_leaves_other_scopes_alone`.
- `policy::mfa` (new): `effective_policy_with_org_examples`, `effective_policy_with_org_exhaustive` (3x4x4 = 48 cases), `effective_policy_delegates_without_org`.
- `saml::tests` (3): escaping, invalid XML characters, UTC instants.
- `saml::request::tests` (8): `request_ids_are_underscore_and_32_hex`, `authn_request_carries_exactly_the_values` (exact string), `prompt_login_sets_force_authn`, `authn_request_escapes_every_input`, `relay_state_round_trips_within_80_bytes`, `malformed_relay_state_is_refused` (12 shapes), `sp_metadata_shape`, `sp_metadata_escapes_inputs`.
- `saml::validate::tests` (32): `valid_assertion_yields_identity`, `optional_parts_may_be_absent`, `empty_attribute_values_are_not_mapped`, one `rejects_*` test per reason code (with boundary tests at exactly the skew), `reason_codes_are_distinct_and_round_trip`, `replay_key_vector`, `replay_key_known_answer` (SHA-256 of `61 00 62`), `replay_expiry_bounds`.

## Files Created/Modified (beyond files_modified)

- `crates/anvil-core/src/policy/claims_mapping.rs`: `rule_applies` and `sorted_unique` are now `pub(crate)`, so org claims reuse the one gating implementation (the plan says "call it; do not copy it"). The plan's verify step already runs this module's tests, and 06-04 lists `policy/*` as 06-05's.
- `crates/anvil-core/src/model/saml.rs`: new field `SamlAssertionData.has_conditions: bool`.
- `crates/anvil-core/src/model/mod.rs`: `pub(crate) use ids::str_enum;`, so `SamlReject` can use the shared macro (`ids` is a private module).

## Decisions Made

See key-decisions in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Missing Conditions was indistinguishable from Conditions without NotOnOrAfter**
- **Found during:** Task 3
- **Issue:** `SamlAssertionData` (06-02) had no field telling whether a `Conditions` element was present, so the two required reason codes could not be told apart.
- **Fix:** added `has_conditions: bool` (it derives Default, so no existing literal broke; anvil-web's 06-04 adapter skeleton still builds). **06-09 must set it when extracting.**
- **Files modified:** crates/anvil-core/src/model/saml.rs
- **Commit:** 0b45ee0

**2. [Rule 3 - Blocking] `str_enum!` was unreachable outside `model`**
- **Fix:** a crate-private re-export in model/mod.rs (one line). No second copy of the macro.
- **Commit:** 0b45ee0

**3. [Rule 3 - Blocking] Claim rule helper was private**
- **Fix:** `pub(crate)` on `rule_applies` / `sorted_unique` in claims_mapping.rs.
- **Commit:** 634cbe5

**4. [Process] TDD commits**
- The tests were written with each module and run before committing, but each task was committed as one `feat` commit, with no separate RED commit. Peers build the same working tree, and a RED commit with panicking bodies would put stubs on main.

**5. [Additions within scope]**
- `missing_assertion_id`: an extra reason code, because the replay key needs the ID.
- `RoutedDomain::from_org_domain`.
- `token_bytes`: the inverse of `new_token`, for the round-trip property and for validating stored tokens.
- `From<DomainError> for CoreError`.

## Issues Encountered

- 06-04 was landing ports at the same time. The first test run failed in its in-progress `Storage` fakes (missing `organizations`). It built again a few minutes later, and none of 06-05's files were involved.

## Verification

- `cargo test -p anvil-core --lib`: 925 passed (whole lib, after all three tasks)
- `cargo test -p anvil-core --lib -- policy:: saml::`: 161 passed
- `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean
- `cargo check -p anvil-web`: builds (with the new SamlAssertionData field)
- `scripts/check-deps.sh`: dependency rules OK (no new anvil-core dependency; psl and idna now used)
- `scripts/check-release-graph.sh`: release graph OK

## Not run here

- `scripts/check-security-tests.sh` stopped with "cargo test --list failed". Some test binary in the working tree did not compile while peers' in-progress anvil-web files (untracked adapters/ui/admin modules) were in flight. The Phase 6 security-test map entries belong to later plans and the gate.
- No Postgres, e2e or conformance runs. This plan has no I/O.

## Next Phase Readiness

- 06-09 (SAML XML adapter): extract into `SamlAssertionData` including `has_conditions`, then call `saml::validate::check`. Use `replay_key`/`replay_expiry` with `ReplayKind::SamlAssertionId`.
- 06-10/06-17 (domains): `normalize_domain` at write, `new_token(random 16 bytes)`, `record_name`/`record_value` for the UI, and `matches` on the hickory RRset.
- 06-13/06-19 (authorize/tokens): `resolve_active_org`, `org_claims_json`, `bound_org_admin_scope`; switch `mfa_context` to `effective_policy_for`.
- 06-16 (identifier-first): `route` plus `RoutedDomain::from_org_domain`.

## Self-Check: PASSED
