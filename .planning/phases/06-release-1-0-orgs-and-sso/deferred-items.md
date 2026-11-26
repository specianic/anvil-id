# Phase 6 deferred items

## From 06-02

- **Pre-existing flake (out of scope):** `model::credential::tests::totp_debug_redacts_the_sealed_seed`
  and `model::webhook::tests::debug_redacts_sealed_secrets` assert that the Debug output does not
  contain `"171"` (the byte `0xAB`). The output also contains UUIDv7 ids, whose timestamp prefix
  contained `171` (`019a2171-…`) for a few minutes on 2026-11-26, so both tests failed in that window
  and passed afterwards. Fix: assert on `"171, 171"` (the byte sequence) instead, as
  `model::organization` does.
- (from 06-05, for 06-09) `SamlAssertionData.has_conditions` (new bool) MUST be set by the XML extractor: `false` when the Assertion has no `<saml:Conditions>` element. Without it `missing_conditions` vs `conditions_missing_not_on_or_after` cannot be told apart; add an extraction test for both.

## From 06-09

- (out of scope, found while removing the 06-09 marker) `crates/anvil-web/src/admin/tenants.rs`
  says the org claim mappings (`org_roles` / `org_permissions`) are "not on the wire yet (06-09)".
  06-09 is the SAML XML adapter and does not own the tenant claim-mapping DTO; the comment names
  the wrong plan. Whoever owns the org claim mapping API (06-12/06-13 by the plan texts) should
  put them on the wire and fix the comment. Not a TRANSITIONAL marker; behaviour is unchanged.
- (from 06-14, decision for gap plan) Org JIT currently follows the tenant `upstream_registration` setting, so a B2B tenant with closed registration silently blocks org SSO sign-ups. Orchestrator recommendation: JIT through an *org-owned* connection is allowed regardless of tenant registration (an admin explicitly configured the org connection and verified the domain); tenant-level connections keep following `upstream_registration`. Needs a test and a docs line.
- (from 06-13) The org claim mapping rules are not yet on the admin tenant-settings DTO (06-09/06-02 note). Whichever later plan owns admin/dto.rs + tenants.rs should expose them, or the gate gap plan.
- (from 06-13/06-14) New negative test names (org_claims.rs, enterprise_oidc.rs, security_linking.rs additions) must be added to scripts/check-security-tests.sh at the gate (06-26).

## From 06-21

- (API gap, console workaround in place) There is no per-user membership list in the admin API. The
  console's user page "Organizations" card lists the tenant's organizations (up to 2000) and asks
  each for `GET …/{org}/members/{user_id}/roles` (404 = not a member): N requests per user page. A
  `GET /tenants/{slug}/users/{user_id}/organizations` endpoint (one `OrgRepo` query) would replace it.
- (API gap, console workaround in place) `GET /tenants/{slug}/users` has no email filter, so "add
  member by email" pages through the users list (up to 10000 users, then asks for the user id). An
  `?email=` filter on listUsers would make the lookup one request.
- (from 06-19) `policy::mfa::effective_policy` now only forwards to `effective_policy_for` with no callers outside mfa.rs: remove it (one implementation) in the gate gap plan. Org MFA during the first password login arrives as an immediate step-up (login flow has no org yet); documented, acceptable.
