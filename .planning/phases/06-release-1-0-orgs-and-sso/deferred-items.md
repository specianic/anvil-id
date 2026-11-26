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
- (from 06-20, UX) After registering through an invitation the user is not signed in, and a signed-out user with an account must sign in and reopen the invitation link manually. Gap plan: return-to-invitation after sign-in (login flow carries a validated return target to /ui/invitation) and optionally sign in after invitation registration.

## From 06-23

- **(Blocker for 06-24 saml.spec, needs a decision)** The mock SAML IdP (06-03, `lib/mock-saml-idp.ts`)
  serves plain http on 127.0.0.1, so its metadata has `SingleSignOnService Location="http://…"`. AnvilID
  refuses that at both layers: `SamlXmlAdapter::parse_metadata` (saml_xml.rs: `scheme != "https"` ->
  `Structure`, the import answers 422 "is not usable SAML IdP metadata") and `SamlConfig::validate`
  (`sso_url` "must be an https URL"). `console-org-sso.spec.ts` works around it because it never signs in
  through the connection (it rewrites the Location to https before pasting). A SAML *sign-in* e2e cannot.
  Options: (a) the mock gains an https listener with its in-memory key/cert (`node:https`; the browser
  context sets `ignoreHTTPSErrors`; anvilid never fetches the SSO URL server-side, only the browser
  does), keeping the product rule as is; (b) allow `http://` loopback SSO URLs in both places, like
  OIDC issuers (`https_or_loopback_http`). (a) keeps the product strict and is the smaller change.
- (one implementation) `ConnectionForm.tsx` now exports `SecretRotation` (write-only secret
  replace/remove, secret via a ref), used by the org connections panel. The tenant page
  `connections/$connectionId.tsx` still has its own `SecretCard` with the same logic (06-23 did not
  own that file); it should switch to `SecretRotation` in the gate gap plan.
- (decision, for 06-24) SAML e2e: use option (a): the mock SAML IdP (tests/e2e/lib/mock-saml-idp.ts) gets an https listener with its in-memory key/cert and the specs set ignoreHTTPSErrors; the product keeps requiring https SSO URLs (no loopback-http exception). 06-24 may edit mock-saml-idp.ts as a forced extra.
- (from 06-22) The brute-force lock and CAPTCHA page (`posted_login_form`) still renders the combined form in routed tenants (no enumeration impact; UX inconsistency). Gap plan: render the email-first form there.
- (from 06-22) `OrgRepo::tenant_has_routing` ignores the SAML runtime flag: a tenant whose only route is SAML with the flag off shows the email page, and every address goes to the password step. Gap plan: make the email-first decision use the same "routable" rule as `routed_domain` (flag-aware).
- (from 06-23) ConnectionForm's reusable `SecretRotation` duplicates the tenant connection page's `SecretCard`; switch the page to the shared component (one implementation).

## Gate dispositions

Categories: (a) already resolved, verified in code; (b) planned in a gap plan (06-28 .. 06-31, run before the gate); (c) belongs to
the gate 06-26 (listed in its must-haves); (d) moved to Phase 7.

| # | Entry | Disposition |
|---|---|---|
| 1 | (06-02) UUIDv7 `"171"` flake in `totp_debug_redacts_the_sealed_seed` / `debug_redacts_sealed_secrets` | (a) Both assert on `"171, 171"` now (model/credential.rs ~167, model/webhook.rs ~325), as model/organization.rs does. |
| 2 | (06-05 for 06-09) `SamlAssertionData.has_conditions` set by the extractor | (a) 06-09: saml_xml.rs sets it; core `validate.rs` requires it (`MissingConditions`); tests `saml_xml_adapter::has_conditions_is_false_without_conditions` and `has_conditions_is_true_for_conditions_without_not_on_or_after`. |
| 3 | (06-09) tenants.rs "not on the wire yet (06-09)" comment for org claim mappings | (a) 06-17: `TokenClaimMapping` / `TokenClaimMappingPatch` carry `org_roles` / `org_permissions` (admin/tenants.rs ~292-381); the "(06-09)" comments are gone. |
| 4 | (06-14) Org JIT follows `upstream_registration`, blocking org SSO sign-ups under closed registration | (b) 06-28 Task 2: JIT through an org-owned connection is allowed whatever the tenant registration setting, for emails trusted for the org (its verified domains); tenant connections keep `upstream_registration`; tests + ORGANIZATIONS/UPGRADING/ARCHITECTURE lines. |
| 5 | (06-13) Org claim mapping rules not on the admin tenant-settings DTO | (a) Same fix as #3 (06-17). |
| 6 | (06-13/06-14) New negative tests (org_claims.rs, enterprise_oidc.rs, security_linking.rs additions) into scripts/check-security-tests.sh | (c) 06-26 must-haves: map groups for org_claims, enterprise_oidc, the security_linking additions, security_admin_v10, security_domains, saml_login, the security_saml corpus, hrd_login, org_invitations, org_switch, security_org_scopes, plus the gap plans' negatives. |
| 7 | (06-21) No per-user membership list in the admin API (console fans out N requests) | (b) 06-29: `GET /tenants/{slug}/users/{user_id}/organizations`, console user page on it. |
| 8 | (06-21) No `?email=` filter on listUsers (console scans up to 10000 users) | (b) 06-29: `listUsers?email=`, "add member by email" on it. |
| 9 | (06-19) Remove forwarding `policy::mfa::effective_policy` | (b) 06-30 Task 1. The note in the same entry (org MFA during the first password login arrives as an immediate step-up) was documented and accepted by 06-19; no action. |
| 10 | (06-20) Invitation: no return-to after sign-in, no sign-in after registration | (b) 06-31: allowlisted, KEK-sealed return target to `/ui/invitation` carried by the login flow (request wins); registration through an invitation signs in. |
| 11 | (06-23) Blocker: mock SAML IdP serves http, AnvilID requires https SSO URLs | (a) Decided as option (a) (#13) and done by 06-24: `tests/e2e/lib/mock-saml-idp.ts` has an `https` listener with its in-memory key/cert; `saml.spec.ts` sets `ignoreHTTPSErrors`; the product rule is unchanged. |
| 12 | (06-23) Tenant connection page keeps its own `SecretCard` | (b) 06-29 Task 2: the page uses the shared `SecretRotation`. |
| 13 | (06-23, decision for 06-24) SAML e2e uses option (a) | (a) Applied by 06-24 (see #11). |
| 14 | (06-22) Lock/CAPTCHA page renders the combined form in routed tenants | (b) 06-28 Task 1: `posted_login_form` takes the form from the same flow decision (email-first in routed tenants). |
| 15 | (06-22) `tenant_has_routing` ignores the SAML runtime flag | (b) 06-28 Task 1: `routing_connections` port + core `idp_routable` (same flag-aware rule as routing); `tenant_has_routing` removed. |
| 16 | (06-23) `SecretRotation` duplicates `SecretCard` | (b) Same as #12 (06-29). |

Additional items (orchestrator, not logged above):

- Stale contract-suite comments ("Unsupported until 06-07 / 06-08", Phase 4/5 "TRANSITIONAL shims") — (b) 06-30 Task 1.
- 06-01's aws-lc duplicate check misfires on one version listed twice — (b) 06-30 Task 2: Cargo.lock-based "exactly one aws-lc-rs
  and one aws-lc-sys version" rule in scripts/check-deps.sh (`just deps`), with a self-test case.
- Plaintext-scan coverage of the new Phase 6 secrets (invitation token, org connection secret, sealed SAML identity and sealed
  return target in flow state) — (c) 06-26 must-haves.

Counts for the 16 logged entries: (a) 6, (b) 9, (c) 1, (d) 0. With the three additional items: (b) 11, (c) 2.
