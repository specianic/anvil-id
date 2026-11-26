---
phase: 06-release-1-0-orgs-and-sso
plan: 14
subsystem: auth
tags: [upstream, enterprise-sso, oidc, organizations, jit, account-linking, email-trust, org-03]

requires:
  - phase: 06-04
    provides: "OrgRepo (verified_domains_of_org, is_member, add_member -> AddMemberOutcome), create_user_with_link(.., membership)"
  - phase: 06-05
    provides: "org model (OrgSettings.default_role_ids), Connection.org_id"
  - phase: 06-07
    provides: "SQLite OrgRepo and create_user_with_link with a membership in one transaction"
  - phase: 06-08
    provides: "Postgres OrgRepo and create_user_with_link with a membership"
provides:
  - "upstream::linking::enterprise_email_trust(email, verified_org_domains, upstream_verified: Option<bool>) -> bool (pure)"
  - "UpstreamService::complete_identity (pub(crate)): the one Login completion path for OIDC/OAuth and SAML (06-18)"
  - "JIT through an org connection creates user + link + membership (default roles) in one transaction; JIT membership for linked, auto-linked and confirmed-link users; audited org_member_added"
  - "Org connections are hidden from the tenant sign-in page buttons"
  - "tests/upstream_flow helpers: create_org, create_role, set_default_roles, claim_domain, verify_domain, add_org_connection, link_identity, is_member, org_role_names, mock_oidc_config, start_at, callback_at, sign_in_at"
affects: [06-17, 06-18, 06-22]

tech-stack:
  added: []
  patterns:
    - "Org trust is applied as an override of UpstreamIdentity.email_verified before link_decision, so the Phase 4 decision table stays the only linking logic"
    - "Org connections are started by slug through the same start route (no button); home-realm discovery (06-22) posts it"

key-files:
  created:
    - crates/anvil-web/tests/enterprise_oidc.rs
  modified:
    - crates/anvil-core/src/upstream/linking.rs
    - crates/anvil-core/src/service/upstream.rs
    - crates/anvil-web/src/ui/upstream.rs
    - crates/anvil-web/tests/security_linking.rs
    - crates/anvil-web/tests/upstream_buttons.rs
    - crates/anvil-web/tests/upstream_flow/mod.rs

key-decisions:
  - "OIDC/OAuth org connections pass Some(identity.email_verified) as upstream_verified: the provider's strict boolean true, still AND-ed with the connection's trust_email_verified. The verified domain only narrows trust, it never grants trust an untrusted connection lacked"
  - "Domain match is exact and ASCII-only after normalize_email: no subdomain coverage, and a U-label domain never matches the stored A-label (fails closed)"
  - "JIT membership is added for SignIn, AutoLink and confirmed links (confirm_link), after require_verified_email and before MFA/session; never for an unconfirmed match"
  - "Default roles that no longer exist (or belong to another org) are skipped, so a deleted default role does not block every org sign-in"
  - "A missing org (race with org deletion) answers the generic error with reason connection_disabled; a storage-refused membership answers reason membership_refused"
  - "Org JIT still follows the tenant's upstream_registration (default: registration == open); no org-level JIT switch was invented"

requirements-completed: [ORG-03]

duration: about 1h
completed: 2026-11-26
---

# Phase 6 Plan 14: Enterprise OIDC per Organization Summary

**An org-owned OIDC connection now signs users in through the Phase 4 upstream routes and one shared completion path. Its email is trusted only on that org's verified domains with a strict `email_verified: true`. JIT creates the user, the link and the org membership (default roles) in one transaction, and existing linked users who are not members become members. Org A's IdP asserting an address on org B's verified domain never auto-links and never adds an org A membership to that account.**

Note: no requirement checkbox was ticked (wave rule). `requirements-completed` records scope only.

## Task Commits

1. **Task 1: pure trust rule and shared completion path:** `5d986d1` feat(06-14): domain-bound enterprise email trust and the shared upstream completion path
2. **Task 2: hidden org buttons and enterprise OIDC tests:** `cb10ab1` feat(06-14): hide org connections from the sign-in page; enterprise OIDC and cross-org tests

## API for 06-18 (SAML) and 06-22 (HRD)

```rust
// crates/anvil-core/src/service/upstream.rs
impl UpstreamService<'_> {
    pub(crate) async fn complete_identity(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,              // the login flow, already proved to be this browser's, pending consumed
        state: LoginState,        // its login state (the pending upstream/SAML request taken out)
        conn: &Connection,        // enabled connection; org_id decides the org rules
        identity: UpstreamIdentity,
        current: Option<&BrowserSession>,
    ) -> Result<UpstreamOutcome, CoreError>;
}

// crates/anvil-core/src/upstream/linking.rs
pub fn enterprise_email_trust(
    email: Option<&str>,
    verified_org_domains: &[String],
    upstream_verified: Option<bool>, // OIDC/OAuth: Some(identity.email_verified); SAML: None
) -> bool;
```

- SAML: `complete_identity` itself chooses `upstream_verified = None` when `conn.config` is `ConnectionConfig::Saml(_)`. 06-18 only builds the `UpstreamIdentity` (subject = NameID, email and names from the mapping; `email_verified` is overridden for org connections, so its value does not matter there) and calls `complete_identity`.
- `complete_identity` only uses `self.flows`. 06-18 can build an `UpstreamService { flows, accounts, client: state.upstream() }` in the web layer (as `AppState::ui_upstream` does) to call it. Failures restart the sign-in from `flow` (`UpstreamOutcome::Continue`) and are audited `upstream_login_failed`.
- The start route `POST /ui/login/upstream/{slug}?flow=` accepts org OIDC connections by slug (test `org_connection_start_by_slug_works`), which is what 06-22's routing posts.

## Behaviour

**Trust rule (Pattern 9):** an org connection's `email_verified` becomes `enterprise_email_trust(email, verified_domains_of_org, upstream_verified)`. That holds when all of these are true:
- the email is present and normalises;
- its domain exactly equals one of the org's verified domains (case-insensitive, ASCII only);
- `upstream_verified` is not `Some(false)`.

Otherwise the email is untrusted. A matching local account then needs the Phase 4 confirmation, and the candidate is not revealed. A JIT account gets an unverified email and a verification email.

**Completion order:** org trust override, `link_decision`, then one of:
- SignIn (touch link);
- AutoLink;
- PendingLink (confirmation flow);
- JIT with `Some(NewMembership { org_id, user_id, role_ids: existing default roles })`;
- Refuse.

After that comes `require_verified_email`, then JIT membership for an existing user (`is_member`, then `add_member`, audited on `Added` only), then `upstream_primary`.

**Audit:** `org_member_added`. The target is the user, and the details are `org_id`, `org_slug`, `connection` and `kind`. The webhook mapping (06-05) turns this into `organization.member_added` with `user_id` and `org_id`. JIT also records `user_registered` as before. New `upstream_login_failed` reason: `membership_refused`. A missing org reuses `connection_disabled`.

**Tenant connections:** unchanged. Every Phase 4 upstream suite passes unmodified. `tenant_connection_trust_is_unchanged_by_org_domains` pins that an org's verified domain neither grants nor removes trust on a tenant connection, and adds no membership.

**Buttons:** `upstream_buttons` filters out `org_id.is_some()` connections.

## Tests

`enterprise_oidc.rs` (7):
- `org_oidc_jit_creates_user_link_and_membership`: an org role plus a tenant role as defaults; mapped names; one link to the org connection; the membership with both roles; `org_member_added` with the org id and slug; `user_registered`; a session.
- `org_oidc_jit_skips_default_roles_that_no_longer_exist`
- `org_oidc_existing_linked_user_gets_membership`: membership plus the default role, audited once; a second sign-in audits nothing new.
- `verified_domain_email_auto_links_existing_local_user`: link mode `auto` plus membership.
- `unverified_domain_email_is_untrusted` (negative): a pending domain claim gives confirmation only, no link and no membership; a JIT account there is unverified.
- `upstream_email_verified_false_is_untrusted_even_on_verified_domain` (negative): `false`, the string `"true"` and `null` all give confirmation; an untrusted org connection on a verified domain also gives confirmation.
- `org_connection_start_by_slug_works`

`security_linking.rs`, negative (+3, 24 in total):
- `foreign_domain_email_never_auto_links`: org A's trusted IdP asserts `victim@orgb.example`, which org B has verified, and the victim is an org B member. The result is the confirmation page without the address: no link, no session, no `identity_linked`, no org A membership, no `org_member_added`. Control: org B's own IdP does link.
- `foreign_domain_jit_account_is_unverified_and_cannot_claim_the_address`
- `tenant_connection_trust_is_unchanged_by_org_domains`

`upstream_buttons.rs` (+1): `org_connection_not_listed_on_tenant_sign_in_page`. The tenant connection is still listed.

Unit tests in `upstream::linking`: `enterprise_trust_needs_a_verified_org_domain_and_upstream_verification`, `enterprise_trust_refuses_other_and_sub_domains`, `enterprise_trust_compares_domains_case_insensitively_after_normalisation`, `enterprise_trust_refuses_missing_or_malformed_email` (including the U-label case), `enterprise_trust_saml_variant_relies_on_the_verified_domain_only`, and the proptest `enterprise_trust_implies_listed_domain`.

**Mutation check:** I temporarily replaced the trust override with the unmodified `email_verified` (then restored it). `foreign_domain_email_never_auto_links`, `foreign_domain_jit_account_is_unverified_and_cannot_claim_the_address` and `unverified_domain_email_is_untrusted` failed, so the negatives depend on the rule.

## Verification (main tree, SQLite)

- `cargo test -p anvil-core --lib upstream::`: 79 passed.
- `cargo test -p anvil-web --test upstream_login --test upstream_google --test upstream_microsoft --test upstream_github --test upstream_apple --test upstream_oauth2 --test security_linking --test enterprise_oidc --test upstream_buttons --test account_linked`: 15 + 7 + 7 + 8 + 6 + 6 + 24 + 7 + 7 + 14, all passed.
- `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean.
- `cargo clippy -p anvil-web --lib` plus the ten upstream test targets above, with `-D warnings`: clean. `--all-targets` for anvil-web was blocked for a while by another wave-4 plan's in-progress `admin/auth.rs` (dead code). I re-ran the targeted clippy once that plan's build recovered.
- `scripts/check-release-graph.sh`: OK. `scripts/check-security-tests.sh`: OK (632 pairs).
- `rustfmt --edition 2024` was run on every touched file.

## Not run

- `ANVILID_TEST_DB=postgres` for these suites (Docker is not used under the wave rules; left for CI). No SQL was added. The membership-in-JIT intent is covered by the 06-04/06-08 contract test `create_user_with_link_with_membership` on Postgres.
- e2e/conformance: not run.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] A deleted default role would block every org JIT sign-in**
- `create_user_with_link` refuses an unknown role with `Conflict`, so a stale `default_role_ids` entry would turn every JIT into the generic error.
- Fix: `default_roles` keeps only existing tenant roles and roles of this org. Test: `org_oidc_jit_skips_default_roles_that_no_longer_exist`.

**2. [Rule 2] JIT membership also on confirmed links**
- `confirm_link` (same file) adds the membership once the user proved the account, so an org IdP identity linked through the confirmation page behaves like any other link. Without this, the membership would only arrive on the next sign-in.

### Interpretations

- `complete_identity` has no `purpose` parameter. The `Link` purpose (account page) stays in `link()`, because SAML has no account-page linking. The plan's "purpose, .." is satisfied by the Login-only signature above.
- Extra tests beyond the plan's list: `org_oidc_jit_skips_default_roles_that_no_longer_exist`, `foreign_domain_jit_account_is_unverified_and_cannot_claim_the_address`, `tenant_connection_trust_is_unchanged_by_org_domains`.

### Notes and open points (for review)

- **Org JIT and tenant registration:** org JIT follows the tenant's `upstream_registration` (default: open registration). A B2B tenant with closed registration must set `upstream_registration: true` for org JIT to work. An org-level switch would need a model change; it was left for the owner.
- **Security map:** `scripts/check-security-tests.sh` passes, but does not list the new negatives (that script is not in this plan's files). Whoever owns the Phase 6 security map should add `security_linking::foreign_domain_email_never_auto_links`, `enterprise_oidc::unverified_domain_email_is_untrusted` and `enterprise_oidc::upstream_email_verified_false_is_untrusted_even_on_verified_domain`.
- The org IdP's identity can also be linked from the account page (`Link` purpose). A later sign-in through it then grants the membership, because the org's IdP authenticated that subject.

## Self-Check: PASSED

- Files exist: crates/anvil-web/tests/enterprise_oidc.rs, crates/anvil-core/src/upstream/linking.rs (`pub fn enterprise_email_trust`), crates/anvil-core/src/service/upstream.rs (`pub(crate) async fn complete_identity`, `NewMembership` passed to `create_user_with_link`), crates/anvil-web/tests/security_linking.rs (`foreign_domain_email_never_auto_links`)
- Commits in history: 5d986d1, cb10ab1
