---
phase: 06-release-1-0-orgs-and-sso
plan: 25
subsystem: docs
tags: [docs, organizations, saml, home-realm-discovery, domains, upgrading, operations, webhooks, theme, ORG-02, ORG-03, ORG-04, ADM-02]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "Every Phase 6 SUMMARY (06-01..06-23) for exact names: routes, operator keys, claims, selectors, reason codes, guards, migrations; deferred-items.md for open items"
provides:
  - "docs/ORGANIZATIONS.md: organizations guide (members, roles, invitations, claims, switcher, org MFA/branding, org admins, enterprise OIDC, domain verification, HRD, lockout recovery, limitations)"
  - "docs/SAML.md: experimental SAML profile, checks, corpus statement, chrono exception, Q3/Q4, Phase 7 interop checklist template"
  - "docs/UPGRADING.md 0.4 -> 1.0 section"
  - "ARCHITECTURE/OPERATIONS/CONFIG-YAML/WEBHOOKS/PRD/theme README synced with 1.0"
affects: [06-26]

tech-stack:
  added: []
  patterns:
    - "Docs keep historical 'built in 0.x' text and add 'added in 1.0' text; open items stated as open"

key-files:
  created:
    - docs/ORGANIZATIONS.md
    - docs/SAML.md
  modified:
    - docs/UPGRADING.md
    - docs/ARCHITECTURE.md
    - docs/OPERATIONS.md
    - docs/CONFIG-YAML.md
    - docs/WEBHOOKS.md
    - docs/PRD.md
    - themes/default/README.md

key-decisions:
  - "Org-admin resource documented as `{public_url}/api/admin/v1` (the code's name; public_url is origin-only, no trailing slash)"
  - "ARCHITECTURE §20 D4 stays open: experimental; corpus green; external review and interop checklist in Phase 7"
  - "Org JIT under closed tenant registration documented as current behaviour (follows upstream_registration) and as an open decision, with advice to set upstream_registration explicitly"

requirements-completed: []

duration: 70min
completed: 2026-11-26
---

# Phase 6 Plan 25: 1.0 docs pass (organizations, SSO, SAML, HRD, operations) Summary

**Two new guides (ORGANIZATIONS.md, SAML.md), a 0.4 -> 1.0 upgrade section, and ARCHITECTURE, OPERATIONS, CONFIG-YAML, WEBHOOKS, PRD status and the theme contract brought in line with what Phase 6 built, with SAML's experimental status and every lockout guard and limitation stated explicitly.**

Requirements ORG-02, ORG-03, ORG-04 and ADM-02 are documented, not ticked (only the gate 06-26 ticks REQUIREMENTS.md).

## Performance

- **Duration:** about 70 min (reading from about 11:50Z, commits 12:58Z and 13:02Z)
- **Tasks:** 2/2
- **Files:** 2 created, 7 modified (plus SAML.md touched again in Task 2)

## Task Commits

1. **Task 1: ORGANIZATIONS.md, SAML.md, UPGRADING 0.4 -> 1.0:** `318bcc3` (docs)
2. **Task 2: ARCHITECTURE, OPERATIONS, CONFIG-YAML, WEBHOOKS, PRD status, theme README:** `661b7c0` (docs)

## What is documented (per the orchestrator's list)

| Item | Where |
|---|---|
| SAML experimental flag and why it stays off | SAML.md "Status", OPERATIONS "SAML (experimental)", ARCHITECTURE §2.1, §9.5, §20 D4 |
| IdP-initiated SSO refused | SAML.md profile table and Decisions (Q4), ARCHITECTURE §9.5 |
| Routing and allow_local_password guards, trade-off, passkeys allowed, tenant admin as recovery | ORGANIZATIONS.md "Guards", "The allow_local_password trade-off", "Recovering from lockouts"; ARCHITECTURE §9.6 |
| Org-admin tokens with `resource={public_url}/api/admin/v1` | ORGANIZATIONS.md "Getting an organization-admin token" (client setup, role, authorize URL, call); ARCHITECTURE §10.3 |
| Invitations incl. the return-to limitation | ORGANIZATIONS.md "Invitations" and "Limitations in 1.0" |
| Daily domain re-check | ORGANIZATIONS.md "Domain verification", OPERATIONS "Domain verification and the daily re-check", WEBHOOKS, ARCHITECTURE §14 |
| Org JIT under closed tenant registration (pending decision, current behaviour) | ORGANIZATIONS.md "Enterprise OIDC connections", UPGRADING "What to configure next", ARCHITECTURE §9.6/M5 |
| deny.toml chrono exception | SAML.md "Dependencies and the chrono exception", ARCHITECTURE §2 (unchanged) and §20 D4 |
| UPGRADING 0.4 -> 1.0, SQLite rebuild, back up first | UPGRADING.md "0.4 to 1.0" |
| Last-org-admin 409 and 401/403 split | ORGANIZATIONS.md "Organization admins", ARCHITECTURE §10.3 |
| Tenant-restricted system admins deferred to Phase 7 | ORGANIZATIONS.md limitations, OPERATIONS limitations, ARCHITECTURE §10.3, §19, M5 |

## Verification

- Task 1 automated check (files non-empty, `saml_experimental`, `allow_local_password`, `0.4 ... 1.0`, `_anvilid-challenge`): OK.
- Task 2 automated check (`organization`, `domain_verification_resolvers`, `organization.domain_unverified`, the three template names): OK.
- Every relative link and anchor in the eight touched docs resolves (scripted check).
- Names cross-checked against the code, not only the SUMMARYs: webhook event names (`model/webhook.rs`, `policy/webhook_event.rs`), audit action names (`model/audit.rs`), the org-admin resource (`admin/auth.rs` `admin_api_resource`), `PublicUrl` (no trailing slash), `check_routing` messages and rules, `resolve_active_org` table, the `domain_recheck` job name and its log line, the unverify SQL (routing stops through `routed_domain`, the routing flag is kept), the `upstream_registration` fallback (`registration == Open`), the absence of any automatic SAML metadata refresh, SAML route paths and error key `saml_login_failed`, OpenAPI operation count (122) and DTO fields, template variables of the four new/changed templates, `org_invitation.txt` payload keys.
- Hostnames in examples are reserved names only (`example.com`, `example.net`); no secrets. The one generic statement about other products in SAML.md was reworded to describe attack classes instead.
- `scripts/check-release-graph.sh`: OK.
- No code changed, so no cargo build or tests were run.

## Deviations from Plan

### Interpretations

1. **`resource` value.** The orchestrator's prompt says `{public_origin}`; the code and tests use `{public_url}/api/admin/v1`, and `PublicUrl` is origin-only. The docs use `{public_url}` with a concrete example.
2. **SAML.md touched in Task 2.** One sentence in SAML.md was reworded during the final public-repo review (commit `661b7c0`), after Task 1's commit.
3. **PRD.** Status notes were added after the ORG and ADM tables (the 04-31 "Note on ..." precedent); requirement text and phases are unchanged.
4. **Theme README "variables".** No new stylesheet classes exist in Phase 6 (the new templates reuse existing classes), so the stylesheet section is unchanged.

### Auto-fixed Issues

None (docs only).

## Issues / Not run

- No e2e, Postgres or conformance runs: docs-only plan.
- 06-24 ran in parallel in the same tree; its uncommitted `tests/e2e/lib/mock-saml-idp.ts` change was not staged by this plan. SAML.md refers to `tests/e2e/specs/saml.spec.ts`, which 06-24 owns; it exists in the tree.

## Next Phase Readiness

- 06-26 (gate): may close the deferred items that the docs list as open (invitation return-to, org JIT under closed registration, `tenant_has_routing` flag awareness, brute-force page in routed tenants). If any is fixed there, update the matching "Limitations in 1.0" bullets in ORGANIZATIONS.md (and the M5 status in ARCHITECTURE).
- The interop checklist template in SAML.md is for Phase 7.

## Self-Check: PASSED
