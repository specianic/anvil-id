---
phase: 06-release-1-0-orgs-and-sso
plan: 24
subsystem: e2e
tags: [e2e, playwright, organizations, invitations, saml, hrd, nojs, axe, mock-dns, ORG-02, ORG-03, ORG-04]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-03 mocks (startMockSamlIdp, mock DNS + publishTxt), 06-17 org SSO admin API, 06-18 SAML login, 06-19 switcher, 06-20 invitations, 06-22 email-first/HRD pages, 06-23 run.sh DNS wiring and console-v10 helpers"
provides:
  - "tests/e2e/lib/org.ts: createOrgTenant, addMember, orgMembers, createInvitation, addVerifiedDomain, patchDomainRouting, createOrgOidcConnection, createOrgSamlConnection, setClientOrganizationPolicy, createOrgClient, submitEmailFirst, expectSsoChoice, expectPasswordStep (+ console-v10 read helpers re-exported)"
  - "mock-saml-idp.ts `https: true` option (TLS with the in-memory key and self-signed cert)"
  - "Specs: org-switch, invitations, saml, hrd, nojs-hrd"
affects: [06-25, 06-26]

tech-stack:
  added: []
  patterns:
    - "`organization` is added to the authorization request with lib/authorize.ts addAuthorizeParams; the rewrite is stopped at the start of signIn so IdP navigations are never intercepted"
    - "Org OIDC IdP in e2e = a second AnvilID tenant (createUpstreamTenant), as in social.spec.ts"
    - "SAML specs start the mock with `https: true` and use test.use({ ignoreHTTPSErrors: true })"

key-files:
  created:
    - tests/e2e/lib/org.ts
    - tests/e2e/specs/org-switch.spec.ts
    - tests/e2e/specs/invitations.spec.ts
    - tests/e2e/specs/saml.spec.ts
    - tests/e2e/specs/hrd.spec.ts
    - tests/e2e/specs/nojs-hrd.spec.ts
  modified:
    - tests/e2e/lib/mock-saml-idp.ts

key-decisions:
  - "The SAML mock serves https only when asked (`https: true`); the default stays http, so the 06-03 self-test and console-org-sso are unchanged. The product keeps requiring https SSO URLs"
  - "hrd.spec's org OIDC IdP is a second AnvilID tenant, not lib/mock-idp.ts: that mock has only Apple-/GitHub-like kinds, neither of which is a generic OIDC provider with discovery"
  - "The SAML spec's client uses organization policy `required`: after JIT the user's only membership is selected, so the token's org_id proves the membership end to end"

requirements-completed: []

duration: ~35min
completed: 2026-11-26
---

# Phase 6 Plan 24: Feature e2e specs for orgs, invitations, the switcher, SAML, HRD and no-JS HRD Summary

**Five browser specs now cover the Phase 6 journeys against the real binary: picking an org on the switcher and switching with `organization=<other>`, accepting an emailed invitation by registering, signing in through a SAML IdP from the "Continue with single sign-on" choice (plus the wrong-audience error page), identifier-first routing through the full allow-password-then-SSO-only lifecycle, and the same routing without JavaScript. Every spec works in tenants of its own and publishes DNS records only through the suite's mock DNS. The mock SAML IdP can now serve https.**

No requirement checkbox was ticked (shared rule). ORG-02, ORG-03 and ORG-04 have their browser evidence for the gate (06-26).

## Specs

| Spec | Journey | axe |
|---|---|---|
| `org-switch.spec.ts` | A user in acme and beta (gamma exists, not a member) signs in to a `required` client. The switcher lists acme and beta only. Picking beta gives `org_id`/`org_slug` beta. A new request with `organization=<acme id>` gives a code for acme on the same session. No `/ui/login` or switcher navigation happens. | switcher |
| `invitations.spec.ts` | Invitation through the admin API (the response contains no token). The `org_invitation` email arrives (subject has the org name). The GET shows the offer and uses nothing (still `open`). Accept while signed out leads to the registration form, whose address is read-only and not a form field. Registering gives `invitation.registered`: the user is verified, a member, and the invitation is `accepted`. The same link then gives `invitation.invalid`. The new account signs in with its password. | offer, registration, registered, invalid |
| `saml.spec.ts` | Connection from the https mock's metadata (import endpoint, then create), verified domain, routing with passwords allowed. At the RP, the routed address gets the SSO choice, then the mock (one AuthnRequest with the SP entity ID and ACS URL), then a code. `org_id` is the org, the JIT user has the asserted names and is a member. `wrong-audience` ends on `#error-message[data-error-key=saml_login_failed]` at the ACS, with no reason shown and no account created. | error page |
| `hrd.spec.ts` | The org OIDC connection points at a second AnvilID tenant. Verification before the TXT record stays pending and routing a pending domain answers 409; `publishTxt` then verify gives verified. The email page has no password field and no button for the org connection. A routed address gets the SSO choice, and "Use password instead" signs the local account in. Before any sign-in through the connection, `allow_local_password=false` answers 409. An RP request with `organization=acme` goes straight to the IdP: JIT user, membership, `org_id` in the token. After that, `false` is accepted (200) and the same local address goes straight to the IdP. A non-routed address gets the password step. | email page, choice page, password step |
| `nojs-hrd.spec.ts` (`nojs` project) | SAML routing with passwords allowed. The routed address goes to the choice page, then the mock page, where the visible `#mock-saml-continue` button is clicked (no script runs), and comes back signed in (JIT plus membership). "Use password instead" signs in. A non-routed address gets the password step. | (axe needs script; it runs in hrd/saml) |

## Task Commits

1. Task 1, lib/org.ts plus the org-switch and invitations specs: `a3304cd` (test)
2. Task 2, saml/hrd/nojs-hrd specs plus the https option of the mock SAML IdP: `c827960` (test)
3. hrd publishes the TXT record itself (pending and 409 before it); lib/org.ts gains claimDomain/verifyDomain under addVerifiedDomain: `12814fd` (test)

## Verification

- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- `scripts/check-release-graph.sh`: OK (no Rust changes).
- **Local browser run without Docker (SQLite), all 5 specs passed twice.**
  - Setup:
    - `cargo build -p anvilid` (debug, main tree), with the binary hardlinked into a scratch dir.
    - The mock DNS was started by hand (`mock-dns-cli.ts --port 53555 --control-port 53556`).
    - anvilid ran with a fresh data dir and the run.sh flags plus `ANVILID_SAML_EXPERIMENTAL=true` and `ANVILID_DOMAIN_VERIFICATION_RESOLVERS=127.0.0.1:53555`.
    - The specs got `E2E_DNS_CONTROL_URL`.
    - Mailpit (Docker) was replaced by a throwaway scratch script: an SMTP sink plus the three Mailpit API calls lib/mailpit.ts uses. It was never committed and was deleted afterwards.
  - Run 1: org-switch and invitations 2/2, then saml, hrd and nojs-hrd 4/4.
  - Run 2, together with regressions: 19/19. That covers the five new specs plus `mock-saml-idp` (6/6, the self-test of the edited mock), `console-org-sso`, `login` and `nojs` (5/5).
  - After commit 3: hrd, saml and nojs-hrd were run again in a fresh instance, 4/4.
  - Every process was stopped, and the scratch dir and `e2e-results/` were deleted.

## Only CI can run

- `tests/e2e/run.sh sqlite …` and `run.sh postgres …` as written: they need Docker (real Mailpit, the release build, the Postgres container). The Postgres variant of all five specs runs only in the CI e2e workflow.
- The full suite (`./run.sh sqlite` with no spec list) was not run locally. Its other specs depend on the real Mailpit and on the sample RP set-up. The new specs touch only their own tenants (the default tenant gets no routed domain), so they cannot change what other specs see.

## Deviations from Plan

### Forced extras

1. **`tests/e2e/lib/mock-saml-idp.ts`** (orchestrator decision, option a). It gains an opt-in `https: true` option that serves the same handler through `node:https` with the in-memory RSA key and the self-signed certificate, which is now generated before listen. `url`, `ssoUrl`, the default entity ID and the metadata Location use https. The specs set `ignoreHTTPSErrors`. The product rule is unchanged. Chromium accepted the https mock page form-posting to the `http://localhost` ACS without an insecure-form interstitial.

### Interpretations

- **hrd's "mock IdP"** is a second AnvilID tenant acting as a generic OIDC provider, the suite's existing pattern (social.spec.ts). lib/mock-idp.ts has no generic OIDC kind (Apple and GitHub only), and the console spec only creates an OIDC connection against it without signing in.
- **"an admin invites"** is done through the admin API. The console's invite form is covered by 06-21's console-orgs spec.
- **The org helpers that already existed** in console-v10.ts (`createOrg`, `orgDomains`, `orgConnections`, `orgInvitations`, `orgMemberRoles`, `randomOrgDomain`) are re-exported from org.ts, not reimplemented (one implementation).
- **SAML connections in the specs use NameID format `persistent`**, the mock's format.

No files outside files_modified were changed except the mock (above).

## Self-Check: PASSED

- FOUND: tests/e2e/lib/org.ts (contains `addVerifiedDomain`), tests/e2e/specs/saml.spec.ts (contains `startMockSamlIdp`), tests/e2e/specs/hrd.spec.ts (contains `publishTxt`), tests/e2e/specs/{org-switch,invitations,nojs-hrd}.spec.ts
- FOUND commits: a3304cd, c827960, 12814fd
