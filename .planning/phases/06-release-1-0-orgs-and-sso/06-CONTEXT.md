# Phase 6: Release 1.0 "Credible for business" (Organizations and SSO) - Context

**Gathered:** 2026-11-26
**Status:** Ready for research
**Source:** docs/PRD.md, docs/ARCHITECTURE.md (M5, D4, §20), ROADMAP Phase 6, Phase 5 carry-overs, orchestrator defaults (user runs GSD in autonomous mode)

<domain>
## Phase Boundary

SaaS builders can serve business customers: organizations with members and roles, each able to bring its own SAML or OIDC
identity provider, with users routed automatically by email domain. Requirements: ORG-02, ORG-03, ORG-04, ADM-02 (read the
exact wording in .planning/REQUIREMENTS.md and docs/PRD.md).

Roadmap success criteria:
1. A tenant admin creates an organization, invites members, assigns org-scoped roles, and the org claim appears in tokens;
   a user in several orgs can switch between them.
2. An organization admin configures an OIDC or SAML 2.0 connection and users log in through it with just-in-time
   provisioning; SAML stays flagged experimental unless it passes the signature-wrapping attack corpus (decision D4).
3. After a domain is verified by DNS TXT record, a user entering an email on that domain is routed to the organization's IdP.
4. Every managed object (tenants, users, clients, organizations, connections, branding, keys, sessions, audit log) can be
   administered from the console.
</domain>

<decisions>
## Implementation Decisions (locked)

- All CLAUDE.md rules apply (no stubs, one implementation per concern, a negative test per security check, storage only
  through traits, public-repo hygiene).
- **Organizations live inside a tenant** (tenant = isolation boundary with its own issuer; org = customer within it). The
  0.4 schema already reserves `org_id` on roles; org-scoped roles reuse RoleService/claims mapping rather than a parallel
  system. MFA policy precedence extends to org (strictest wins: tenant / org / client), as decided in Phase 4.
- **Org admins** are tenant users with an org-scoped admin role; they manage their org (members, invitations, connections,
  domains) through scoped admin API endpoints. This also delivers "tenant-restricted admins" deferred from Phase 5 Q3.
- **Invitations:** single-use, expiring, hashed at rest, delivered through the sealed outbox; accepting binds to a signed-in
  or newly registered user; no account enumeration.
- **Org claim and switcher:** the token carries the active org (claim name per research; e.g. `org_id` + optional
  `org_slug`), selectable via an authorization parameter and a switcher page for users in several orgs; consent and
  sessions stay per user.
- **Enterprise OIDC connections** reuse the Phase 4 upstream machinery (connection table, SSRF-guarded client, ID token
  validation, linking rules), scoped to an org instead of the tenant.
- **SAML 2.0 SP:** experimental flag until it passes a signature-wrapping attack corpus (D4). Strict XML handling (no DTDs,
  no external entities), exact signature-reference checks, audience/recipient/destination/time checks, replay protection
  via assertion id cache, signed assertions required. Library choice per research (pure Rust, passes cargo deny, single
  crypto backend aws-lc-rs).
- **JIT provisioning** creates users on first SSO login inside the org, with attribute mapping; never links to an existing
  account without the Phase 4 safe-linking rules.
- **Domain routing:** domains verified by DNS TXT record (resolver through a dedicated, timeout-bounded lookup; no
  user-controlled hostnames beyond the domain itself); identifier-first login routes verified domains to the org IdP;
  a domain belongs to at most one org per tenant.
- **Console:** every managed object administrable (ADM-02), including organizations, members, invitations, org roles,
  org connections, domains, keys and sessions.
- **Phase 5 carry-overs to consider here:**
  - Role/permission claims for opaque tokens and introspection (05-12, deferred because roles get reworked for orgs).
  - Resource URI case folding (05-25) — revisit only if a design need appears; otherwise keep exact matching.
  - Narrowing the browser passkey picker to the step's user at the second-factor step (05-30).

### Claude's Discretion
- Plan decomposition and waves (maximize parallel plans with disjoint files; shared files in early foundation plans).
- Exact claim names, invitation flow details, DNS resolver crate, SAML library (subject to D4), SAML metadata handling.
</decisions>

<deferred>
## Deferred Ideas
- OIDC certification filing, external security review, migration tooling, docs site (Phase 7)
- SCIM provisioning, fine-grained authorization engine (D5, 3.0)
</deferred>

---
*Phase: 06-release-1-0-orgs-and-sso*

## Decisions after research (orchestrator defaults, 2026-11-26 — owner may override)

- **Q1 org admin access:** org sub-routes of the admin API also accept the tenant's own tokens carrying a bounded
  `org:admin` scope plus a matching `org_id`; an org admin can never act outside their org (negative tests). "Tenant-
  restricted admins" = system roles with a tenant list (`admin_tenants` claim) — include only if it fits without a second
  authorization path; otherwise defer to Phase 7 and say so.
- **Q2 SAML library (D4):** option A — `bergshamra-dsig` on aws-lc + `uppsala` as the only XML parser + our own narrow
  SAML layer. The `chrono` ban gets ONE narrow `deny.toml` exception scoped to `tsp-ltv` (wrapper = that crate only), with a
  comment explaining why; flag this exception explicitly in the phase summary for the owner. Mandatory mitigations: strict
  profile pre-check before any library call, pinned signature location, `forbid_dtd`, no reference resolution outside the
  document, claims read only from the verified node, attack corpus in CI.
- **Q3 experimental flag:** SAML stays behind a runtime operator flag (off by default) through 1.0, even if the corpus
  passes, until the Phase 7 external review and a real-IdP interop checklist.
- **Q4 IdP-initiated SSO:** refused in 1.0.
- **Q5 org role model:** hybrid on one assignment table (tenant roles assignable per org + org-owned roles).
- **Q6/Q7 SSO enforcement (conservative default):** verified-domain routing is on once an org verifies a domain, but
  password lockout is OPT-IN — `allow_local_password` defaults to **true**; an org admin must explicitly turn it off to force
  SSO for that domain. Document the trade-off. (Researcher recommended default false; owner can flip.)
- **Q8:** Phase 6 work starts on main now; the v0.3.0 (04-33) and v0.4.0 (05-29) tags remain owner-gated and land before
  the 1.0 gate.
- The researcher's 16 self-resolved items stand (claim names `org_id`/`org_slug`/`org_roles`/`org_permissions`,
  `organization` authorize parameter, switching = new authorization request, invitations, no orgs in the system tenant,
  opaque-token/introspection role claims done here, resource URI matching stays exact, passkey picker narrowing as a small
  plan, unsigned AuthnRequests, DNS record format/crate, migration split, signing-keys API + console page, config YAML
  prune must exclude org-owned objects).
