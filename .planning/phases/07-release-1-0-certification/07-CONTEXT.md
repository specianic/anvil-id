# Phase 7: Release 1.0 "Credible for business" (Certification and release) - Context

**Gathered:** 2026-11-26
**Status:** Ready for research
**Source:** docs/PRD.md, docs/ARCHITECTURE.md (M5), ROADMAP Phase 7, Phase 6 carry-overs, orchestrator defaults (autonomous GSD run)

<domain>
## Phase Boundary

AnvilID 1.0 ships as a certified, externally reviewed, stable platform that teams can migrate onto. Requirements:
OIDC-18, OIDC-23, UI-05, AGT-03, ADM-08, ADM-09, QUAL-03, SEC-08 (exact wording in .planning/REQUIREMENTS.md and
docs/PRD.md).

Roadmap success criteria:
1. OpenID conformance passes in CI for Basic OP, Config OP, Form Post, RP-Initiated Logout and Back-Channel Logout, and
   certification is submitted for all target profiles.
2. An external security review is completed and its findings fixed; the project publishes a security policy.
3. An admin imports users with existing password hashes (bcrypt, scrypt incl. Firebase, PBKDF2, Argon2, salted SHA-2) who
   can then log in with their old passwords, and can export users individually, in bulk and as a GDPR data-subject export.
4. Clients can use pushed authorization requests, SPAs and native apps can drive login through the versioned headless
   flow API, and the consent screen clearly identifies agent clients with incremental scope step-up.
5. The upgrade path from 0.4 to 1.0 is tested, public APIs are versioned with a documented compatibility policy, and the
   documentation site covers install, integrations and migration guides.
</domain>

<decisions>
## Implementation Decisions (locked)

- All CLAUDE.md rules apply (no stubs, one implementation per concern, negative test per security control, storage only
  through traits, public-repo hygiene, no unverified claims about other products).
- **Owner-only actions are checkpoints, never faked:** submitting OpenID certification, commissioning/conducting the
  external security review, and publishing releases/tags are owner actions. Plans prepare everything (conformance green
  in CI with exported evidence, a certification submission package, a review scope/threat-model/brief, a findings tracker)
  and then stop at an explicit checkpoint. Findings from the review are fixed in a follow-up gap plan once they exist.
- **Security policy (SEC-08):** SECURITY.md with private reporting channel placeholder the owner fills, supported-versions
  table, disclosure process; no personal contact data committed.
- **Password-hash import (ADM-08):** verify legacy hashes on first login and transparently rehash to the current
  algorithm; each scheme isolated behind one verifier interface with known-answer test vectors from primary sources;
  constant-time comparison; refuse weak/unknown parameters explicitly; import is idempotent and audited; imported hashes
  never logged or exported in clear. Firebase scrypt per its published parameters.
- **User export (ADM-09):** single, bulk (streamed/paginated), and GDPR data-subject export (all personal data held about
  a user, incl. sessions, consents, links, audit entries about them); secrets never exported.
- **PAR (OIDC-18 or as numbered):** RFC 9126 pushed authorization requests, `request_uri` single-use and short-lived,
  client authentication required, optional `require_pushed_authorization_requests` per client; discovery metadata.
- **Headless flow API (UI-05 or as numbered):** versioned JSON API driving the same login flows (no second flow engine),
  CSRF/binding equivalent for SPA and native clients, documented and covered by the OpenAPI drift test.
- **Agent clients (AGT-03):** consent screen clearly identifies agent/MCP clients (CIMD/DCR provenance) with incremental
  scope step-up (requesting additional scopes prompts only for the new ones).
- **API versioning & compatibility policy (QUAL-03 or as numbered):** documented policy for admin API, headless API,
  config YAML, migrations; deprecation process; tested upgrade path 0.4 → 1.0 (the Phase 6 upgrade tests extended).
- **Docs site:** static site generated from docs/ (install, integrations, migration guides), built in CI; no third-party
  tracking; hostable on GitHub Pages (publishing is an owner action).
- **Phase 6 carry-overs:** tenant-restricted system admins (Q1 second half) — plan it or justify deferring past 1.0;
  SAML experimental flag stays until the external review + interop checklist (Q3), so the review scope must include SAML.

### Claude's Discretion
- Plan decomposition and waves (parallel plans with disjoint files incl. hidden shared files; foundations first).
- Docs site generator (prefer a small, maintained static generator or plain mdBook-style tool; no JS tracking).
- Exact requirement-ID mapping where ROADMAP numbering differs from PRD wording.
</decisions>

<deferred>
## Deferred Ideas
- SCIM provisioning, fine-grained authorization engine (D5, 3.0)
</deferred>

---
*Phase: 07-release-1-0-certification*

## Decisions after research (orchestrator defaults, 2026-11-26 — owner may override)

Owner-only decisions stay as checkpoints (not decided here): Q2 OIDF membership/fee/waiver + public deployment;
Q3 external reviewer, budget, timeline; Q9 publishing tags; Q12 which vendors get migration guides (each verified
against the vendor's current docs before commit); certification submission; GitHub private vulnerability reporting.

Technical defaults (researcher recommendations):
- **Q1 legacy-hash crypto:** plan the import verifiers with RustCrypto `scrypt` and `bcrypt`, scoped in deny.toml with
  wrappers (blowfish only via bcrypt, salsa20 only via scrypt), verification of imported hashes only; PBKDF2/SHA-2/AES-CTR
  via aws-lc-rs. This is a crypto-policy exception: the plan that adds it ends with a **checkpoint for owner approval**
  before the gate; if rejected, bcrypt/scrypt import is dropped and documented.
- **DoS caps:** hard caps on imported hash parameters (memory/iterations/cost) enforced at import AND verify, incl. for
  Argon2 parameters read from stored hashes; floors per research Q10 defaults.
- **Q4 password-hash export:** CLI-only, opt-in flag, audited; never in the admin API bulk export, never in the GDPR export.
- **Q5 headless SPAs:** per-tenant allow-list of origins (exact match), CSRF/binding per research design.
- **Q6 native headless:** support browser SPAs AND native first-party clients via PAR + PKCE returning the code as JSON,
  documented as following the IETF draft shape (not an RFC); first-party clients only.
- **Q7 agent clients:** explicit `client_kind = agent` marker (CIMD/DCR provenance shown too); agents never skip consent;
  incremental step-up prompts only for new scopes.
- **Q8 tenant-restricted system admins:** deferred to 1.x with written justification in ARCHITECTURE.
- **Q11 import ids:** keep source user ids when they are valid UUIDs so `sub` survives; otherwise generate.
- **Q13 API compatibility check:** small in-repo breaking-change test against the committed OpenAPI baseline (no beta tool).
- **Headless throttling:** extract one shared `flow_driver` used by both UI handlers and the headless API (no duplicate
  throttling/CAPTCHA/session logic).
- **Migrations:** new files only (SQLite 0010+, Postgres 0008+); upgrade tests cover 0.4→1.0 and beta.1→1.0; avoid
  CHECK-constrained discriminator columns that force SQLite rebuilds.
- **Review findings** are tracked privately (draft advisories), never committed before fixes ship.
