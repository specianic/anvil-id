---
phase: 07-release-1-0-certification
plan: 06
subsystem: security-policy
tags: [security, SEC-08, disclosure, threat-model, external-review]
status: complete
requires: []
provides:
  - SECURITY.md (published security policy, owner placeholder pending)
  - docs/SECURITY-REVIEW-SCOPE.md (external review scope, package inputs, reviewer brief, findings rule)
  - docs/THREAT-MODEL.md (assets, attacker models, trust boundaries, control map to QUAL-01 groups)
affects: [07-23 gate (maps Phase 7 controls), 07-25 review commissioning, 07-27 release checklist (reword supported-versions table)]
tech-stack:
  added: []
  patterns: [GitHub private vulnerability reporting, GitHub Security Advisories with CVE, private draft advisories for review findings]
key-files:
  created:
    - SECURITY.md
    - docs/SECURITY-REVIEW-SCOPE.md
    - docs/THREAT-MODEL.md
  modified: []
decisions:
  - "SECURITY.md carries two supported-versions tables: the pre-1.0 one (latest 1.0 prerelease and 0.4.x) and the post-1.0 one (1.0.x only) that replaces it at release"
  - "Response targets are stated as targets, not guarantees: acknowledgement 5 working days, assessment 14 days, critical/high fix aiming for 30 days, medium/low aiming for 90 days (owner may adjust)"
  - "Threat-model control groups are the map label before the first colon, or the whole label when it has none; every group name used was checked against scripts/check-security-tests.sh"
metrics:
  duration: ~35 min
  completed: 2026-11-26 (Task 1); Task 2 awaiting owner
requirements: [SEC-08 (not ticked; 07-27 ticks it after the review)]
---

# Phase 7 Plan 06: Security policy and external review package Summary

Public-safe security policy (GitHub private vulnerability reporting, advisories with CVEs, fixes in the
open-source release) plus the external review package: a scope document covering every surface from
research §Security policy (with PAR, DCR/CIMD, both headless modes, import caps, export redaction, SAML
SP and the chrono exception, supply chain), and a threat model mapping eight trust boundaries to the
QUAL-01 security-map groups.

## Documents

- `SECURITY.md`: supported versions (pre-1.0 and post-1.0 tables), reporting through the Security tab
  -> Report a vulnerability, the owner placeholder line
  `<!-- OWNER: optional alternative contact (leave out to use GitHub private reporting only) -->`,
  what a report should contain, safe-testing note, response targets, coordinated disclosure through
  GitHub Security Advisories with a CVE, "fixes ship in the open-source release", scope and out of scope.
- `docs/SECURITY-REVIEW-SCOPE.md`: version to review ("the 1.0.0 release candidate tagged at the 07-23
  gate"), in-scope surfaces, review package inputs table, reviewer brief (build and run, test accounts via
  `tests/conformance/setup.sh`, `tests/e2e/run.sh` and `tests/e2e/lib/`, known limitations, out of scope),
  findings handling (private GitHub draft security advisories, nothing public before fixes ship, public
  summary only after release).
- `docs/THREAT-MODEL.md`: assets, attacker models, trust boundaries (browser to UI, RP to protocol
  endpoints, admin to management API, headless SPA and native clients, upstream IdPs/SAML IdPs, outbound
  fetches/SSRF, storage/KEK, operator/CLI) plus supply chain, each with attacker capabilities and named
  control groups; Phase 7 controls marked "mapped at the 07-23 gate"; residual risks for 1.0.

## In-scope list (review)

Protocol endpoints (discovery, JWKS, authorize, token, userinfo, introspect, revoke, PAR, DCR/RFC 7592,
CIMD, RP-Initiated and Back-Channel Logout, token issuance); headless flow API browser and native modes;
flow engine, sessions, account pages, consent incl. agent clients, upstream sign-in and linking; password
import verifiers, floors and caps; export redaction; admin API and console authZ (RBAC, org admins, scope
bounding, config, keys API); SAML SP (D4 corpus, profile pre-check, conditions/replay/binding, metadata,
bergshamra/uppsala stack, chrono exception); organizations, domains and enterprise SSO; KEK sealing and
key rotation; SSRF guard; CSRF, cookies, CSP and headers; multi-tenant isolation; webhooks; rate limiting
and abuse resistance; migrations, backup/restore, setup, recovery, healthcheck; supply chain (deny policy,
deps check, release graph, release workflow and attestations).

## Task status

| Task | Name | Status | Commit |
| --- | --- | --- | --- |
| 1 | SECURITY.md, review scope with brief, threat model | done | 7ae54a2 |
| 2 | Owner enables GitHub private vulnerability reporting | **awaiting owner (checkpoint:human-action)** | - |

## Verification

- Plan Task 1 automated verify (file presence, required strings, no email-like strings): passed.
- Extra: every backticked control-group name in the trust-boundary sections exists as a label (or label
  prefix) in `scripts/check-security-tests.sh`; no URLs other than localhost examples; no personal names,
  phone numbers or private hostnames in the three documents.
- `gh api repos/{owner}/{repo}/private-vulnerability-reporting` before the owner action (read-only):
  `{"enabled":false}`.
- No Rust code changed; no cargo, release-graph or security-map runs were needed for this docs-only plan.

## Owner confirmation

2026-11-27. Owner reply (verbatim): "I enabled private vulnerability reporting". No alternative contact was
given, so the SECURITY.md placeholder was removed (GitHub private reporting only).
`gh api repos/{owner}/{repo}/private-vulnerability-reporting` returned `{"enabled":true}`.

## Deviations from Plan

None in scope. Two wording corrections made while self-checking claims against the repository before
committing: "reproducible" was dropped from the release-binary description and the container image is
described only as running as non-root (both unverified otherwise).

## Self-Check: PASSED

- FOUND: SECURITY.md, docs/SECURITY-REVIEW-SCOPE.md, docs/THREAT-MODEL.md
- FOUND: commit 7ae54a2
