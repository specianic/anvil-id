---
phase: 07-release-1-0-certification
plan: 22
subsystem: docs
status: complete
tags: [docs, mdbook, migration, install, guides, architecture, security-policy]
requires: ["07-01", "07-06", "07-07", "07-10", "07-13", "07-14", "07-16", "07-17", "07-18", "07-19", "07-21"]
provides:
  - "docs site navigation covering every Phase 7 page"
  - "install, integration (OIDC app, SPA, native app, MCP/agents) and migration guides (overview, Firebase, AnvilID-to-AnvilID)"
  - "ARCHITECTURE describing the built 1.0 (PAR, headless, import/export, M5, Q8)"
  - "check-docs-site.sh rule 5 (SECURITY.md) with self-test"
affects: ["07-23 gate (docs CI)", "07-27 release (Pages URL, SECURITY.md placeholder)"]
key-files:
  created:
    - docs/INSTALL.md
    - docs/guides/oidc-app.md
    - docs/guides/spa.md
    - docs/guides/native-app.md
    - docs/migration/README.md
    - docs/migration/firebase.md
    - docs/migration/anvilid.md
    - docs/security.md
    - docs/reference.md
  modified:
    - docs/SUMMARY.md
    - docs/MCP.md
    - docs/ARCHITECTURE.md
    - docs/THREAT-MODEL.md
    - docs/SECURITY-REVIEW-SCOPE.md
    - scripts/check-docs-site.sh
    - README.md
decisions:
  - "Vendor guides (Q12): owner has not answered; no vendor guide beyond Firebase and AnvilID-to-AnvilID written"
  - "docs/security.md links SECURITY.md on GitHub instead of {{#include}}: SECURITY.md's own docs/... links would break inside the site"
  - "Guides in docs/guides and docs/migration link sibling site pages with ../X.md (inside docs/, verified by the site link check); nothing links outside docs/"
  - "OpenAPI reference is one page (docs/reference.md): mdBook SUMMARY entries must be Markdown chapters"
metrics:
  completed: 2026-11-26
  tasks: "2 of 3 (Task 1 awaiting owner)"
---

# Phase 7 Plan 22: Documentation site for 1.0 Summary

The docs site now covers install, integrations (OIDC web app, SPA, native app, MCP/agents) and
migration (overview, Firebase, AnvilID-to-AnvilID), with every Phase 7 page in the navigation.
ARCHITECTURE describes the built 1.0, and the site check guards SECURITY.md. The vendor choice (Q12)
is still open: Task 1 is a real owner checkpoint.

## Tasks

| Task | Name | Status | Commit |
| --- | --- | --- | --- |
| 1 | Owner picks vendor migration guides (Q12) | **awaiting owner** | - |
| 2 | Install, integration and migration guides | done | 8ce24fb |
| 3 | SUMMARY, ARCHITECTURE, README link, SECURITY.md check, site build | done | 59beb0f |

## Owner vendor decision (Q12)

Owner decision (verbatim, 2026-11-27): "let's do Auth0, Keycloak, AWS Cognito, Okta, Supabase Auth, Clerk and
Microsoft Entra (Azure AD B2C)". The owner chose these after being told that, as far as known before verification,
Cognito, Okta and Entra do not export password hashes: their guides cover moving users and profile data with a
password reset (or other first-sign-in path) instead of keeping passwords. Each guide is verified against the vendor's
current public documentation (URL + date footer).

Question asked: which source providers get dedicated migration guides in 1.0, beyond the generic
format overview, Firebase and AnvilID-to-AnvilID? Reply "none" or a list of vendors. Each named
vendor's current public export documentation is checked (URL and date in the guide footer)
before its guide is written; a vendor whose docs do not describe a hash export in a format 07-02
accepts gets no guide and is reported instead. docs/migration/README.md is written so per-vendor
guides drop in (sources list plus an "Adding a guide for another source" section) and names no
unverified vendor.

## Pages written

- docs/INSTALL.md: zero-config start, binary archive with sha256 and `gh attestation verify`,
  container image, Compose with Postgres, Helm, going beyond localhost, where data lives, next steps.
  Flags taken from `anvilid --help` (release build of HEAD).
- docs/guides/oidc-app.md: issuer and discovery, client registration (console/API), code + PKCE,
  refresh rotation, logout, optional PAR, troubleshooting.
- docs/guides/spa.md: same-site requirement, allow-list (`headless.allowed_origins`), public
  client, the API sign-in with `X-CSRF-Token` and `credentials: "include"`, then a top-level
  `/authorize` with `prompt=none` and the token exchange; the `request`/`continue_to` variant.
- docs/guides/native-app.md: first-party only and why (RFC 8252 for third parties), eligibility
  rules, PAR + flow start + `AnvilFlow` token + code as JSON + token exchange, flow-token
  handling, `browser_required` fallback, the server-side session row whose cookie is never sent.
- docs/MCP.md: "Agent clients (1.0)" (how admins mark `client_kind: agent`, provenance notes,
  agents never skip consent) and "Incremental consent (step-up)".
- docs/migration/README.md: overview, record format, id preservation, CLI/API import, dry run,
  reports, re-runs, caps/floors/weak hashes, first-login rehash, leaving AnvilID.
- docs/migration/firebase.md: hash parameters, `auth:export`, hash profile, a jq conversion
  filter (`firebase_scrypt`), import, after-import checks; "Checked against" footer.
- docs/migration/anvilid.md: tenant YAML first, `--include-password-hashes` export, a jq filter
  converting every stored form (Argon2, bcrypt, `$anvil-scrypt$`, `$anvil-pbkdf2$`, `$anvil-sha2$`,
  `$anvil-firebase-scrypt$` with a profile id map) into import records, blocked-user caveat, what
  does not move.
- docs/security.md, docs/reference.md, docs/SUMMARY.md (Get started, Integrate, Migrate, Operate,
  Security, Design, Reference, Project).
- docs/ARCHITECTURE.md: §6.1 `pushed_authorization_request` and `password_hash_profile` rows, the
  1.0 client columns, the stale "Also used for PAR" fixed; §10.1 PAR; §10.2 headless browser and
  native modes over `flow_driver` (incl. the native session-row note); §10.3 import/export/profile
  routes and `admin:users:export` (129 operations); §10.3/§19 tenant-restricted admins now "later
  1.x (Q8)"; §18 M5 status; §20 Q8 row with the justification. §2 keeps "owner review pending
  (07-01)" (no approval recorded).
- README.md: Documentation section; the Pages URL is given as "once published" (07-27 confirms it).

## Vendor documentation checked

| Source | URL | Read on |
| --- | --- | --- |
| Firebase, "auth:import and auth:export" (page marked "Last updated 2026-11-19 UTC") | https://firebase.google.com/docs/cli/auth | 2026-11-26 |
| firebase/scrypt README | https://github.com/firebase/scrypt | 2026-11-26 |

## Verification

- Task 2 automated verify (grep set): pass.
- `scripts/check-docs-site.sh --self-test`: 18/18 (14 existing + 4 new rule-5 cases: missing file,
  no table, table outside the section, `OWNER:` placeholder).
- Site build: mdBook 0.5.4 installed in scratch (`cargo install --locked`), built from a copy of
  docs/ without research/ plus book.toml and SECURITY.md: build ok.
  `scripts/check-docs-site.sh <book>`: **fails only on rule 5**, because SECURITY.md line 40 still
  holds the 07-06 `OWNER:` placeholder (owner action pending). The same build checked against a
  SECURITY.md copy without that line passes every rule. Docs CI (docs.yml) will be red on this rule
  until the owner resolves the placeholder (fill in the contact or delete the comment).
- Extra: every `#anchor` link in the built site resolves to an id on its target page (29 pages,
  0 bad), including the UPGRADING.md anchors 07-21 could not verify.
- Guides exercised against the release build of HEAD (two scratch instances, SQLite, deleted
  afterwards): Firebase filter + import with the published firebase/scrypt sample (sign-in ok,
  also with URL-safe base64); AnvilID-to-AnvilID export, filter and import with Argon2id, bcrypt,
  scrypt, Firebase scrypt (mapped profile), PBKDF2 and salted SHA-2 users: all signed in on the
  target, ids identical, re-import all `unchanged`; SPA sequence (allow-list PATCH, preflight
  headers, 403 `csrf` without the header, API sign-in, `/authorize?prompt=none` code, token
  exchange); native sequence (client with `headless_native`, PAR, flow start with `flow_token`, 403
  `browser_signals` with `Origin`, completion with code/iss/state, token exchange).
- `scripts/check-release-graph.sh`: OK. No Rust code changed.

## Deferred-items routed to 07-22

Handled: docs/SUMMARY.md entries (PAR, HEADLESS, IMPORT-EXPORT, COMPATIBILITY, CERTIFICATION,
security pages); `../SECURITY.md` links in THREAT-MODEL.md and SECURITY-REVIEW-SCOPE.md (now GitHub
URLs; needed for the site link check); ARCHITECTURE PAR table line and both "deferred to Phase 7"
lines (now 1.x, Q8, with the justification in §20); HEADLESS.md already documents the native
session row (07-18 wrote it), and the native-app guide and ARCHITECTURE §10.2 repeat it.

Not handled (outside this plan's files): docs/OPERATIONS.md "Limitations in 1.0" still says
tenant-restricted admins are "deferred to Phase 7"; docs/COMPATIBILITY.md mentions a CHANGELOG that
does not exist. Both are one-line fixes for the gate (07-23) or 07-27.

## Deviations from Plan

- [Rule 3 - Blocking] docs/THREAT-MODEL.md and docs/SECURITY-REVIEW-SCOPE.md edited (not in
  files_modified): their `../SECURITY.md` links would fail the site link check once in SUMMARY.
- [Rule 3 - Blocking] docs/reference.md created (not in files_modified): mdBook SUMMARY entries must
  be Markdown chapters, so the OpenAPI JSON files are linked from one reference page.
- docs/security.md links SECURITY.md on GitHub instead of `{{#include ../SECURITY.md}}`: the
  included file's `docs/...` links would resolve to missing pages in the site.
- Pages under docs/guides/ and docs/migration/ link sibling site pages with `../X.md`. These stay
  inside docs/ and are verified by the site's broken-link check; no link points outside docs/.
  INSTALL.md links the migration overview as `migration/` because mdBook renders README.md as
  index.html.
- README.md got only the Documentation section; its stale "Status: early release (0.2)" text is
  left for the release commit (07-27).

## Self-Check: PASSED

- FOUND: docs/INSTALL.md, docs/guides/{oidc-app,spa,native-app}.md, docs/migration/{README,firebase,anvilid}.md, docs/security.md, docs/reference.md
- FOUND: commits 8ce24fb, 59beb0f

## Vendor guides (Task 1 resumed, 2026-11-27)

Written after the owner's decision, each verified against the vendor's current public docs (footer per guide) and
tested on synthetic example.test data imported into a scratch AnvilID build:
docs/migration/auth0.md, keycloak.md, supabase.md, clerk.md (passwords kept) and cognito.md, okta.md, entra.md
(profiles only; hashes not exportable or no export documented). Linked from docs/SUMMARY.md and docs/migration/README.md.
mdBook 0.5.4 build of a research-free copy passes scripts/check-docs-site.sh.
