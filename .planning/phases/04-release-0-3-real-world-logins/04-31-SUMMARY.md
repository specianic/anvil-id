---
phase: 04-release-0-3-real-world-logins
plan: 31
subsystem: docs
tags: [docs, architecture, upgrading, theme-contract, i18n, social-login-checklist, ui-04]
requires:
  - phase: 04-01 … 04-26
    provides: the APIs, routes, selectors, decisions and divergences recorded in their SUMMARYs
provides:
  - "docs/ARCHITECTURE.md synced with 0.3 (data model, storage intents, tokens, logout, flows, federation, HTTP surface, i18n, theming, controls, config, jobs, CI)"
  - "docs/UPGRADING.md 0.2 -> 0.3 section"
  - "docs/social-login-checklist.md (manual real-provider checklist, `Last verified: not yet`)"
  - "themes/default/README.md theme contract for every 0.3 template, t(), locales/"
  - "PRD and REQUIREMENTS scope notes (UI-04 pages only, AUTH-07 manual checklist)"
affects: [04-32, 04-33]
tech-stack:
  added: []
  patterns: []
key-files:
  created:
    - docs/social-login-checklist.md
  modified:
    - docs/ARCHITECTURE.md
    - docs/PRD.md
    - docs/UPGRADING.md
    - themes/default/README.md
    - .planning/REQUIREMENTS.md
key-decisions:
  - "04-31: ARCHITECTURE keeps the historical 'built in 0.1/0.2' paragraphs and adds 'added in 0.3' text next to them instead of rewriting history; the 0.1 prompt list is annotated, not deleted"
  - "04-31: known gaps found by earlier plans are documented in the docs as open items (logout-token iss for custom-host tenants, require_verified_email for untrusted upstream accounts, email_otp/magic_link meaning the same thing, logo purge, resource-aware consent, no in-flow passkey enrolment), not described as done"
  - "04-31: UPGRADING warns that breach_check_url and back-channel endpoints on private networks now need outbound_allow_cidrs (the guarded client applies to HIBP and CAPTCHA too)"
requirements-completed: []
duration: about 50 min
completed: 2026-11-25
---

# Phase 4 Plan 31: Docs pass for 0.3 Summary

**ARCHITECTURE, PRD, REQUIREMENTS notes, UPGRADING and the theme README now describe what release
0.3 actually built. The owner has a concrete, secret-free real-provider checklist that ends in
`Last verified: not yet` for 04-33 to update.**

No requirement checkbox was ticked (the gate ticks them after phase verification). The plan's
requirement list is documentation coverage only.

## What changed

- **ARCHITECTURE.md**
  - Stack table: our own upstream relying party on the guarded reqwest client plus anvil-jose. The
    reason is the dependency policy: the evaluated crates pull in `chrono` and a second crypto
    stack. Fluent is listed for i18n.
  - Services table: the four 0.3 services.
  - §6.1 data model: `connection`, `identity_link` with `connection_id`/`metadata`/`last_used_at`,
    `rp_session` without `sid`, `logout_delivery`, `branding`/`branding_logo` (Postgres
    `branding_draft`), the new client columns, tenant settings and their defaults, the widened kind
    checks, and the migration names.
  - §6.2 secrets: email codes (flow-bound HMAC), magic-link and email-change tokens, connection
    secrets with their AAD.
  - §7: the three new repos, the 0.3 intents, enqueue-on-revoke, the 0.2 -> 0.3 upgrade test and
    purge additions.
  - §8: RFC 8707 rules, the UserInfo audience rule, `amr` `otp`/`fed`, and a new §8.3 Logout.
    §8.3 covers RP-initiated decisions and hint rules, and back-channel delivery: worker, lease,
    retry table, give-up audit, current URI, and the canonical-issuer open item.
  - §9: login engine 0.3, session switch, `login_hint`, and `prompt` handling (select_account,
    create, plus `create` with required email verification). New §9.1 MFA policy (strictest wins,
    enrolment, step-up, `unmet_authentication_requirements`). New §9.2 upstream sign-in and the
    linking decision table. New §9.3 email code and magic link.
  - §10: discovery additions and 0.3 prompt values (the old `["none","login"]` line is annotated),
    the 0.3 UI routes table, 0.3 admin API resources and scopes, new §10.6 i18n and §10.7 theming.
  - §11: the SSRF row rewritten for the guarded client and the operator keys. New rows for upstream
    sign-in, email sign-in, RP-initiated logout and theming. CSP exception for the preview page.
  - §13: 0.3 config keys. §14: back-channel worker. §17: five conformance plans. §19: connections
    enum and back-channel not being an event subscriber.
  - M3 exit criterion: checked. It already reads "mock IdPs in CI plus a manual real-provider
    checklist", and so does ROADMAP Phase 4 criterion 2.
- **PRD.md:** notes under the AUTH and UI tables: AUTH-7 real-provider verification is the manual
  checklist; UI-4 covers pages only and localized email templates come later.
- **REQUIREMENTS.md:** "Scope notes (Phase 4, release 0.3)" for UI-04 and AUTH-07. No checkbox and
  no traceability status changed.
- **UPGRADING.md (0.2 to 0.3):**
  - Back up first.
  - Both migrations: the SQLite rebuilds are transactional and non-destructive, Postgres only adds.
  - Stop 0.2 nodes before starting 0.3.
  - Defaults table: MFA optional, email sign-in off, auto-link on, consent unchanged, empty client
    logout/resource fields.
  - The new keys, with the private-network caveat.
  - Behaviour changes: discovery, logout, `acr_values`/`prompt`, resources, the UserInfo audience
    rule, languages, user switch, `login_hint`, admin scopes.
  - What to configure next.
- **themes/default/README.md:**
  - Page context and form shape: `locales/` in the layout, `page.lang`/`page.dir`, the `label_key`
    and `args` fields.
  - New "Translations" section: `t()`, `<bdi>`, fallbacks, one file per feature, the id rule,
    duplicate and malformed files, the completeness test, the override directory, the negotiation
    order.
  - Variables of every 0.3 template. The `account_base` variables are corrected: it is
    `account_base`/`account_nav`, no longer `current`.
  - The seven-entry account navigation.
  - "Release 0.3 pages" selector list: upstream buttons, email code, magic link, link confirmation,
    MFA enrolment, chooser, consent resources, logout pages, account profile/email/password/linked,
    preview, `.anvil-logo`.
  - The logout contract sentences and URL layout.
  - The new CSS hooks and the three new email contracts. Branding through the console is described
    as the first option before overriding the theme.
- **docs/social-login-checklist.md (new, 189 lines):**
  - Preparation steps and the redirect URI format (placeholder host only).
  - Google: just-in-time sign-up, second sign-in, auto-link, `hd`, rotation.
  - Apple: Services ID/Team/Key/.p8, the PKCE check, the client secret, first-login name, Hide my
    email, second login without a name, form_post return, key rotation.
  - Microsoft: personal and work accounts, email never trusted, single directory, the
    risk-acceptance switch, rotation.
  - GitHub: private email, no verified email, renamed login, auto-link, rotation.
  - Generic OIDC.
  - Link confirmation (with MFA), connect, already-linked refusal, last-method guard, disabled
    connection.
  - A recording template that holds no secrets, then `Last verified: not yet`.

## Divergences raised (doc vs code, now synced)

1. `rp_session.sid` was in §6.1. It is dropped: `sid` is the browser session id, which ID tokens
   have used since 0.2.
2. §6.1 listed `branding (JSON)` on `client`. Branding is a separate per-scope `branding` table
   with content-addressed logos. Postgres keeps drafts in `branding_draft`, SQLite in columns.
3. `identity_link.provider_id` is now `connection_id`, and the table also has `metadata` and
   `last_used_at`.
4. `connection` was listed as a 1.0 org row. It shipped in 0.3, tenant-scoped, with OAuth 2 as a
   kind next to Social and OIDC (§19 updated).
5. §19 said back-channel logout is an event subscriber. Deliveries are enqueued by the revoking
   storage intents in the same transaction.
6. §14 listed back-channel delivery as a lease-guarded job. It is a per-node worker with 2-minute
   row leases (and `SKIP LOCKED` on Postgres), not a `job_lease`.
7. The CONTEXT locale order was ui_locales > Accept-Language > tenant default. The code also puts
   the user's `locale` claim between ui_locales and Accept-Language, on account pages only.
   Documented as built.
8. Logout pages: the confirmation is reached by a 303 to `/ui/logout`, the signed-out page after
   confirmation is `/ui/signed-out`, and errors use `logged_out.html` in error mode (the
   conformance contract).
9. The theme README had a stale `current` variable for `account_base.html`, and a CSS class table
   split by a paragraph. Both fixed.

Open items documented as open (not fixed here; the code follow-ups stay in deferred-items.md for
the gap plan):
- Logout-token `iss` for custom-host tenants.
- `require_verified_email` for untrusted upstream accounts.
- `email_otp`/`magic_link` both enable the code and the link.
- Logo purge.
- Consent covers scopes only (no resources).
- No in-flow passkey enrolment.

## Task Commits

1. **Task 1: ARCHITECTURE, PRD, REQUIREMENTS notes, UPGRADING:** `f206b80`
2. **Task 2: Theme README contract + social-login checklist:** `bfa574e`
3. **Follow-up:** `c1a1592` (theme README) and `f5b9951` (ARCHITECTURE §10.6).
   04-30 landed during this run and its catalog parity test (`i18n_catalogs.rs`) makes every
   shipped locale complete, so "other languages may be partial" was corrected

## Verification

- Task 1 automated check: `outbound_allow_cidrs` and `logout_delivery` in ARCHITECTURE, "0.2 to 0.3"
  in UPGRADING. Passes.
- Task 2 automated check: `logout-confirm-submit` in the README, Apple in the checklist, a
  `^Last verified:` line, no secret-shaped `client_secret`. Passes.
- Checked against the code, not only the summaries:
  - Postgres 0004 table definitions, tenant setting defaults (`MfaPolicy::Optional`), template
    header comments and ids, `logout.ftl` sentences (copied byte for byte), account nav ids.
  - The `parse_resources` rules, the SSRF block list, the CSS deny-list, RTL languages, the i18n
    negotiation doc comment and test names.
  - Upstream audit actions and `.ftl` message texts used in the checklist.
- Public-repo hygiene: the only URLs in the new text use `id.example.com`. There are no secrets or
  real account names. The single claim about third-party crates is dated and limited to their
  dependency lists. Provider steps say what AnvilID needs, without describing provider consoles in
  detail.
- No code, build or test run was needed (markdown only).

## Deviations from Plan

None in scope. Notes:
- `requirements` in the plan frontmatter lists IDs the docs cover. Per the orchestrator, no
  checkbox was ticked and `requirements mark-complete` was not run.
- ROADMAP Phase 4 criterion 2 already had the agreed wording, so ROADMAP.md was not edited for it
  (it is not in this plan's files).

## Self-Check: PASSED

- FOUND: docs/social-login-checklist.md, docs/UPGRADING.md, docs/ARCHITECTURE.md, themes/default/README.md
- FOUND: commits f206b80, bfa574e, c1a1592, f5b9951
