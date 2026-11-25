# Phase 4 deferred items

- (found by 04-02, 2026-11-25) `GET /api/admin/v1/tenants/{t}/email-templates` returns 500 at 04-01 commit 755d7c0 and later: admin_api_v02 `email_templates_default_override_validation_and_reset`, security_admin_v02 `every_new_route_requires_its_scope` / `every_new_route_accepts_its_resource_scope_and_admin_write`. Not caused by 04-02 (it fails before 04-02's Task 2/3 too); likely 04-01's in-progress anvil-mail render/check change.
- (found by 04-11, 2026-11-25) `cd admin-ui && npm run typecheck` fails before and after 04-11: `src/lib/email.ts` (EmailKind record lacks `login_code`, `email_change`, `email_changed`) and `src/routes/audit/index.tsx` (AuditAction record lacks the 15 Phase 4 actions). The enum values came into `schema.d.ts` with 04-01's regeneration; the console files are not 04-11's (the console plan, e.g. 04-19, should add them). `npm run check:api` is clean.
- RESOLVED: the email-templates 500 (fixed by 04-15) and the console typecheck failure (fixed by 04-19, 32bc998).

## Gate list (orchestrator, for 04-32 or a gap plan)

- Replaced branding logos are never purged (04-04); 04-18 could not do it within its files. Needs storage work: `purge_unreferenced_logos` (or extend `purge_expired`) in both backends with a contract test; delete only `branding_logo` rows no branding/draft row references (SQL sketch in 04-18-SUMMARY). Same gap plan: deleting a client leaves its branding row behind.
- Review 04-18's replacement of the global 64 KiB body limit with a per-request middleware (400 KiB only for the logo route): confirm every route still gets 413 above 64 KiB.
- Saved consent covers scopes only: a client already consented to is not re-prompted when it requests a different allowed resource (04-12). Phase 5 or a gap plan.
- Console: the read-only client detail card (`admin-ui/src/routes/clients/$clientId.tsx`) does not show the 0.3 client fields; the edit form does (04-19).
- `themes/default/README.md` should document `page.lang`/`page.dir`, `t()`, the `locales/` override directory and the logout pages (04-06, 04-13).
- Postgres `purge_expired` never deletes expired token families (SQLite does); pre-dates Phase 4 (04-05).
- `state advance-plan` cannot parse STATE.md during parallel waves; fix STATE.md Current Position at the phase gate.
- In-flow passkey registration as an MFA enrolment choice under `required` is not built; only TOTP enrolment is offered (04-16). Check against AUTH-08 wording at verification.
- Logout-token `iss` for custom-host tenants (04-17): tokens use the tenant's canonical issuer, but a user who signed in via `/t/{slug}` on a custom-host tenant got ID tokens with the path issuer. OIDC Back-Channel Logout requires the logout token's iss to match the ID token's; decide (e.g. record the issuer per RP session) before 0.3. Also: `canonical_issuer` (core) duplicates anvil-web's private `admin_issuer_of`; make the latter delegate.
- Docs pass (04-20): docs/ARCHITECTURE.md still lists prompt values `["none","login"]` (~line 478); themes/default/README.md should list select_account.html and selectors; document that `prompt=create` on a tenant requiring email verification cannot resume until the user verifies and signs in.
- Upstream sign-in (04-21): `require_verified_email` is not applied to accounts created from an untrusted provider (unverified email). Orchestrator recommendation: apply it (the user must verify before the account can be used), consistent with local registration. Gap plan.
- Upstream sign-in (04-21): every callback response clears the binding cookie, including rejections, so a forged cross-site callback can cancel a victim's pending upstream sign-in (they retry). Consider clearing only on success/state-match; low severity.
- Upstream sign-in buttons are missing from the lockout, CAPTCHA and passkey-failure login pages (04-21).
- Apple-specific path (ES256 client secret, first-login name) is implemented but covered only via the generic form_post hop until 04-26.
- Linked accounts (04-25): after Connect, `ui/upstream.rs` `outcome_page` still shows the `upstream.linked` message; make it a 303 to `/ui/account/linked` and update the assertion in `upstream_login.rs::account_page_link_connects_the_signed_in_user`.
- Linked accounts (04-25): the last-sign-in-method guard counts tenant email_otp/magic_link as a remaining method even when the user's email is unverified. Require a verified email for that to count (and confirm 04-24 only offers email sign-in for verified emails).
- Linked accounts (04-25): the guard is check-then-delete; two concurrent unlinks of different links could both pass and leave no sign-in method. Needs an atomic storage intent in both backends.
- Email sign-in (04-24): either tenant toggle (email_otp or magic_link) enables both code and link, because the login_code template always contains both. Either rename to one setting or let the template omit one; decide before 0.3 docs.
- Back-channel latency (04-28): only `/logout` and `/ui/logout` wake the delivery worker (`logout_wake`). A session switch (prompt=select_account "use another account", 04-16), account-page session revocation and admin revocations enqueue deliveries but wait for the 10 s poll. Consider waking the worker from `revoke_with_families` callers too; e2e waits allow 30 s for the switch case.

## Gate list disposition (planner, 2026-11-26)

Gap-closure plans 04-34..04-37 run before the gate. 04-32 now depends on them (wave 10) and 04-33 is wave 11.

- Planned in 04-34 (storage):
  - logo purge and client-branding cleanup;
  - Postgres token-family purge;
  - logout-token `iss` per RP session (new migrations SQLite 0006 / Postgres 0005; `admin_issuer_of` delegates to `canonical_issuer`);
  - atomic unlink guard with the verified-email rule;
  - verification-aware `create_user_with_link`.
- Planned in 04-35: independent `email_otp` / `magic_link` (optional `login_code` variables, per-toggle routes).
- Planned in 04-36:
  - back-channel wake on every revocation path (one helper);
  - upstream buttons on the lockout, CAPTCHA and passkey-failure pages;
  - console client card with the 0.3 fields;
  - a regression test for 04-18's per-request body limit (413 above 64 KiB everywhere except the logo uploads).
- Planned in 04-37:
  - `require_verified_email` for upstream accounts;
  - binding cookie cleared only on a state match;
  - 303 to `/ui/account/linked` after Connect;
  - docs for every closed gap.
- Already done: the themes README / ARCHITECTURE docs pass (04-31) and the Apple provider suite (04-26).
- At the gate: the STATE.md Current Position fix (04-32/04-33).

### Moved to Phase 5

- **Remembered consent covering resources (04-12).** Saved consent covers scopes only, so a client already consented to is not
  re-prompted when it requests a different allowed resource. Reason: OIDC-16 (audience-bound tokens, `invalid_target`, downscoping)
  is met without it. Closing it changes the consent model: the `consent_grant` schema, the consent screen and revocation. That
  belongs with the Phase 5 RBAC/permissions work rather than a late 0.3 storage change. Documented as a known limitation in
  ARCHITECTURE by 04-37.
- **In-flow passkey enrolment as an MFA choice under `required` (04-16).** Reason: AUTH-08 reads "Admin can set MFA policy
  (off/optional/required) per tenant, org or client; clients can request step-up via acr_values". It does not require passkey
  enrolment during sign-in. TOTP enrolment satisfies `required` in 0.3, and passkeys can be added from the account page.
  Documented by 04-37.
- (found by 04-27 CI follow-up) Generic OIDC connections to spec-following providers (email only in UserInfo, OIDC Core 5.4) fail with `email_missing` unless the admin enables fetch_userinfo. Fix in 04-37: fall back to UserInfo when the ID token has no email (or default fetch_userinfo on for generic OIDC), with a test.
- (found by 04-27 CI follow-up) Cookie names are derived from the first 12 hex chars of the tenant UUIDv7, which is just its millisecond timestamp: two tenants created in the same millisecond share session/flow/binding cookie names. Fix in 04-37: derive the suffix from the whole id (e.g. a short hash), keep it stable, test two tenants with the same timestamp prefix.
