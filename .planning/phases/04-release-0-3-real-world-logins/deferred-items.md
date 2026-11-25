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
