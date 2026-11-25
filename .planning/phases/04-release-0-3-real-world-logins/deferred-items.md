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
