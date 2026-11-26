# Phase 7 deferred items

Items found during execution, dispositioned at the 07-23 gate.

- (07-10) Headless browser mode: `login_hint` prefill on API start not implemented.
- (07-10) No second-factor happy-path test through the headless API (wired through the same flow_driver call as ui::mfa, untested). 07-18 or the gate should add it.
- (07-10) `GET /api/flows/v1/{unknown}` returns 405 with empty body (router limitation); unknown kinds on other paths get JSON 404.
- (07-01) Owner approval of the scrypt/bcrypt crypto exception pending.
- (07-06) Owner action pending: enable GitHub private vulnerability reporting; decide the SECURITY.md alternative contact.
- (07-15) `anvilid users export` without --out disables tracing so the stdout audit mirror doesn't corrupt the NDJSON; consider routing the CLI audit mirror to stderr instead.
- (07-13) docs/ARCHITECTURE.md ~L236 says authorization_request is "also used for PAR"; PAR has its own table since 07-08 (07-22 docs pass).
- (07-13) docs/SUMMARY.md needs entries for PAR.md, HEADLESS.md, IMPORT-EXPORT.md (07-22).
- (07-13) /par has only the per-IP Token rate class, no per-client limit.
- (07-13) id_token_hint refused at /par (documented in PAR.md).
- (07-13) Observed once mid-wave: export_redaction "admin email leaked" failures during a shared-tree run; passed in final runs. Watch for flakiness at the gate.
- (07-19) docs/SUMMARY.md needs CERTIFICATION.md; THREAT-MODEL.md and SECURITY-REVIEW-SCOPE.md link `../SECURITY.md` (fails docs-site link check if added to the site) — 07-22.
- (07-17) New import/export/profile named negatives must be registered in scripts/check-security-tests.sh (07-23 gate). futures-util added as direct dep (already in graph via axum).
- (07-18) Native headless completion still creates a server-side session row (its cookie is never sent): authorization_code.session_id is NOT NULL and create_code writes rp_session with an FK to browser_session. Owner decision at the gate: accept, or make code issuance session-less in a later release. Browser-mode second-factor happy path (07-10 item) is now covered by headless_native::browser_mode_second_factor_completes_the_sign_in.
- (07-18) New native named negatives (security_headless.rs `native_*`) may need registering in scripts/check-security-tests.sh (07-23 gate).
- (07-18) Orchestrator default (owner may override): native headless sign-in keeps the server-side browser_session row (authorization_code.session_id NOT NULL; rp_session FK) but never sends its cookie, proven by native_no_sso_session_created. Accepted for 1.0; sessionless code issuance is a 1.x candidate. 07-22 documents it in HEADLESS.md.
- (07-21) docs/SUMMARY.md needs COMPATIBILITY.md; ARCHITECTURE.md (~L1440, ~L1463) and OPERATIONS.md "Limitations in 1.0" still say tenant-restricted admins are "deferred to Phase 7" (now: later 1.x, Q8); COMPATIBILITY.md mentions a CHANGELOG that doesn't exist (07-22). UPGRADING.md anchors unverified until the docs CI build.
- (07-21) API baselines were captured at 0ab478f (pre-rc); 07-23 should re-confirm they equal the rc documents (additions since are allowed; anything else is a break).
- (07-20) Tenant switcher doesn't keep the Password hash profiles section (TENANT_PAGES in lib/tenant.ts not extended).
