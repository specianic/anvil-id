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
