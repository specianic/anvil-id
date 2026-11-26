# Phase 7 deferred items

Items found during execution, dispositioned at the 07-23 gate.

- (07-10) Headless browser mode: `login_hint` prefill on API start not implemented.
- (07-10) No second-factor happy-path test through the headless API (wired through the same flow_driver call as ui::mfa, untested). 07-18 or the gate should add it.
- (07-10) `GET /api/flows/v1/{unknown}` returns 405 with empty body (router limitation); unknown kinds on other paths get JSON 404.
- (07-01) Owner approval of the scrypt/bcrypt crypto exception pending.
- (07-06) Owner action pending: enable GitHub private vulnerability reporting; decide the SECURITY.md alternative contact.
