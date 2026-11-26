---
phase: 07-release-1-0-certification
plan: 10
subsystem: headless-flow-api
tags: [headless, spa, cors, csrf, openapi, flow-driver, UI-05]

requires:
  - phase: 07-03
    provides: TenantSettings.headless.allowed_origins (HeadlessSettings)
  - phase: 07-04
    provides: api_flows skeleton merged outside the UI Fetch-Metadata layer; POST /api/flows rate-limit class Auth
  - phase: 07-05
    provides: ui::flow_driver (start, start_login, submit, identify, passkey_*, login_methods, DriveOutcome)
provides:
  - "/api/flows/v1 browser mode: start/get/submit for login, registration, recovery, verification, plus 6 passkey sub-routes, all through ui::flow_driver"
  - "versioned DTO (api_flows::dto): FlowResponse, FormDto, FieldDto, MethodDto, FlowProblem, StartRequest, SubmitRequest, PasskeyRequest"
  - "layers::csrf::headless_origin_layer and layers::cors::headless_cors (router-local)"
  - "docs/openapi/flows-v1.json (utoipa) with tests/openapi_flows_drift.rs; just openapi-update regenerates both documents"
  - "docs/HEADLESS.md with a 'Native apps' placeholder for 07-18"
affects: [07-12 (admin/YAML exposure of headless.allowed_origins), 07-18 (native mode adds FlowBinding::Token and fills HEADLESS.md 'Native apps'), 07-21 (compatibility policy names /api/flows/v1), 07-23 gate]

tech-stack:
  added: []
  patterns:
    - "Second renderer: JSON handlers encode DriveOutcome/FlowOutcome exactly where the page handlers render templates"
    - "Hidden DTO field factor_token carries the existing sealed binding tokens (second factor, email step) instead of a new mechanism"

key-files:
  created:
    - crates/anvil-web/src/api_flows/browser.rs
    - crates/anvil-web/src/api_flows/dto.rs
    - crates/anvil-web/src/api_flows/openapi.rs
    - docs/openapi/flows-v1.json
    - docs/HEADLESS.md
    - crates/anvil-web/tests/openapi_flows_drift.rs
    - crates/anvil-web/tests/headless_support/mod.rs
    - crates/anvil-web/tests/headless_flows.rs
    - crates/anvil-web/tests/security_headless.rs
    - tests/e2e/specs/headless.spec.ts
    - tests/e2e/fixtures/headless-spa/index.html
    - tests/e2e/fixtures/headless-spa/app.js
  modified:
    - crates/anvil-web/src/api_flows/mod.rs
    - crates/anvil-web/src/layers/cors.rs
    - crates/anvil-web/src/layers/csrf.rs
    - crates/anvil-web/src/ui/flow_driver.rs
    - crates/anvil-web/src/ui/mod.rs (forced extra, visibility)
    - crates/anvil-web/src/ui/mfa.rs (forced extra, visibility)
    - crates/anvil-web/src/ui/email_code.rs (forced extra, visibility)
    - crates/anvil-web/tests/skeleton_v10.rs
    - justfile

key-decisions:
  - "step is a small enum (form, message, completed, browser_required); form.id names the form step. Unknown steps, field kinds and methods are ignored by clients (documented versioning rule)"
  - "result.continue_to is an absolute URL on the AnvilID origin ({issuer}/authorize/continue?request=…): a relative path would resolve against the SPA's origin"
  - "Upstream/SAML/enterprise SSO (method upstream, identify -> StartIdp, start_login -> Idp) answer browser_required with the built-in sign-in page URL ({issuer}/ui/login[?request=]); the UI's POST-only upstream start cannot be reached top-level from a same-site SPA (Fetch-Metadata refuses same-site POSTs)"
  - "Registration not open (disabled or invite-only) is 403 registration_disabled at start; no flow is created"
  - "GET .../{flow_id} re-renders the step read-only through flow_driver::current_step (core engine::current_form + check_binding); one-time values (TOTP secret, binding tokens) are only in the answer that produced them"
  - "The second-factor and email-step binding tokens of ui::mfa / ui::email_code are reused as a hidden factor_token field; flow_driver exposes seal/open wrappers so api_flows never touches the KEK purposes itself"
  - "The JSON catch-all moved to /api/flows/v1/{kind}/{flow_id}/{*rest}: matchit refuses a catch-all next to the {kind} parameter; unknown kinds are refused by the handlers (404 not_found)"

requirements-completed: []

duration: ~2h
completed: 2026-11-26
---

# Phase 7 Plan 10: Headless flow API, browser mode Summary

**SPAs can now drive login, registration, recovery and verification through `/api/flows/v1` in browser mode. The handlers are a second renderer over `ui::flow_driver`: the flow cookie plus an `X-CSRF-Token` header bind each flow, the router has its own exact-origin allow-list and JSON-only layer, credentialed CORS is sent to listed origins only, and the API is described in a utoipa OpenAPI document (`flows-v1.json`) that a drift test guards.**

## Routes (tenant-relative)

| Route | Handler |
|---|---|
| `POST /api/flows/v1/{kind}` | `browser::start_flow` (body `{request?, token?}`) |
| `GET /api/flows/v1/{kind}/{flow_id}` | `browser::get_flow` |
| `POST /api/flows/v1/{kind}/{flow_id}` | `browser::submit_flow` (body `{method?, values, captcha?}`) |
| `POST /api/flows/v1/login/{flow_id}/passkey/options` | `browser::passkey_options` |
| `POST /api/flows/v1/login/{flow_id}/passkey` | `browser::passkey_assertion` (`Throttle::Passkey`) |
| `POST /api/flows/v1/login/{flow_id}/enroll/passkey/{start,finish}` | `enrolment_passkey_start/finish` |
| `POST /api/flows/v1/login/{flow_id}/second-factor/passkey/{start,finish}` | `second_factor_passkey_start/finish` |
| `/api/flows/v1`, `/api/flows/v1/{kind}/{flow_id}/{*rest}` | JSON 404 problem |

Submission methods and their driver call: `password` (`Throttle::Password` with the CAPTCHA answer), `identify` (`flow_driver::identify`), `totp` / `recovery_code` (`Throttle::SecondFactor`, user from `factor_token`), `email_code_request` (`Throttle::EmailCodeSend`), `email_code` (`Throttle::EmailCode`), `upstream` (`browser_required`), `register` / `recovery_request` / `recovery_reset` / `verify` (`Throttle::None`; a reset wakes the logout worker like the page).

Grep proof: `grep -rn 'guard_attempt\|record_attempt\|FlowService' crates/anvil-web/src/api_flows` prints nothing.

## DTO (api_flows::dto)

`FlowResponse {flow: FlowRef{id, kind, expires_at?}, step, csrf_token?, form?: FormDto{id, fields, messages, methods, totp?, captcha?}, message?, result?: ResultDto{continue_to?, recovery_codes}, url?, retry_after?}`. `FieldDto {name, kind (text|email|password|hidden|unknown), label_key, label?, required, autocomplete?, value?, messages}`. `MethodDto` is tagged by `kind`: password, passkey, email_code, magic_link, upstream{slug,name}, sso. Problems use `FlowProblem {type: urn:anvilid:problem:flows:<code>, title, status, code, retry_after?, captcha?}`. The mapping is `form_dto(form, methods, localized, FormExtras)`. Password values are never copied. `label`/`text` are filled only with `?ui_locales=`, through `i18n::localize_form`.

## Layers

- `layers::csrf::headless_origin_layer()` / `headless_verdict()`: `Origin` must equal the tenant's own origin (`AllowedOrigins`) or an exact entry of `headless.allowed_origins`. Without `Origin`, only `Sec-Fetch-Site: same-origin|none` passes (no browser headers at all also passes). A `POST` must be `application/json`, else 415. Refusals are JSON problems.
- `layers::cors::headless_cors()`: `AllowOrigin::predicate` over the resolved tenant's list, `allow_credentials(true)`, GET/POST, `content-type` and `x-csrf-token`, exposes `Retry-After`, max-age 600. `public_cors()` and `fetch_metadata_layer()` are unchanged.

## Tests

- Unit: `layers::csrf::headless_tests` (7), `layers::cors::tests::headless` (3), `api_flows::dto::tests` (8), `api_flows::browser::tests` (4). The 10 existing `ui::flow_driver` tests still pass.
- `headless_flows` (10): `login_with_password_completes_and_continue_to_issues_a_code`, `wrong_password_answers_the_form_with_the_error_and_400`, `get_returns_the_current_step`, `login_lists_email_code_and_magic_link_when_enabled`, `email_code_request_answers_the_email_step_with_its_token`, `registration_open_signs_in_and_closed_is_refused`, `recovery_request_and_verification_start`, `ui_locales_de_fills_labels_and_texts`, `upstream_method_answers_browser_required_with_the_sign_in_page`, `an_unknown_kind_and_unknown_paths_are_json_404`.
- `security_headless` (11): `headless_foreign_origin_refused`, `headless_missing_csrf_header_refused`, `headless_wrong_csrf_header_refused`, `headless_form_encoded_body_refused_415`, `headless_no_wildcard_cors_with_credentials`, `headless_preflight_only_for_allowed_origin`, `headless_ui_router_still_refuses_cross_site`, `headless_throttling_shared_with_ui` (both directions), `headless_captcha_required_in_browser_mode`, `headless_dto_never_contains_internal_fields`, plus `headless_api_not_behind_ui_fetch_metadata` (moved here from skeleton_v10).
- `openapi_flows_drift` (2): `committed_flows_spec_matches_generated`, `flows_spec_is_openapi_3_1_v1_with_every_route`.

## Mutation checks (recorded, reverted)

1. `headless_verdict` with the origin refusal removed (admits any `Origin`): `headless_foreign_origin_refused` FAILED (an unlisted origin got 200 with a flow).
2. `browser.rs` password submission passing `Throttle::None` instead of `Throttle::Password` (driver gate bypassed): `headless_throttling_shared_with_ui` FAILED (the sixth API attempt was 400, not 429).

## Evidence

- `cargo test -p anvil-web --locked --no-fail-fast`: 120 test binaries, all ok, including `openapi_drift` (admin) and `skeleton_v10`. Postgres-backed cases skip without a database.
- `cargo clippy -p anvil-web --all-targets --locked -- -D warnings`: clean.
- `scripts/check-release-graph.sh`: OK.
- `just openapi-update` was not run in the shared tree (it rewrites admin-v1.json too). Both drift tests pass, so it would write identical files.
- E2E: `tests/e2e/specs/headless.spec.ts` **ran locally and passed (2/2, chromium)** against a debug `anvilid` started from a scratch data dir (`--public-url http://localhost:18197 --breach-check off`, auth rate budget raised as in run.sh), with SETUP_URL from its log. No Mailpit was needed because the spec sends no email. The scratch instance, its data dir and `e2e-results/` were removed afterwards. `run.sh` (release build plus console) was not used, to save disk in the shared tree. CI e2e on SQLite and Postgres is authoritative. The nojs project never matches this spec, and `beforeEach` also skips it there.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.

## E2E allow-list route (checked at execution time)

07-12 has not shipped: the admin tenant settings keep `headless` unchanged and do not expose it. The spec creates a dedicated tenant through `POST /api/admin/v1/tenants/{slug}/config/apply`. The config document's `tenant.settings` is the full `TenantSettings`, so `headless.allowed_origins` passes through, and the tenant is deleted in `afterAll`. Once 07-12 validates the field, `http://localhost:<port>` is still accepted in development mode.

## Task Commits

1. Task 1 (layers, DTO, OpenAPI base, driver helpers) + the handlers: `4949644` feat(07-10)
2. Task 2 (integration/security tests, flows-v1.json, drift test, justfile): `870e990` test(07-10)
3. Task 3 (SPA fixture, e2e spec, HEADLESS.md): `41d4add` test(07-10)

## Deviations from Plan

1. **[Rule 3 - Blocking] Forced extra files: `ui/mod.rs`, `ui/mfa.rs`, `ui/email_code.rs` (visibility only).** `flow_driver` was a private module, so `api_flows` could not call it. It is now `pub(crate) mod flow_driver`. `mfa::open_factor_token` and `email_code::{seal_email_token, open_email_token, send_ident}` are now `pub(super)`, so `flow_driver` can wrap them. No logic changed in these files, and neither 07-08 nor 07-09 owns them. `login_methods` became `pub(super)` (`UpstreamButton` stays `pub(super)`). The API calls `flow_driver::offered_methods`, which lists the upstream buttons itself.
2. **[Rule 3] Handlers committed with Task 1.** `api_flows/mod.rs` and `browser.rs` must declare and use the new modules for the crate to compile, so the Task 1 commit holds all the production code and Task 2 holds the tests and generated files. `skeleton_v10.rs` (a Task 2 file) went into the first commit to keep each commit green, because its flows cases broke as soon as the routes existed.
3. **[Rule 1] Catch-all placement.** matchit refuses `/api/flows/v1/{*rest}` next to `/api/flows/v1/{kind}/{flow_id}`, so the JSON 404 catch-all from 07-04 moved one level down (`/{kind}/{flow_id}/{*rest}`). An unknown kind answers 404 from the handler. A `GET` on `/api/flows/v1/{unknown}` is a 405 with an empty body, not a JSON 404.
4. **GET current step without a core method.** `FlowService` has no read-only "current step". `flow_driver::current_step` loads the flow through the storage port, checks the binding with core `check_binding`, and renders with core `engine::current_form` plus `bind_form`. It does not run a second state machine.
5. **Status codes.** Forms answer 200 or 400, the same as the pages. 422 is not used.
6. **`api_flows_not_behind_ui_fetch_metadata` moved** from skeleton_v10 to security_headless as `headless_api_not_behind_ui_fetch_metadata`. A cross-site request without `Origin` is now refused (JSON 403) by the headless layer, so the test checks that an allow-listed cross-site caller gets 200.
7. **Not done:** prefilling `login_hint` on API start (the pages do it through the private `login::login_hint`) and a second-factor happy path through the API. The second factor is wired through the same driver call and token as `ui::mfa` but has no API integration test.

## Self-Check: PASSED

- FOUND: crates/anvil-web/src/api_flows/browser.rs (1150+ lines, min 150), contains `flow_driver::`
- FOUND: docs/openapi/flows-v1.json (contains `/api/flows/v1`)
- FOUND: crates/anvil-web/tests/security_headless.rs (contains `headless_foreign_origin_refused`)
- FOUND: crates/anvil-web/src/api_flows/mod.rs (contains `headless_`)
- FOUND: commits 4949644, 870e990, 41d4add
