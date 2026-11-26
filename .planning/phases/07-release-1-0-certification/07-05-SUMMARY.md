---
phase: 07-release-1-0-certification
plan: 05
subsystem: web-ui
tags: [refactor, flow-driver, rate-limit, captcha, headless-prep, UI-05]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: ui/login.rs orchestration (password, identifier-first, passkey, CAPTCHA), ui/mfa.rs, ui/email_code.rs
provides:
  - crates/anvil-web/src/ui/flow_driver.rs, the one web-side orchestration of a flow step (binding, gate, CAPTCHA, submit, record, lock, sign-in methods)
  - typed DriveOutcome / DriveRejection with no HTML, for 07-10 (headless browser mode) and 07-18 (native token binding)
  - login_methods(form, tenant, upstream) -> Vec<LoginMethod>, which ui/login.rs renders its choices from
affects: [07-10 headless browser mode, 07-18 headless native mode, 07-23 gate]

tech-stack:
  added: []
  patterns:
    - "HTML handlers do: extract -> flow_driver::{start,submit,identify,...} -> encode DriveOutcome (templates, cookies, CSP, no-store)"
    - "Brute-force classes as data: Throttle -> gate() (limiter keys + deny answer) -> count() (keys/success/regate per AuthAttempt), both pure and unit-tested"

key-files:
  created:
    - crates/anvil-web/src/ui/flow_driver.rs
  modified:
    - crates/anvil-web/src/ui/mod.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/ui/mfa.rs
    - crates/anvil-web/src/ui/email_code.rs

key-decisions:
  - "DriveOutcome::Flow carries the core FlowOutcome (typed, HTML-free) instead of re-modelling Completed/Message/Redirect variants: no second outcome mapping to keep in sync"
  - "FlowBinding is an enum with a single Cookie { jar, csrf } variant, so 07-18 adds Token without touching call sites"
  - "registration/recovery/verification still call login::start_page/submit_page, which are now thin HTML encoders over flow_driver::start/submit (Throttle::None); those three files needed no edit"
  - "setup.rs (system first-admin bootstrap) keeps its own FlowService::submit call: not a tenant flow, not in this plan's files, not reused by the headless API"

requirements-completed: []

duration: ~70min
completed: 2026-11-26
---

# Phase 7 Plan 05: Shared flow_driver Summary

**`ui::flow_driver` now handles the binding, brute-force gate, CAPTCHA, submission, attempt recording, lock decision and sign-in method list for every UI flow step. It returns `DriveOutcome` and no HTML. The login, MFA and email-code handlers only encode that result, so the headless API (07-10/07-18) can call the same code. Behaviour is unchanged: the anvil-web integration tests pass without edits.**

## Final flow_driver API (for 07-10 / 07-18)

All items are `pub(crate)` in `crates/anvil-web/src/ui/flow_driver.rs`:

```rust
enum FlowBinding<'a> { Cookie { jar: &'a CookieJar, csrf: &'a str } }    // 07-18 adds Token
  fn csrf(&self) -> &str
  fn flow_token(&self, state, tenant) -> Option<String>
  async fn current_session(&self, state, tenant) -> Result<Option<BrowserSession>, CoreError>

enum DriveRejection { Binding /* CoreError::Forbidden */, Failed(CoreError) }
enum DriveOutcome {
    Flow { outcome: FlowOutcome, attempt: Option<AuthAttempt>, captcha: bool },
    Locked { form: FormDescription, retry_after: Duration, attempt: Option<AuthAttempt> },
    Throttled { retry_after: Duration },
    CaptchaRejected { form: FormDescription },        // message CAPTCHA_REQUIRED / CAPTCHA_FAILED
    Rejected(DriveRejection),
}
struct CaptchaAnswer<'a> { turnstile: Option<&'a str>, hcaptcha: Option<&'a str> }
enum Throttle<'a> {
    None, Password { identifier, ip, captcha: CaptchaAnswer }, Passkey { ip },
    SecondFactor { user }, EmailCodeSend { ident: Option<[u8; 32]>, ip }, EmailCode { subject },
}

async fn start(state, tenant, kind, request, token) -> Result<StartedFlow, CoreError>
async fn start_login(state, tenant, request, current, return_target) -> Result<LoginStart, CoreError>
async fn submit(state, tenant, ctx, flow, binding: FlowBinding, throttle: Throttle, input: FlowInput) -> DriveOutcome
async fn identify(state, tenant, ctx, flow, &binding, IdentifyInput, ip) -> Result<Identified, DriveRejection>
    enum Identified { Done { outcome: Box<FlowOutcome>, captcha: bool }, StartIdp(IdpStart) }
async fn passkey_options(state, tenant, flow, &binding, PasskeyStep{SignIn,Enrolment,SecondFactor}) -> Result<String, DriveRejection>
async fn passkey_finish(state, tenant, ctx, flow, &binding, InFlowPasskey{Enrolment,SecondFactor}, response) -> Result<SubmitResult, DriveRejection>
async fn email_link(state, tenant, ctx, flow, &binding, link_token) -> Result<EmailLinkOutcome, DriveRejection>
fn login_methods(form: &FormDescription, tenant: &ResolvedTenant, upstream: &[UpstreamButton]) -> Vec<LoginMethod>
    enum LoginMethod { Password, Passkey, EmailCode, MagicLink, Upstream { slug, name }, Sso }
const CAPTCHA_REQUIRED, CAPTCHA_FAILED
```

Note for 07-10: `UpstreamButton` is `pub(super)` in `ui::upstream`. A JSON handler outside `ui` needs it made `pub(crate)`, or it can call `login_methods` through a `ui` re-export.

## Moved functions

| From | To |
|---|---|
| `login::verify_captcha` | `flow_driver::verify_captcha` (private; takes `CaptchaAnswer`, not `UiForm`) + `captcha_failure_reason` |
| `login::password_step_captcha` | `flow_driver::password_step_captcha` (private, used by `identify`) |
| `login::posted_login_form` + `Posted` | `flow_driver::posted_login_form` (private; used for pre-flow locks and CAPTCHA demands) |
| `login::submit_flow`, `login::current_session` | `flow_driver::run_submission` + `FlowBinding::{flow_token,current_session}` |
| `login::FlowPasskey` | `flow_driver::{PasskeyStep, InFlowPasskey}` (`login::passkey_failed_key` stays for the JSON error key) |
| guard/record sequences in `login::submit`, `login::passkey_submit`, `mfa::submit`, `email_code::{request,verify}` | `flow_driver::submit` with `Throttle::{Password,Passkey,SecondFactor,EmailCodeSend,EmailCode}` |
| `FlowService::{start,start_login,identify,passkey_*,email_link}` calls in login/email_code | the matching `flow_driver` functions |

New HTML-side helpers in login.rs: `sign_in_gate_page` (password and passkey gate pages, with upstream buttons), `drive_response` (generic encoder for registration, recovery, verification, the second factor and email codes), and `rejection_page` (Binding → csrf page 403, Failed → error page). `render_tenant_form_with` builds the passkey, email-code and upstream choices from `login_methods`.

## Task Commits

1. **Task 1 + Task 2 (one commit):** `d147f2f` refactor(07-05): extract the shared ui::flow_driver and run the UI flow handlers through it

## Evidence

- `cargo test -p anvil-web --lib ui::flow_driver`: 10 passed. Covers login_methods for a password-only tenant, an issuer that cannot be a WebAuthn relying party, email code + magic link on a bound form only, upstream buttons, and a routed-domain tenant (email-first page, then SSO choice). Also the gate keys per class, attempt counting per class (including counting second-factor attempts for the user the flow reports), the lock mapping and the CAPTCHA answer per provider.
- `cargo test -p anvil-web --test flow_login --test flow_login_factors --test security_bruteforce --test captcha --test security_enumeration --test hrd_login --test flow_passkey --test flow_mfa`: all green (9/9/8/13/3/21/4/7). No test was edited.
- `cargo test -p anvil-web --locked --no-fail-fast`: 116 test binaries ok. One failure, `admin_config::json_schema_matches_the_document_types` ("settings.headless missing in the schema"), is not from this plan: 07-01 has an uncommitted `TenantSettings.headless` in the shared tree. Postgres-backed tests skip without a database.
- `cargo clippy -p anvil-web --all-targets --locked -- -D warnings`: clean.
- `scripts/check-release-graph.sh`: OK.
- Grep proofs: `grep -rln 'guard_attempt\|record_attempt\|verify_captcha' crates/anvil-web/src/ui | grep -v flow_driver.rs` prints nothing. `grep -rn '\.submit(' crates/anvil-web/src/ui` lists only flow_driver.rs and setup.rs:240 (system setup, see decisions).
- **E2E not run locally.** run.sh needs a release build of anvilid plus the console (disk cost) in a tree where other wave-1 plans have uncommitted work. Following the shared executor rules, the Playwright specs (login, nojs, mfa-policy, passkey, totp, email-code, nojs-email-code, registration, recovery, hrd, nojs-hrd) on SQLite and Postgres are left to CI, which is authoritative at the 07-23 gate.

## Deviations from Plan

1. **Tasks 1 and 2 share one commit.** Moving `submit_flow` and the guard/record sequences out of login.rs breaks the build until mfa.rs and email_code.rs use the driver, so a Task-1-only commit would not compile.
2. **registration.rs, recovery.rs and verification.rs are unchanged.** They already went through `start_page`/`submit_page`, and those helpers now just encode the driver's result, so editing these files would only have added duplication. Recovery still wakes the logout worker on every reset POST, as before.
3. **Outcome shape differs from the plan's sketch.** `Completed`/`Message`/`Redirect` are covered by the core `FlowOutcome` inside `DriveOutcome::Flow`. `Throttled` (a plain 429, for second factor and email code) is separate from `Locked` (a form shown again), because existing behaviour tells them apart.
4. **setup.rs still calls `FlowService::submit`.** It is not in files_modified and it is the system bootstrap flow, not a tenant UI flow, so the grep proof lists it as the only exception.

## Self-Check: PASSED

- FOUND: crates/anvil-web/src/ui/flow_driver.rs (1330 lines, min 200)
- FOUND: commit d147f2f
