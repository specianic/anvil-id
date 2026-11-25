---
phase: 04-release-0-3-real-world-logins
plan: 08
subsystem: core
tags: [oidc, rp-initiated-logout, backchannel-logout, rfc8707, resource-indicators, mfa-policy, acr, tdd, proptest]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01: Client logout/resource/MFA fields, MfaPolicy (Ord), DeliveryResult, LOGOUT_DELIVERY_TTL, CoreError::{InvalidTarget, UnmetAuthenticationRequirements}, ACR_PWD/ACR_MFA/AMR_MFA"
provides:
  - "oauth::logout: HintCheck, EndSessionRequest, CurrentSession, PostLogoutRedirect, LogoutError, EndSessionDecision, validate_end_session, build_post_logout_redirect, logout_token_claims, DeliveryOutcome, classify_delivery, next_attempt"
  - "oauth::resource: parse_resources, validate_resources, downscope, Audience (untagged serde), audience, userinfo_audience_ok"
  - "policy::mfa: effective_policy, AcrRequest, acr_request, MfaRequirement, mfa_requirement, acr_for"
affects: [04-12, 04-13, 04-16, 04-17]

tech-stack:
  added: []
  patterns:
    - "Security decisions are pure functions with explicit decision tables and proptests; services only orchestrate"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/oauth/logout.rs
    - crates/anvil-core/src/oauth/resource.rs
    - crates/anvil-core/src/policy/mfa.rs

key-decisions:
  - "Added LogoutError::UnknownClient: a client_id that names no client (without a hint) is an error page, not silently ignored"
  - "With a valid hint, client_id must equal the hint's client and be in aud (stricter than 'in aud'); client_by_id is only used without a hint"
  - "Valid hint for another user/session -> Confirm with no redirect (the other user's browser is not sent to the RP)"
  - "Any status other than 200/204 and 5xx gives up (including 201/202/3xx); Blocked gives up; retry delay 10 s * 2^min(n,9) capped at 1 h"
  - "Resource values are returned verbatim (never normalised); whitespace/control characters rejected because Url::parse strips them silently"
  - "An essential acr claim that does not name ACR_MFA is AcrRequest::None"

patterns-established:
  - "Pure decision module + caller-verified inputs (HintCheck) so signature verification stays in the service"

requirements-completed: []

duration: 25min
completed: 2026-11-25
---

# Phase 4 Plan 08: Pure Logout, Resource-Indicator and MFA-Policy Decisions Summary

**The RP-initiated logout decision table, the Back-Channel logout token claim set and delivery retry classification, RFC 8707 parse/validate/downscope/audience, and the strictest-wins MFA policy and step-up table. All are pure functions in anvil-core, with 60 table tests and proptests.**

Note: `requirements-completed` is empty. OIDC-12, OIDC-16 and AUTH-08 are delivered end to end by 04-12, 04-13, 04-16 and 04-17. No checkbox was ticked.

## Performance

- **Duration:** about 25 min
- **Completed:** 2026-11-25
- **Tasks:** 1 TDD feature (RED + GREEN)
- **Files modified:** 3

## Signatures

### oauth::logout (RP-Initiated Logout 1.0 §2-4, Back-Channel Logout 1.0 §2.4, §2.8)
```rust
pub enum HintCheck { Absent, Invalid, Valid { sub: String, sid: Option<String>, aud: Vec<String> } }
pub struct EndSessionRequest { id_token_hint: HintCheck, client_id, post_logout_redirect_uri, state, ui_locales: Option<String> }
pub struct CurrentSession { user_id: String, session_id: String }
pub struct PostLogoutRedirect { uri: String, state: Option<String> }   // .to_url()
pub enum LogoutError { InvalidIdTokenHint, RedirectUriNotRegistered, IdTokenHintRequired, ClientMismatch, UnknownClient } // .key() -> "logout.*"
pub enum EndSessionDecision { LogoutNow { redirect }, Confirm { client_id, redirect }, Error(LogoutError) }
pub fn validate_end_session(req: &EndSessionRequest, hint_client: Option<&Client>, client_by_id: Option<&Client>, current_session: Option<&CurrentSession>) -> EndSessionDecision
pub fn build_post_logout_redirect(uri: &str, state: Option<&str>) -> String
pub fn logout_token_claims(issuer, client_id, sub, sid, jti: &str, now: OffsetDateTime) -> serde_json::Map<String, Value>
pub enum DeliveryOutcome { Status(u16), Network, Timeout, Blocked }
pub fn classify_delivery(outcome, attempts: u32, created_at, now: OffsetDateTime) -> DeliveryResult
pub fn next_attempt(attempts: u32, now: OffsetDateTime) -> OffsetDateTime
// consts: BACKCHANNEL_LOGOUT_EVENT, LOGOUT_TOKEN_TTL (2 min), DELIVERY_BASE_DELAY (10 s), DELIVERY_MAX_DELAY (1 h)
```

### oauth::resource (RFC 8707 §2, §2.2, §3)
```rust
pub const MAX_RESOURCE_LEN: usize = 2048;
pub fn parse_resources(values: &[String]) -> Result<Vec<String>, CoreError>      // InvalidTarget
pub fn validate_resources(requested: &[String], allowed: &[String]) -> Result<(), CoreError>
pub fn downscope(granted: &[String], requested: &[String]) -> Result<Vec<String>, CoreError>
#[serde(untagged)] pub enum Audience { One(String), Many(Vec<String>) }          // .values(), .contains()
pub fn audience(resources: &[String], client_id: &str) -> Audience
pub fn userinfo_audience_ok(aud: &[String], client_id: &str, issuer: &str) -> bool
```

### policy::mfa (Core §3.1.2.1, §5.5.1.1; Unmet Authentication Requirements 1.0)
```rust
pub fn effective_policy(tenant: MfaPolicy, client: Option<MfaPolicy>) -> MfaPolicy
pub enum AcrRequest { None, Voluntary, Essential }
pub fn acr_request(acr_values: &[String], claims_acr_essential: Option<&[String]>) -> AcrRequest
pub enum MfaRequirement { None, SecondFactor, Enroll, Unmet }
pub fn mfa_requirement(policy: MfaPolicy, acr: AcrRequest, session_is_mfa: bool, user_has_factor: bool) -> MfaRequirement
pub fn acr_for(amr: &[String]) -> &'static str
```

## Decision tables

### End session
| Input | Decision |
|---|---|
| hint `Invalid` | `Error(InvalidIdTokenHint)` |
| valid hint, `hint_client` is None or its client_id is not in `aud` | `Error(InvalidIdTokenHint)` |
| valid hint, `client_id` not in `aud` or not the hint's client | `Error(ClientMismatch)` |
| URI not exactly in the effective client's list (`?foo=bar`, trailing `/`, case, fragment all fail) | `Error(RedirectUriNotRegistered)` |
| valid hint, session matches `sub` (and `sid` if present), or no session | `LogoutNow { redirect iff URI }` |
| valid hint for another user or session | `Confirm { client_id: Some, redirect: None }` |
| no hint, unknown `client_id` | `Error(UnknownClient)` |
| no hint, known `client_id` (+ registered URI) | `Confirm { client_id, redirect iff URI }` |
| no hint, no `client_id`, URI | `Error(IdTokenHintRequired)` |
| no params / only `state` | `Confirm { None, None }` |

`state` is echoed only when sent. `build_post_logout_redirect` keeps the registered string verbatim (including its own query) and appends only `state=<form-encoded>` with `?` or `&`.

### Delivery
| Outcome | Result |
|---|---|
| 200, 204 | Delivered |
| 5xx, Network, Timeout, now < created_at + 24 h | Retry at now + min(10 s * 2^attempts, 1 h) |
| 5xx, Network, Timeout, now >= created_at + 24 h | GiveUp |
| any other status (400, other 4xx, 1xx, 201/202, 3xx), Blocked | GiveUp |

### MFA requirement (36-row exhaustive test)
| Session MFA | Policy | acr | Has factor | Result |
|---|---|---|---|---|
| yes | any | any | any | None |
| no | Off | None | any | None |
| no | any else | any | yes | SecondFactor |
| no | Required | any | no | Enroll |
| no | Off/Optional | Essential | no | Unmet |
| no | Off/Optional | None/Voluntary | no | None |

Effective policy is `max(tenant, client)` (Required > Optional > Off). The org slot is documented for Phase 6.

## Task Commits

1. **RED: failing tables and proptests**: `4451add` (test)
2. **GREEN: implementation**: `b64d1b5` (feat)

There was no separate REFACTOR commit. The GREEN commit already includes the spec-citing doc comments and the clippy fixes.

## Verification

- `cargo test -p anvil-core --lib -- oauth::logout oauth::resource policy::mfa`: 60 passed.
- In an isolated worktree (target/wt-04-08) with its own target dir, because other wave-2 plans' in-progress `upstream/` files break the shared build: `cargo clippy -p anvil-core --all-targets -- -D warnings` was clean, `cargo fmt --check` was clean, the full `cargo test -p anvil-core --lib` passed 399 tests, and `scripts/check-deps.sh` passed. The worktree and its target dir were removed afterwards.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] Added `LogoutError::UnknownClient`**
- **Found during:** GREEN
- **Issue:** The planned enum had no outcome for an unknown `client_id` without a hint. Silently ignoring it would show a confirmation page for a client that does not exist.
- **Fix:** Added an explicit error variant (message key `logout.unknown_client`). 04-13 needs a catalog entry for it.
- **Commit:** 4451add / b64d1b5

**2. [Signature] `current_session: Option<&CurrentSession>`** (a reference, not by value as the plan sketch had it) so callers do not clone.

None of the other files were touched.

## Next Phase Readiness
- 04-13 (logout) calls `validate_end_session` with a `HintCheck` built from `verify_op_token_algs(.., ExpiryCheck::Ignore)` and needs i18n keys for the five `LogoutError::key()` values.
- 04-17 (back-channel worker) uses `logout_token_claims` + `classify_delivery`.
- 04-12 uses the resource functions and `userinfo_audience_ok`.
- 04-16 uses `effective_policy`, `acr_request`, `mfa_requirement` and `acr_for`. `Unmet` maps to `CoreError::UnmetAuthenticationRequirements`.

## Self-Check: PASSED
