---
phase: 06-release-1-0-orgs-and-sso
plan: 06
subsystem: auth
tags: [passkey, webauthn, second-factor, allowCredentials, carry-over, auth-08]

requires:
  - phase: 05-30
    provides: "FlowService::passkey_second_factor_options/finish, second-factor passkey tests"
  - phase: 05-11
    provides: "tests/passkey_support (SoftAuthenticator)"
provides:
  - "Second-factor passkey request options carry publicKey.allowCredentials = the step user's credential ids"
  - "service::flow::with_allow_credentials (private helper)"
  - "SoftAuthenticator::credential_id_b64 (test support)"
affects: []

tech-stack:
  added: []
  patterns:
    - "Request options from the ceremony port are post-processed as JSON in core (publicKey.allowCredentials) instead of adding a port method; the stored ceremony state is unchanged"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-web/tests/flow_mfa_policy.rs
    - crates/anvil-web/tests/passkey_support/mod.rs

key-decisions:
  - "allowCredentials is injected into the options JSON in core from PasskeyCredential.credential_id (base64url), with no port change; the ceremony state stays discoverable, so the finish path and its ownership checks are untouched (one verification path)"
  - "Options that are not an object with a publicKey object give CoreError::Internal (no silent pass-through of un-narrowed options)"

requirements-completed: []

duration: about 30min (including about 10min waiting for a peer's in-progress ports.rs build break)
completed: 2026-11-26
---

# Phase 6 Plan 06: Second-factor Passkey Picker Narrowing Summary

**At the second-factor step, `POST /ui/login/second-factor/passkey/start` now returns options whose `publicKey.allowCredentials` lists exactly the step user's passkeys (`{"type":"public-key","id":<base64url>}`), so the browser picker offers only that user's passkeys. The identify-step (usernameless) options stay discoverable with an empty list. The 05-30 server-side refusals are unchanged.**

Traceability: refines AUTH-08 and closes the 05-30 deferred item "the discoverable second-factor challenge carries no allowCredentials". No requirement checkbox was ticked (wave rule).

## Tests (gate map)

`crates/anvil-web/tests/flow_mfa_policy.rs`:
- `second_factor_passkey_options_list_only_the_step_users_credentials` (new, positive): Alice has two passkeys and Bob has one. Alice's second-factor options list exactly Alice's two ids and not Bob's, and the narrowed options still complete a sign-in with Alice's second passkey.
- `identify_step_passkey_options_stay_discoverable` (new): the `/ui/login` passkey options have no or an empty `allowCredentials`.
- `second_factor_passkey_of_another_user_is_refused` (05-30, unchanged) and every other 05-30 negative test still pass: unknown credential, replay, cross-flow, identify-step challenge, finish without a challenge, and options outside the step.

`crates/anvil-core/src/service/flow.rs` unit tests:
- `allow_credentials_list_exactly_the_given_passkeys`: replaces an existing list, uses base64url without padding (`-_` alphabet), leaves the other fields alone.
- `allow_credentials_refuse_malformed_options`: non-JSON, a non-object, or a missing or non-object `publicKey` gives `Internal`.

RED was confirmed before the change. The first test failed with `"allowCredentials":[]` from webauthn-rs.

## Task Commits

1. **RED:** `1129186` test(06-06): add failing test for second-factor allowCredentials
2. **GREEN:** `14ce42e` feat(06-06): narrow the second-factor passkey picker with allowCredentials

## Verification (main tree, SQLite)

- `cargo test -p anvil-web --test flow_mfa_policy`: 33 passed (2 new, 31 existing).
- `cargo test -p anvil-web --test flow_passkey`: 4 passed.
- `cargo test -p anvil-core --lib service::flow`: 18 passed (2 new).
- `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean. `rustfmt --edition 2024` was run on the three touched files only.
- `scripts/check-release-graph.sh`: OK.
- **e2e locally without Docker:** the debug `anvilid` ran from a scratch copy with the run.sh flags (fresh data dir, port 18096). `specs/mfa-policy.spec.ts` passed 4/4, including the passkey second-factor sign-in with the virtual authenticator, which now gets the narrowed options. The scratch dir and `e2e-results/` were deleted afterwards.

## Not run

- `ANVILID_TEST_DB=postgres` for `flow_mfa_policy` (no Docker). No SQL was added: only the existing `users().passkeys(..)` is used, which already ran in this function.
- `tests/e2e/run.sh sqlite|postgres` itself (CI).

## Deviations from Plan

None in behaviour. Notes:
- `passkey_support/mod.rs` gained the small accessor `credential_id_b64()`, so tests compare ids without parsing assertions. This file is listed in files_modified.
- The plan's stop condition did not apply: `PasskeyCredential.credential_id` exposes the raw id, so no webauthn-rs internals are parsed in core and there is no port change.
- During GREEN, the build was broken for about 10 minutes by 06-04's in-progress `ports.rs` (OrgRepo). I waited and retried as the wave rules say, and edited no peer file.

## Deferred Issues

None.

## Self-Check: PASSED
- crates/anvil-web/tests/flow_mfa_policy.rs contains `second_factor_passkey_options_list_only_the_step_users_credentials`
- crates/anvil-core/src/service/flow.rs contains `allowCredentials` in `with_allow_credentials`, called from `passkey_second_factor_options`
- Commits 1129186 and 14ce42e are in history
