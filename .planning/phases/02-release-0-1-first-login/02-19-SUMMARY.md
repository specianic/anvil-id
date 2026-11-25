---
phase: 02-release-0-1-first-login
plan: 19
subsystem: conformance
tags: [openid-conformance, basic-op, config-op, tls, rustls, pkce, nonce, ci]
requires:
  - phase: 02-18
    provides: release 0.1 binary with --tls-cert/--tls-key, zero-config start, /setup
  - phase: 02-16
    provides: admin API (clients, users) used by the setup script
provides:
  - "tests/conformance/run.sh: fresh anvilid over TLS (openssl cert in a temp dir) on port 9443, then Basic OP + Config OP"
  - "tests/conformance/setup.sh: /setup bootstrap -> management token -> three confidential require_pkce=false clients + full-claims user -> suite config in a temp file"
  - "tests/conformance/config.template.json: browser automation (#identifier/#password/#login-submit) and per-module overrides"
  - "expected-failures.json [] and a reviewed one-entry expected-skips.json; M0 http ratchet retired"
  - "C1 amended: opted-out confidential clients may omit nonce"
affects: [conformance CI workflow, OIDC-01 wording, Phase 3 FAPI/PAR work that builds on the PKCE rules]
tech-stack:
  added: []
  patterns:
    - "Conformance secrets, cert/key and config live only in the gitignored results tmp dir and are deleted on exit"
    - "After the PKCE step, 'no challenge' implies a confidential client with require_pkce=false (debug_assert documents the invariant)"
key-files:
  created:
    - tests/conformance/setup.sh
    - tests/conformance/config.template.json
    - tests/conformance/expected-skips.json
  modified:
    - tests/conformance/run.sh
    - tests/conformance/compose.override.yml
    - tests/conformance/expected-failures.json
    - tests/conformance/README.md
    - .github/workflows/conformance.yml
    - crates/anvil-core/src/oauth/authorize_request.rs
    - crates/anvil-web/tests/security_pkce.rs
    - docs/PRD.md
    - docs/ARCHITECTURE.md
    - .planning/REQUIREMENTS.md
    - .planning/phases/02-release-0-1-first-login/02-CONTEXT.md
  deleted:
    - tests/conformance/config-m0.json
    - tests/conformance/expected-failures-m0.json
key-decisions:
  - "C1 amended by the user (option A): a confidential client an admin set to require_pkce=false may omit nonce (OIDC Core 3.1.2.1; needed by oidcc-ensure-request-without-nonce-succeeds-for-code-flow). PKCE stays required by default, public clients can never opt out, plain is always rejected, the downgrade defense is unchanged"
  - "anvilid listens on 9443 in the harness because the suite's nginx owns 8443/8444"
  - "Only one expected skip (unsigned request object -> request_not_supported); the other planned skips are not scheduled for static_client at the pinned suite tag"
  - "oidcc-ensure-request-object-with-redirect-uri passes via a browser override"
requirements-completed: []
requirements-addressed: [OIDC-01, OIDC-02, OIDC-03, OIDC-05, OIDC-07, OIDC-08, OIDC-09, OIDC-24, SEC-01]
duration: 90min
completed: 2026-11-25
---

# Phase 2 Plan 19: OpenID conformance Basic OP + Config OP over TLS Summary

**The conformance harness starts a fresh anvilid over its own rustls listener with a certificate generated at run time, and provisions the suite through `/setup` and the admin API. On the final run, Basic OP passed 36 modules (1910 conditions, 0 failures, 0 warnings, 1 reviewed skip) and Config OP passed with 0 failures. `expected-failures.json` is now `[]`. To get there, the user amended C1 so that confidential clients set to `require_pkce = false` may omit `nonce`.**

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | TLS launch, setup script, config template | 29b808e |
| 2 | Reviewed skips, empty failures, request-object browser override, README, workflow | d826fd4 |
| 2 (after checkpoint) | C1 amendment: nonce optional for opted-out confidential clients, tests and docs | 2cfd0c2 |

## Decision checkpoint (C1 amendment)

Before the change, Basic OP passed 34/35. The one failure was `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`, because `authorize_request` step 9 rejected OpenID requests that carried neither PKCE nor `nonce`. OIDC Core makes `nonce` optional for the code flow, and the suite's static clients use `require_pkce = false`.

The user chose option A, which is now implemented:
- Step 9 no longer requires `nonce`. Step 6 still rejects a missing challenge for public clients and for clients with `require_pkce = true`. So a request without PKCE can only come from a confidential client with `require_pkce = false`, and its code stays bound to client authentication at the token endpoint. A `debug_assert!` documents this invariant.
- Unchanged: S256 only and `plain` rejected (also for opted-out clients, now tested), partial PKCE parameters rejected, and the downgrade defense at the token endpoint.
- Tests:
  - Unit tests: `opted_out_confidential_client_may_omit_pkce_and_nonce` and `require_pkce_client_without_pkce_is_rejected_even_with_nonce`. `public_client_always_needs_pkce` now also covers the case with no nonce.
  - HTTP tests: `opted_out_confidential_client_may_omit_pkce_and_nonce` and `pkce_required_client_without_pkce_is_rejected_even_with_nonce` replace `nonce_is_required_without_pkce`.
  - The fuzz target `fuzz/fuzz_targets/authorize_parse.rs` checks no nonce invariant. Its PKCE invariant (public or `require_pkce` ⇒ challenge present) still holds without changes.
- Docs updated: PRD OIDC-1, ARCHITECTURE §11 PKCE row, REQUIREMENTS OIDC-01 wording, and a C1 amendment note in 02-CONTEXT.

## Verification

- `cargo test --workspace --locked`: all pass. In the first run, one test failed after 11.7 s, most likely the timed `zero_config` check, which ran while the machine was under build load. The rerun passed fully (see Deferred Issues).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean. `cargo fmt --check`: clean.
- `just conformance` (four runs, Docker Desktop on WSL2):
  - In every run, `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` passed.
  - Runs 1–3 each had 1–2 modules interrupted by the suite's Java client reporting "Remote host terminated the handshake" on a different endpoint each time (discovery, `/token`, `/userinfo`, `/jwks`). With `anvilid::server=debug` logging, anvilid recorded no handshake failure or timeout. A 1000-request, 20-way concurrent TLS probe from a container through `host.docker.internal` had 0 failures.
  - Run 4: exit 0. Basic OP passed 36 modules (1910 conditions, 0 failures, 0 warnings) with one expected skip (`oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`). Config OP: 32 conditions, 0 failures.

## Deviations from Plan

These deviations were kept from before the checkpoint:
- **[Rule 3 - Blocking] Port 9443 instead of 8443.** The suite's nginx owns 8443/8444. Public URL: `https://host.docker.internal:9443`.
- **Skip list narrower than planned.** It has 1 entry. At the pinned suite tag the other request-object/request-uri modules and `oidcc-idtoken-unsigned` are not scheduled for static_client, and listing them would only add stale entries.
- **`oidcc-ensure-request-object-with-redirect-uri`** passes through a browser override instead of being skipped.

New after the checkpoint:
- **[User decision] C1 amended.** This is the decision described above, not an auto-fix.

## Deferred Issues

- **Intermittent TLS handshake aborts in local conformance runs (Docker Desktop on WSL2).** In 3 of 4 runs, 1–2 modules were interrupted by "Remote host terminated the handshake". anvilid logged nothing for those connections, and a concurrent container probe was clean. That suggests the drops happen in Docker Desktop's `host.docker.internal` forwarding rather than in anvilid, but this is not confirmed. Watch CI (native Docker on Linux). If it shows up there, consider a retry for interrupted modules in `run.sh` or running the suite with `network_mode: host`.
- **The timed `zero_config` test may be sensitive to machine load.** One failure under concurrent build load, then it passed on rerun.

## Self-Check: PASSED
