---
phase: 06-release-1-0-orgs-and-sso
plan: 30
subsystem: hygiene
tags: [gap-closure, mfa-policy, contract-suite, dependencies, aws-lc, check-deps, ORG-02, ORG-03]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-01 aws-lc single crypto backend + check-deps.sh; 06-07/06-08 backends; 06-19 effective_policy_for"
provides:
  - "effective_policy_for(tenant, org, client) is the only MFA policy combinator"
  - "Contract-suite group headers without stale 'Unsupported until ...' / TRANSITIONAL notes"
  - "scripts/check-deps.sh check_single_aws_lc: exactly one aws-lc-rs and one aws-lc-sys version in Cargo.lock, with self-test case I"
affects: [06-26]

tech-stack:
  added: []
  patterns:
    - "Lockfile rules read Cargo.lock with awk (distinct versions per [[package]] name), not `cargo tree -d`"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/policy/mfa.rs
    - crates/anvil-core/src/oauth/decision.rs
    - crates/anvil-storage/src/contract/mod.rs
    - crates/anvil-storage/src/contract/clients.rs
    - crates/anvil-storage/src/contract/connections.rs
    - crates/anvil-storage/src/contract/roles.rs
    - crates/anvil-storage/src/contract/branding.rs
    - crates/anvil-storage/src/contract/mail_settings.rs
    - crates/anvil-storage/src/contract/grants.rs
    - scripts/check-deps.sh

key-decisions:
  - "check_single_aws_lc runs first in check(): a lock that no longer matches the manifests makes the later `cargo tree --locked` calls exit under set -e, and the RULE VIOLATION line must already be printed"
  - "Zero locked aws-lc versions is a violation too (aws-lc is the one crypto backend)"
  - "Case I reuses `run_case --append` with $'...' quoting; no new run_case mode"

requirements-completed: []

duration: 10min
completed: 2026-11-26
---

# Phase 6 Plan 30: Hygiene gap closure (MFA combinator, contract comments, aws-lc lock rule) Summary

**`effective_policy` is removed, so `effective_policy_for` is now the only MFA policy combinator. The contract-suite headers no longer say "Unsupported until 06-07 / 06-08" or "TRANSITIONAL". `scripts/check-deps.sh` gains a Cargo.lock rule that requires exactly one aws-lc-rs and one aws-lc-sys version, and self-test case I proves it rejects a second version.**

## Tasks

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1 | Remove the forwarding effective_policy; fix stale contract comments | 933379b |
| 2 | Cargo.lock-based single aws-lc version rule in check-deps.sh | ed394f6 |

## What changed

- `policy/mfa.rs`: `effective_policy` is deleted. The strictest-wins table and the never-weaker tests now call `effective_policy_for(t, None, c)`. The old equality test (`effective_policy == effective_policy_for(.., None, ..)`) is now `effective_policy_without_org_adds_nothing`: `effective_policy_for(t, None, c) == c.map_or(t, |c| t.max(c))`.
- `oauth/decision.rs`: the `MfaContext::policy` doc links to `effective_policy_for` and mentions the active organization.
- Contract suite: the Phase 4/5/6 headers in `mod.rs` keep their plan provenance and now list what each group covers. The per-file Phase 6 headers in clients, connections, roles, branding, mail_settings and grants lose the "the backends refuse ... until 06-07 / 06-08" clause. Only comments changed. `org_domains.rs` was not touched (06-28 owns it).
- `check-deps.sh`: the header documents the new rule. `check_single_aws_lc()` uses awk over `[[package]]` blocks, then `sort -uV`, and reports `RULE VIOLATION: Cargo.lock has N versions of <crate> (<versions>)` when N != 1. It is called first in `check()`. Case I appends a `[[package]] name = "aws-lc-sys" version = "0.99.0"` block to the copy's Cargo.lock.

## Verification

- `cargo test -p anvil-core --lib policy::mfa`: 9 passed. `cargo test -p anvil-core --lib`: 998 passed.
- `cargo test -p anvil-storage-sqlite --test contract`: 470 passed. Postgres is left for CI.
- `cargo clippy -p anvil-core -p anvil-storage --all-targets -- -D warnings`: clean. Cargo prints a manifest-level `unused dependency anvil-core` warning for anvil-storage. That is a cargo lint, not clippy, and it predates this plan.
- `rustfmt --edition 2024 --check` on the touched files: clean.
- `! grep -rn "fn effective_policy(" crates`: no hits. `! grep -rn "until 06-07\|TRANSITIONAL" crates/anvil-storage/src/contract`: no hits.
- `scripts/check-deps.sh`: `dependency rules OK`, exit 0.
- `scripts/check-deps.sh --self-test`: cases 0 and A-I all PASS, including `PASS I: Cargo.lock gains a second aws-lc-sys version (checker: fail, expected: fail)`, then `dependency checker self-test OK`.
- Parser unit check (run in a scratch copy of the lock): one version listed in two `[[package]]` entries passes. Adding a second aws-lc-sys version prints `RULE VIOLATION: Cargo.lock has 2 versions of aws-lc-sys (0.47.0 0.99.0)`. Removing aws-lc prints `0 versions ... (none)` for both crates.
- `just deps` / `just deps-selftest` run exactly these two script invocations (justfile lines 31-36), and `deps` is part of `just ci`.
- `scripts/check-release-graph.sh`: OK.
- `shellcheck` is not installed here, so it was not run.

## Deviations from Plan

None in the plan's own files.

## Left for the gate (06-26)

- **TRANSITIONAL hits outside this plan's files:** 16 files under `admin-ui/src/routes/` (the pre-tenant-routing pages: users, email, audit, connections, clients, sessions, branding, settings) still carry `// default tenant for this release. TRANSITIONAL: remove in 0.5.` No hits remain in `crates/`, `scripts/` or `docs/`. These files are not owned by this plan, so I left them alone.
- **`RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" cargo doc -p anvil-core` fails** because of two links that predate this plan, both in `crates/anvil-core/src/service/client_resolver.rs` (lines 18 and 34, `oauth::cimd::check_url` / `oauth::cimd::validate`, missing `crate::`; from 05-15). mfa.rs and decision.rs produce no rustdoc warnings. client_resolver.rs is not in this plan's files.

## Self-Check: PASSED
