---
phase: 01-foundations-and-spikes
verified: 2026-11-25T01:35:00Z
status: passed
score: 5/5 must-haves verified
---

# Phase 1: Foundations and Spikes (M0) Verification Report

**Phase Goal:** The chosen stack is proven viable: the workspace builds and tests with one command, CI enforces the architecture rules, and the three risk spikes succeed (or the stack decision is revisited per ARCHITECTURE.md §2.1)
**Status:** passed
**Re-verification:** No, initial verification

## Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | One command builds, lints and tests; PR CI runs fmt, clippy, deny, tests | VERIFIED | `justfile` `ci: fmt-check lint deny deps test`. Ran locally: `cargo fmt --check` ok, clippy `-D warnings` clean, `cargo deny --locked check` ok (advisories, bans, licenses, sources), `cargo test --workspace --locked` all pass. ci.yml run 45525545513 (latest main) success. |
| 2 | CI fails a PR adding an I/O dep to core or a concrete storage import to web | VERIFIED | `scripts/check-deps.sh --self-test` passes. Case A (core gains tokio) fails, case B (web gains storage-sqlite) fails, case C (dev-dep allowed) passes, case D (reverse edge) fails. grep finds no sqlx references in anvil-core or anvil-web. |
| 3 | Shared contract suite (tenant repo + atomic `consume_code`, concurrency, one winner) passes on SQLite and Postgres, duplication cost recorded | VERIFIED | Tests run locally: sqlite contract 16 passed, postgres contract 8 passed (testcontainers). 32-way concurrency test is described in SPIKE-RESULTS as 1 Consumed and 31 AlreadyConsumed. Duplication cost table in `01-SPIKE-RESULTS.md`. |
| 4 | CI produces static musl amd64 + arm64 binaries (aws-lc-rs, mimalloc, embedded assets), reports size and idle RSS | VERIFIED | release-build run 45525545442 success on latest main, and 45524848917 success. SPIKE-RESULTS records the numbers: 9.44 MiB / about 21 MB RSS on amd64, 7.66 MiB / about 19 to 21 MB on arm64. |
| 5 | CI starts a fresh binary and runs OpenID conformance end to end | VERIFIED | conformance run 45524848884 success ("All tests ran to completion", exit 0, 8 expected failures ratcheted). Run 45525545915 on latest main also reports success; the job showed as completed and green when checked. |

**Score:** 5/5

## Required Artifacts

| Artifact | Status | Details |
|----------|--------|---------|
| `justfile`, `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml` | VERIFIED | Present, tracked, used by CI. |
| `.github/workflows/{ci,release-build,conformance}.yml` | VERIFIED | Present and green on main. |
| `scripts/check-deps.sh` | VERIFIED | Self-test passes. |
| `crates/anvil-storage-{sqlite,postgres}` with `.sqlx` and migrations | VERIFIED | Present, tests pass. |
| `crates/anvil-web` (router, discovery, assets, 501 stubs) | VERIFIED | router tests 10 passed. |
| `crates/anvilid` | VERIFIED | serve tests 4 passed. |
| `01-SPIKE-RESULTS.md` | VERIFIED | §2.1 verdicts for all conditions, "stack confirmed". |

## Key Links

| From | To | Status |
|------|----|--------|
| justfile `ci` | CI workflows | WIRED (same recipes) |
| contract suite (`anvil_storage::contract`) | both backends | WIRED (both `tests/contract.rs` run it) |
| anvilid | storage backends and web | WIRED (serve tests pass) |
| conformance.yml | tests/conformance/run.sh and expected-failures ratchet | WIRED (CI green) |

## Requirements Coverage

| Req | Source Plans | Status | Evidence |
|-----|--------------|--------|----------|
| FND-01 | 01-01, 01-02, 01-07(08) | SATISFIED | Truth 1 |
| FND-02 | 01-02, 01-08 | SATISFIED | Truth 2 |
| FND-03 | 01-03, 01-05, 01-08 | SATISFIED | Truth 3 |
| FND-04 | 01-07, 01-08 | SATISFIED | Truth 4 |
| FND-05 | 01-06, 01-07, 01-08 | SATISFIED | Truth 5 |

All five IDs appear in plan frontmatter and in REQUIREMENTS.md (marked Complete, mapped to Phase 1). No orphaned requirements.

## CLAUDE.md Compliance

- No stubs returning success: the unbuilt endpoints in `crates/anvil-web/src/not_implemented.rs` return an explicit 501. No `todo!`, `unimplemented!`, TODO or FIXME in `crates`.
- No test hooks or hardcoded users in production paths found. The `#[cfg(test)]` block in anvilid's `main.rs` is test-only.
- Storage only via traits: no sqlx dependency or usage in core or web, and the dependency checker enforces this.
- No secrets: no `.env`, `.pem` or `.key` files tracked.
- Security checks (PKCE, redirect URI, client auth) are not in M0 scope. The only one in scope is code single-use, which has a concurrency test.

## Anti-Patterns

None blocking.

## Notes (informational)

- Work went directly to `main` instead of through a PR. CI evidence is on main pushes, and the criterion "every PR runs ..." is met by the workflow triggers, not exercised by a PR yet.
- The first two conformance runs failed on a git sparse-checkout problem, fixed in plan 08. All current runs are green.
- aarch64 binary is statically linked, non-PIE (watch item recorded).
- Latest conformance run (45525545915) was still in progress at the first `gh run list`. By the time of `gh run view` it showed success.

## Human Verification Required

None.

---

_Verified: 2026-11-25T01:35:00Z_
_Verifier: Claude (gsd-verifier)_
