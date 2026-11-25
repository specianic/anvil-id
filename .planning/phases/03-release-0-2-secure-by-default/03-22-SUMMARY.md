---
phase: 03-release-0-2-secure-by-default
plan: 22
subsystem: admin-console delivery
tags: [admin-console, rust-embed, content-negotiation, brotli, gzip, etag, csp, spa]
requires:
  - phase: 03-03
    provides: admin-ui/dist with base /console/, .br/.gz sidecars (> 1 KiB), no inline script/style
  - phase: 03-13
    provides: outer router / security-header layering in lib.rs app()
provides:
  - "anvil_web::console: ConsoleAssets (#[folder = \"$CARGO_MANIFEST_DIR/../../admin-ui/dist\"], #[allow_missing = true]), routes(), CONSOLE_CSP, IMMUTABLE, NO_CACHE"
  - "GET /console -> 308 /console/; /console/ and /console/{*path} served installation-wide, outside tenant resolution"
  - "Pure helpers: resolve_path (SPA fallback / 404 / traversal), cache_control, negotiate (br > gzip > identity, q=0 and * honoured)"
  - "Placeholder page (200, no script, no inline style) when the binary was built without admin-ui/dist"
affects: [03-25, 03-29]
tech-stack:
  added: []
  patterns:
    - "Pre-compressed sidecar negotiation in the handler (rust-embed compression feature not used)"
    - "Per-variant strong ETag = quoted hex of the embedded file's sha256 metadata; weak If-None-Match comparison"
key-files:
  created:
    - crates/anvil-web/src/console.rs
    - crates/anvil-web/tests/console.rs
  modified:
    - crates/anvil-web/src/lib.rs
key-decisions:
  - "03-22: Console CSP is default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none' (03-03 recorded no inline-style need, so style-src is not relaxed)"
  - "03-22: Every file under assets/ (Vite's content-hashed output) is immutable for a year; index.html, the placeholder and any other file are no-cache"
  - "03-22: ETag is per encoding variant (hash of the .br/.gz/original actually sent), so a cached br validator never matches the identity body; Vary: accept-encoding on every file response"
  - "03-22: /console redirects with 308 to /console/; the console is mounted on the outer router so /t/{slug}/console/ is a tenant 404 and the console works before installation"
  - "03-22: Placeholder links the theme stylesheet /assets/anvil.css (same origin) rather than inline styles"
duration: 25min
completed: 2026-11-25
---

# Phase 3 Plan 22: Console served at /console/* Summary

**The binary embeds `admin-ui/dist` with rust-embed (`allow_missing`) and serves it at `/console/*` on the outer router. It picks the `.br`/`.gz` sidecar from `Accept-Encoding`, marks hashed assets immutable and `index.html` no-cache, gives each variant its own ETag and answers 304 on a match. Extension-less paths fall back to the SPA index, missing files return 404, and every response carries a strict CSP. A binary built without Node shows a placeholder page that explains how to build the console.**

## Task Commits

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1 | Console asset module (embedding, negotiation, cache and path policy, placeholder) | 40bd4a9 |
| 2 | Router wiring and HTTP tests (with and without a console build) | 7516cae |

## What was built

- `console.rs`:
  - `ConsoleAssets` embeds `admin-ui/dist`. Debug builds read it from disk, release builds embed it.
  - `routes()` serves `/console` (308), `/console/` and `/console/{*path}`.
  - `resolve_path`:
    - Paths that are empty, `index.html` or have no extension resolve to the index.
    - An embedded file is served as an asset.
    - A missing path with an extension returns 404.
    - Paths containing `..`, `.`, empty segments, backslashes or control characters return 404. Axum percent-decodes the path first, so `%2e%2e`, `%2f` and `%5c` are caught too.
  - `negotiate` chooses `br` before `gzip`. A coding is used only if its sidecar exists and its q is above 0, whether it is listed by name or matched by `*`. `x-gzip` counts as gzip. Anything else gets identity.
  - Content-Type always comes from the original file name.
  - 7 unit tests.
- `lib.rs`: `.merge(console::routes())` on the outer router, before `fallback_service(tenant_routed)`. The global security headers still apply (insert-if-absent), so the console's own CSP and Cache-Control are kept.
- `tests/console.rs` (6 tests, 209 lines):
  - 308 redirect from `/console`.
  - Index or placeholder at `/console/` and on deep links, with the CSP and no-cache.
  - Works before installation.
  - `/t/system/console/` is not the console.
  - Traversal and missing files return 404.
  - When the real index is served, the test takes the entry chunk from `index.html` and checks:
    - br, gzip and identity encodings with `Vary`
    - the immutable Cache-Control
    - 304 for the matching variant ETag and 200 for another variant's ETag
    - index 304 on a deep link
    - 404 for a missing `.js` chunk

## Verification

- `cargo test -p anvil-web --lib console`: 7 passed.
- `cargo test -p anvil-web --test console` with `admin-ui/dist` present (main tree, debug): 6 passed, asset branch exercised.
- Same suite without `admin-ui/dist` in a fresh worktree (`target/wt-03-22`, own target dir; dist is gitignored, so it was absent): 6 passed, placeholder branch exercised. The build succeeded without dist.
- Release profile (files embedded at compile time) in the same worktree: without dist, `--test console` 6 passed and `--lib console` 7 passed (placeholder). After copying a built dist into the worktree, `--test console` 6 passed with the real index embedded (the test binary contains the dist `index.html`). The worktree and its target dir were removed afterwards. A full `cargo build --release -p anvilid` was not run separately; the embedding crate was built in release with and without dist.
- `cargo clippy -p anvil-web --lib --test console -- -D warnings`: clean.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `pub mod console;` was added to lib.rs in the Task 1 commit**
- The module's unit tests (Task 1 verify) can only compile once the module is declared. The router wiring itself went into Task 2.

**2. [Rule 2 - Correctness] Per-variant ETag**
- The plan says "ETag from the embedded file hash". The hash of the file actually sent (sidecar or original) is used, so a cached brotli body is never revalidated against the identity body.

**3. [Rule 2] `style-src 'self'` stated explicitly in the console CSP**
- `default-src 'self'` already implies it. Stating it makes the "no inline style" property explicit, and the unit test checks it.

### Notes / follow-ups

- `assets.rs` was not in this plan's files, so its private `sha256_hex` and `if_none_match_hits` were not made `pub(crate)`. `console.rs` now has its own `etag` and `if_none_match_hits`, which makes three copies (assets.rs, protocol/jwks.rs, console.rs). A follow-up that owns all three files should extract one shared `http_cache` helper.
- Release artifacts must contain the real console. Per the plan this is enforced by CI (03-03 console job, 03-29 release check), not by build.rs. A release build without dist compiles and serves the placeholder.
- 03-25 Playwright: the real CSP is now live at `/console/`. Recheck that React's `<style precedence>` path is never hit (03-03 note).
- The console's OIDC redirect target `/console/callback` resolves to the index (extension-less), as needed.

## Issues Encountered

- Other plans had in-progress edits in the main tree (anvil-core flow.rs, anvil-mail, tests/flow_recovery.rs). They did not affect these targets. Commits used `git commit -- <paths>`.

## Self-Check: PASSED

- FOUND: crates/anvil-web/src/console.rs, crates/anvil-web/tests/console.rs
- FOUND commits: 40bd4a9, 7516cae
