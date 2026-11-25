---
phase: 04-release-0-3-real-world-logins
plan: 09
subsystem: core
tags: [theming, branding, css-validation, wcag-contrast, logo-sniffing, tdd, proptest]

requires:
  - phase: 04-01
    provides: ThemeTokens, ThemeColors, Logo model types; anvil_jose::encoding::sha256
provides:
  - anvil_core::policy::branding::{validate_tokens, validate_custom_css, contrast_ratio, merge_tokens, theme_stylesheet, sniff_logo}
  - Rgb, ThemeWarning, ThemeError, CssError, LogoError, ThemeCss, ColorScheme, ContrastPair
  - Constants MAX_CUSTOM_CSS_BYTES (32 KiB), MAX_LOGO_BYTES (256 KiB), MAX_RADIUS_PX (32), MIN_CONTRAST (3.0), AA_CONTRAST (4.5)
affects: [04-16, 04-18, 04-24]

tech-stack:
  added: []
  patterns:
    - "Custom CSS validation is an allow-list for at-rules and functions, plus a deny-list matched case-insensitively in the raw text and in a view without comments or whitespace"
    - "theme_stylesheet re-checks token syntax and custom CSS, so stored data can never break out of its declaration"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/policy/branding.rs

key-decisions:
  - "theme_stylesheet returns Result<ThemeCss, ThemeError> and re-validates syntax and custom CSS (not contrast) instead of trusting stored input"
  - "Custom light colours without a dark variant emit :root{color-scheme: light} plus a prefers-color-scheme: dark block that pins the whole effective light palette. Without that block, anvil.css's dark block would still override the non-customised variables"
  - "Contrast is checked for text/bg, text/surface and primary_text/primary. A pair is checked when either colour is customised, and the missing colour comes from that scheme's default palette"
  - "Custom CSS allow-lists the at-rules media, supports, keyframes, layer and container, and a fixed set of value, gradient, transform, filter and selector functions. src(), image(), cross-fade(), element(), paint() and attr() are refused"
  - "The font family must also have balanced quotes (an unterminated string would swallow the following declarations)"

requirements-completed: []

duration: 25min
completed: 2026-11-25
---

# Phase 4 Plan 09: Pure Theming Rules Summary

**Pure, std-only theming rules in anvil-core. Theme tokens are checked (hex colours, 0-32 px radius, system-font charset), and WCAG contrast below 3:1 is refused while below 4.5:1 gives a warning. Custom CSS goes through an allow-list validator that reports line numbers. Tokens merge per field (client > tenant > default). The stylesheet is deterministic and carries a SHA-256 hash, and logos are identified by magic bytes. Every security check has negative tests and proptests.**

## Performance

- **Duration:** about 25 min
- **Completed:** 2026-11-25
- **Tasks:** 1 TDD feature (RED + GREEN; the threat-model docs went into the GREEN commit, so no REFACTOR commit was needed)
- **Files modified:** 1

## Accomplishments

- `validate_tokens`
  - Colours must be `#rgb`, `#rrggbb` or `#rrggbbaa`. A bad value is reported as `ThemeError::Color { field: "colors.x" | "colors_dark.x" }`.
  - Radius 33 or more is refused. The font family must use `[A-Za-z0-9 ,'"-]`, be 1-200 characters, not be blank, and have balanced quotes.
  - Contrast is checked for both the light and the dark set, and warnings are tagged with the scheme.
- `contrast_ratio(Rgb, Rgb)` uses WCAG relative luminance (#000/#fff = 21, #767676 on white = 4.54). Alpha is ignored, and this is documented.
- `validate_custom_css`
  - Limits: 32 KiB, and no control characters (TAB, LF and CRLF are allowed; a lone CR, NUL, form feed, ESC, DEL and C1 controls are refused).
  - The listed forbidden constructs are refused in any casing: in the raw text (comments and strings included) and when split by comments or whitespace (`u/**/rl(`, `behavior : x`).
  - Only allow-listed at-rules and functions are accepted.
  - `{}`, `()` and `[]` must be balanced and properly nested, comments must be terminated, and strings must be single-line and terminated.
  - Every error carries a 1-based line number.
- `merge_tokens`: precedence is per field. `colors_dark` is merged per colour across the layers that define it.
- `theme_stylesheet`
  - Output is a `:root{…}` block (colours lowercased, fixed order, then `--anvil-font` and `--anvil-radius`), then either a dark media block or the light-scheme pinning, then the custom CSS verbatim.
  - `hash` is the lowercase hex SHA-256 from `anvil_jose::encoding::sha256`, using a local hex fn. No base64 is involved.
- `sniff_logo`: accepts PNG, JPEG and WebP (RIFF....WEBP). SVG, XML, GIF, WAV and truncated signatures are refused, as are empty input and anything over 256 KiB.
- `LIGHT_DEFAULTS`/`DARK_DEFAULTS` mirror `themes/default/static/anvil.css`. A test reads the CSS with `include_str!` and keeps the two in sync.
- Tests: 26 in total (23 table tests and 3 proptests).
  - `url_in_any_casing_is_rejected`
  - `accepted_css_never_escapes_its_context`: any accepted CSS is balanced, contains no `<`, `\`, `url(` or `@import`, and all generated blocks close before the custom CSS starts.
  - `accepted_tokens_stay_in_their_declaration`: an accepted token block closes exactly at the end of its line and has exactly three declarations.

## Task Commits

1. **RED: failing tests**: `5e71454` (test)
2. **GREEN: implementation + threat-model docs**: `12685aa` (feat)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] theme_stylesheet returns Result and re-validates its input**
- **Found during:** GREEN
- **Issue:** The plan signature returns `ThemeCss` directly. If the function trusted its input, a stored value that bypassed validation (for example after a validator change or a direct DB edit) would be rendered verbatim into the stylesheet.
- **Fix:** It returns `Result<ThemeCss, ThemeError>` (with a new `ThemeError::Css` variant) and re-runs the syntax and custom CSS checks. Contrast is not re-checked, because it is a publish-time policy.
- **Commit:** 12685aa

**2. [Rule 1 - Bug prevention] Light-scheme pinning also overrides the default dark block**
- **Issue:** `color-scheme: light` does not stop anvil.css's `@media (prefers-color-scheme: dark)` block from applying. Users with a dark OS preference would get the brand's custom colours mixed with dark defaults.
- **Fix:** Next to `:root{color-scheme: light}`, the sheet emits a dark-media block containing the full effective light palette (all 15 colour variables).
- **Commit:** 12685aa

**3. [Rule 2 - Accessibility] text/surface contrast is checked too**
- Forms sit on `--anvil-surface`, so text on surface is checked in addition to the plan's text/bg and primary_text/primary pairs.

**4. [Rule 2 - Security] Allow-lists beyond the plan's deny-list**
- Following the orchestrator's note that the validator must be an allow-list, at-rules and functions are allow-listed and the plan's deny-list is kept for specific messages. Brackets must nest properly, strings must be single-line, and the font family must have balanced quotes.

### Notes
- Verification ran in a separate worktree (target/wt-04-09, own CARGO_TARGET_DIR), which was removed afterwards. Other wave-2 plans have uncommitted anvil-core edits in the main tree.
- `cargo clippy -p anvil-core --all-targets -- -D warnings` fails only on `crates/anvil-core/src/oauth/resource.rs:145` (`cloned_ref_to_slice_refs`). That file was committed by 04-08 in its RED commit 4451add and is outside this plan's scope. branding.rs produces no warnings.
- `scripts/check-deps.sh` passes. No dependencies were added.

## Issues Encountered
None blocking.

## Next Phase Readiness
- 04-16/04-18 (theming backend) can call `validate_tokens` and `validate_custom_css` on PUT and preview. They can call `merge_tokens(&ThemeTokens::default(), tenant, client)` followed by `theme_stylesheet` for `/assets/theme/{hash}.css`, and `sniff_logo` on upload.

## Self-Check: PASSED

- crates/anvil-core/src/policy/branding.rs exists (1618 lines, min 250).
- Commits 5e71454 and 12685aa are in the history.
- `cargo test -p anvil-core --lib -- policy::branding`: 26 passed. `scripts/check-deps.sh`: OK.
