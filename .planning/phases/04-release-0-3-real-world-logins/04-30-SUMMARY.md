---
phase: 04-release-0-3-real-world-logins
plan: 30
subsystem: ui
tags: [i18n, fluent, german, catalogs, e2e, playwright]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-06 i18n pipeline (Catalogs, negotiation, t()); English catalogs from 04-12, 04-13, 04-15, 04-16, 04-18, 04-20, 04-21, 04-24, 04-25"
provides:
  - "German (de) catalogs mirroring all ten en/*.ftl files"
  - "crates/anvil-web/tests/i18n_catalogs.rs: per-file id parity, variable subset, plural selector parity for every shipped locale"
  - "tests/e2e/specs/i18n.spec.ts: ui_locales / Accept-Language selection, German consent and account pages, 320 px reflow, axe, discovery"
affects: [future locales, any plan adding an en/*.ftl file (must add the de file too)]

tech-stack:
  added: []
  patterns:
    - "A new en/<feature>.ftl needs a matching file in every other locale dir; i18n_catalogs fails CI otherwise"
    - "Sentence fragments around links/values are translated so the template's fixed spaces still read naturally (German reauth: 'Aus Sicherheitsgründen <link>melden Sie sich bitte erneut an</link> und ändern Sie danach ...')"

key-files:
  created:
    - themes/default/locales/de/main.ftl
    - themes/default/locales/de/account.ftl
    - themes/default/locales/de/account_linked.ftl
    - themes/default/locales/de/email_code.ftl
    - themes/default/locales/de/logout.ftl
    - themes/default/locales/de/mfa.ftl
    - themes/default/locales/de/preview.ftl
    - themes/default/locales/de/resource.ftl
    - themes/default/locales/de/select_account.ftl
    - themes/default/locales/de/upstream.ftl
    - crates/anvil-web/tests/i18n_catalogs.rs
    - tests/e2e/specs/i18n.spec.ts
  modified:
    - crates/anvil-web/tests/i18n.rs

key-decisions:
  - "The parity test scans messages line by line (column-0 `id =` plus indented continuations) and cross-checks the count against FluentResource::entries(); fluent-syntax is not a direct dependency and adding it would touch shared Cargo files"
  - "Discovery needed no change: ui_locales_supported is derived from Catalogs::available(), so embedding de advertises it"
  - "Formal address (Sie); Passkey, Token, Client-ID/Secret, Theme and protocol parameter names stay untranslated"

requirements-completed: [UI-04]

duration: 35min
completed: 2026-11-26
---

# Phase 4 Plan 30: German Catalogs, Catalog Parity Test and i18n E2E Summary

**German is a complete second locale (all ten en/*.ftl files mirrored with the same ids, variables and plural selectors). A CI test enforces per-file parity for every locale. A Playwright spec covers ui_locales and Accept-Language selection, German consent and account pages, and 320 px reflow.**

Note: no requirement checkbox was ticked (wave rule). `requirements-completed` records the scope only.

## Performance

- **Duration:** about 35 min
- **Completed:** 2026-11-26
- **Tasks:** 2
- **Files:** 12 created, 1 modified

## Accomplishments

- `ls themes/default/locales/en` lists main, account, account_linked, email_code, logout, mfa, preview, resource, select_account and upstream. All ten now have a `de` counterpart. No en file was added after the plan was written.
- `i18n_catalogs.rs` checks every locale directory except en against en, file by file. It fails on:
  - a missing file or an extra file
  - a missing id, or an id that en lacks
  - a `$variable` that en does not declare
  - a missing plural selector where en has one

  It also asserts that `Catalogs::load(None)` loads, that `available()` contains en and de, and that German plurals render ("1 Sekunde" / "30 Sekunden"). A unit test proves the comparison rejects each kind of bad input.
- Discovery advertises de without code changes, because `ui_locales_supported` comes from `catalogs().available()` (discovery.rs line 197).
- `i18n.spec.ts` covers the following:
  - discovery contains en and de
  - `ui_locales=de` gives a German login page (lang, heading, labels, button), axe passes, and the page reflows at 320 px
  - the consent page that follows is German (heading, Allow/Deny, scope text) and reflows at 320 px
  - a `de-DE` context without ui_locales gets a German login
  - `ui_locales=xx en` and an `en-US` context get English
  - the account security page is German via `?ui_locales=de` and via a `de-DE` browser (heading and nav, including the linked-accounts entry), and reflows at 320 px

## Task Commits

1. **Task 1: German catalogs + completeness test**: `387788c` (feat)
2. **Task 2: i18n browser spec**: `8d34187` (test)

## Verification

- `cargo test -p anvil-web --test i18n_catalogs --test i18n --test discovery`: 4 + 18 + 9 passed.
- `cargo test -p anvil-web --test authorize --test logout --test render`: passed. These cover `ui_locales=de-CH en` and the existing snapshots, and English output is unchanged.
- `cargo clippy -p anvil-web --test i18n_catalogs --test i18n -- -D warnings`: clean.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- Not run: `tests/e2e/run.sh sqlite specs/i18n.spec.ts`, because Docker is not available here. The spec has never executed and is left for CI.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Extra file: crates/anvil-web/tests/i18n.rs**
- **Found during:** Task 1
- **Issue:** Two 04-06 tests assumed no embedded German. `missing_messages_fall_back_to_english_then_to_the_key` expected `title.registration` in de to fall back to English. The `t()` probe expected the English plural for de.
- **Fix:** The fallback test now uses an unshipped locale (`fr` theme override). The probe now expects the German plural sentence.
- **Commit:** 387788c

**2. [Design] Line scanner instead of the fluent-syntax AST**
- The plan suggested walking the AST via fluent-bundle, but fluent-bundle does not re-export the `fluent_syntax::ast` types. A dev-dependency would edit shared Cargo files during a concurrent wave. Each file is still parsed by `FluentResource::try_new`, which fails on malformed input, and the scanned message count must equal the parser's message count.

## Issues / Follow-ups

- None. Account-page dates are locale-neutral (`YYYY-MM-DD HH:MM UTC`, ui/format.rs), so the German sentences around them need no date localisation.

## Self-Check: PASSED
