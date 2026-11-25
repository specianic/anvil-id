---
phase: 04-release-0-3-real-world-logins
plan: 06
subsystem: ui
tags: [i18n, fluent, locale-negotiation, minijinja, templates, rtl, wcag]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01: fluent-bundle/fluent-langneg/unic-langid deps, TenantSettings.default_locale; 04-02: pre-registered i18n module"
provides:
  - "anvil_web::i18n: Catalogs (embedded + theme override, one .ftl file per feature), Locale, negotiate(), RequestLocale extractor, locale_for_request, locale_for_user, localize_form, carry_ui_locales, t() template function"
  - "English catalog themes/default/locales/en/main.ftl for every 0.2 page and message"
  - "FormMessage.args + FormField.label_key; core emits keys only"
  - "PageContext { lang, dir, .. } with for_tenant(state, tenant, &Locale, title_key) / installation(state, &Locale, title_key)"
  - "errors::error_page_in / core_error_page_in (negotiated locale)"
  - "Discovery ui_locales_supported"
affects: [04-07, 04-08, 04-09, 04-10, 04-11, 04-13, 04-15, 04-18, 04-21, 04-24]

tech-stack:
  added: []
  patterns:
    - "Every page string goes through t(\"dotted.key\"); Fluent id = key with '.' -> '-'"
    - "Each feature ships themes/default/locales/{lang}/<feature>.ftl; never edit main.ftl from another plan"
    - "Handlers take RequestLocale and thread `loc: &Locale` into every render/error helper"
    - "Core forms/messages carry keys (+ args); the web layer localizes just before rendering"

key-files:
  created:
    - themes/default/locales/en/main.ftl
    - crates/anvil-web/tests/i18n.rs
    - crates/anvil-web/tests/snapshots/i18n__login_page_en.snap
  modified:
    - crates/anvil-web/src/i18n.rs
    - crates/anvil-web/src/render.rs
    - crates/anvil-web/src/errors.rs
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/src/ui/{login,mfa,registration,verification,recovery,setup,consent,account_security,account_sessions,account_apps}.rs
    - crates/anvil-core/src/flow/{form,engine,login,registration,recovery,setup,verification}.rs
    - crates/anvil-core/src/service/{flow,session,account}.rs
    - themes/default/templates/*.html (all 21)
    - themes/default/static/anvil.css

key-decisions:
  - "t() is one global minijinja function reading page.lang through State (works inside imported macros and includes); output is a plain auto-escaped string"
  - "FormField gains label_key (explicit stable key) rather than deriving it from form id + name"
  - "An honoured ui_locales is carried as &ui_locales= on form actions and page links so later POSTs keep the language; RequestLocale reads that query parameter"
  - "error_page/core_error_page keep their signature (tenant default locale, used by layers); UI handlers call error_page_in/core_error_page_in with the negotiated locale"
  - "Missing message everywhere renders the dotted key (debug log), never the old generic 'Something went wrong.'"
  - "User values that are the sole content of a contract element (tenant name, consent-client, admin-email) are isolated with CSS unicode-bidi: isolate instead of <bdi>, so exact-markup tests stay unchanged"

patterns-established:
  - "New page: PageContext::for_tenant(state, tenant, &loc, \"title.my_page\"), strings via t(), catalog in locales/en/<feature>.ftl"
  - "New form message: FormMessage::error(\"feature.key\").with_arg(\"n\", 3); the catalog uses { $n -> [one] .. *[other] .. }"

requirements-completed: [UI-04]

duration: 30min
completed: 2026-11-25
---

# Phase 4 Plan 06: i18n Infrastructure Summary

**Fluent catalogs (embedded, theme-overridable, one file per feature), locale negotiation ui_locales > user claim > Accept-Language > tenant default > en, a `t()` template function, keys-only core forms, `<html lang dir>`, logical CSS, and every 0.2 template converted with byte-identical English output.**

Note: `requirements-completed` lists UI-04 as delivered by this plan's scope (infrastructure + English); no requirement checkbox was ticked (wave rule).

## Performance

- **Duration:** about 30 min
- **Completed:** 2026-11-25
- **Tasks:** 3
- **Files modified:** about 60

## i18n API for later plans

### Catalog files (file-per-feature rule)
- Add `themes/default/locales/en/<feature>.ftl` (and other locales later). Every `.ftl` of a locale dir is loaded in file-name order. Never edit `main.ftl` from another plan.
- Message id = dotted key with `.` replaced by `-`: `t("upstream.button")` reads `upstream-button`. Use `anvil_web::i18n::fluent_id(key)` when unsure.
- Two files of one locale defining the same id fail startup and the error names both files. A malformed file fails startup with its name and line.
- Operators override single messages with `{theme_dir}/locales/{lang}/*.ftl`. These files win per id and can add new locales.
- Fluent trims leading and trailing spaces of a value, so keep the spaces in the template, not in the message.

### Rust
```rust
use crate::i18n::{Locale, RequestLocale, locale_for_request, locale_for_user, carry_ui_locales};

// Handler: negotiated from ?ui_locales=, Accept-Language, tenant default (installation: en)
async fn show(State(state): State<AppState>, tenant: ResolvedTenant,
              RequestLocale(loc, _): RequestLocale, ...) -> Response

// Pages continuing an authorization request (stored ui_locales):
ui::login::page_locale(&state, &tenant, request_locale, &headers, Some(request_id)).await
i18n::locale_for_request(&state, &tenant, &headers, Some(&auth_request.params)) -> Locale

// Account pages (user's locale claim between ui_locales and Accept-Language):
ui::consent::account_locale(&state, &tenant, &request_locale, &session).await
i18n::locale_for_user(&state, &tenant, &request_locale, claim) -> Locale

PageContext::for_tenant(&state, &tenant, &loc, "title.my_page")   // title is localized
PageContext::installation(&state, &loc, "title.my_page")
state.renderer().localize_form(&loc, &mut form)                    // labels + message texts
state.renderer().text(&loc, "my.key")                              // one string
state.renderer().catalogs().text(&loc, key, &[("n", FluentValue::from(3))])
errors::error_page_in(&state, Some(&tenant), &loc, status, "error_key", "")
errors::core_error_page_in(&state, Some(&tenant), &loc, &err)
carry_ui_locales(&url, &loc)   // append &ui_locales= when the page honours an explicit one
```
- Core: `FormMessage::new(level, key)`, `FormMessage::error(key)`, `.with_arg(name, value)`. Fields set `label_key` (for example `field.email`). Core leaves `text`/`label` empty.
- In `ui::login`, `render_tenant_form_with`, `message_page`, `locked_page`, `start_page`, `restart_login`, `submit_page`, `submit_flow`, `outcome_response_with`, `bad_form`, `csrf_page`, `render_form` and `BadQuery::into_response` all take `loc: &Locale` after `tenant`.
- `ui::consent::PageMessage::{error, info}(key)` builds a page message. Its text is filled by `consent::localized(state, loc, msgs)` or `msg.localized(state, loc)` right before rendering.

### Templates
- `{{ t("my.key") }}` and `{{ t("my.key", name=value, count=n) }}`. Numbers stay Fluent numbers, so plurals work. The output is auto-escaped and never marked safe.
- `t()` uses `page.lang` and falls back to English when it is absent. It works inside `{% import %}` macros and `{% include %}` partials.
- `forms.render(form, t("feature.submit"))`. Without a label the button reads `t("form.continue")`.
- Wrap user values that sit inside translated text in `<bdi>`.

## Accomplishments
- `Catalogs::load` handles the embedded files plus theme-dir overrides, with duplicate and malformed detection. Isolation marks are off, and bundles are `concurrent::FluentBundle` (Sync).
- `negotiate` follows the locked order. Accept-Language is ordered by q-value (q=0 and `*` dropped). Unknown or malformed tags fall through. RTL detection covers ar, he, fa, ur, ps and yi.
- Core: the four `message_text` tables are deleted (flow/engine, session, account, web consent). Core tests now assert keys. `login.too_many_attempts` is a Fluent plural driven by the `seconds` arg. The CAPTCHA and signed-in texts moved to the catalog.
- Every handler in the listed UI files takes `RequestLocale`. Login, registration and consent use the stored `ui_locales` of the authorization request. The account pages use the user's `locale` claim.
- Discovery advertises `ui_locales_supported` (`["en"]` today).
- All 21 templates were converted, and the grep heuristic finds no literal English sentence. `base.html` emits `lang`/`dir`. Scope descriptions are localized (`scope.{name}`).
- `anvil.css` uses logical properties. In LTR the look is unchanged, and the disclosure triangle is mirrored in RTL.

## Task Commits
1. **Task 1: i18n module (catalogs, negotiation, t function)**: `04f1520` (feat). It compiles together with Task 2 (`localize_form` and `RequestLocale` need the new `FormField`/`Renderer` API).
2. **Task 2: Core emits keys; renderer and handlers localize; discovery**: `41861f6` (feat)
3. **Task 3: Convert every template + logical CSS + en snapshot**: `4f7cf34` (feat)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Extra files the build forced**
- `crates/anvil-web/src/lib.rs`: `pub(crate) mod i18n` became `pub mod i18n` so the integration tests (and later plans' tests) can reach the API.
- `crates/anvil-web/src/protocol/authorize.rs`: the form_post page uses the new `PageContext::for_tenant` signature (tenant default locale, key `title.form_post`).
- `crates/anvil-core/src/flow/{login,registration,recovery,setup,verification}.rs`: field labels became label keys (`field.*`).
- `crates/anvil-core/src/service/flow.rs`: the restarted-flow message uses `FormMessage::new` (no English).
- `crates/anvil-web/tests/render.rs`: fixtures fill the new `label_key`/`args` fields. `tests/snapshots/render__*.snap` (9 files) gain only `dir="ltr"` on `<html>`.
- Commits: 04f1520, 41861f6, 4f7cf34

**2. [Design] `t()` is a global environment function, not a per-render closure**
- The plan said the function is "created per render, closing over Arc<Catalogs> + Locale". minijinja imports do not see per-render context variables in every case, while a global function with `&State` sees `page.lang` everywhere (verified in a scratch test). The behaviour is the same: `t()` is bound to `page.lang`.

**3. [Design] Error pages raised by layers keep the tenant default locale**
- `error_page`/`core_error_page` keep their signature (CSRF layer, rate-limit layer, tenant layer and lib fallback are owned by other plans) and render in the tenant default, or English without a tenant. Every UI handler uses the new `*_in` variants with the negotiated locale.

**4. [Design] CSS bidi isolation instead of `<bdi>` for contract elements**
- `<p class="anvil-tenant">`, `#consent-client` and `#admin-email` are matched as exact markup by existing tests (shell.rs, consent.rs, security_setup.rs). They get `unicode-bidi: isolate` in anvil.css. `<bdi>` is used where the user value shares an element with other content: app name h2, passkey label cell, session device cell.

**5. [Rule 1] Sessions page device fallback localized**
- "Unknown device" was produced in Rust. `device_label` now returns `Option` and the row falls back to `sessions.unknown_device` in the page locale. The module unit tests were adjusted.

### Plan items not done
- `crates/anvil-web/src/ui/format.rs` was not changed. Timestamps stay `YYYY-MM-DD HH:MM UTC` because no English words are involved. A localized date format can come with the first non-English catalog.
- `themes/default/README.md` (theme contract doc) is not in this plan's files. It should gain `page.lang`/`page.dir`, `t()` and the `locales/` override directory. Left for the docs pass (04-18/branding or a docs plan).

## Verification
- In a separate worktree (target/wt-04-06, own CARGO_TARGET_DIR, removed afterwards), the following pass: `cargo clippy --workspace --all-targets -- -D warnings` (clean), `cargo fmt --all --check` (clean), `cargo test -p anvil-core --lib` (488 passed), and `cargo test -p anvil-web --no-fail-fast` (51 test binaries ok, including `--test i18n` with 18 tests, `--test render` and `flow_login` snapshot unchanged).
- The only failures are the known expected-red TRANSITIONAL(04-15) email-template list: `admin_api_v02::email_templates_default_override_validation_and_reset`, plus `security_admin_v02::every_new_route_*`, which fail on the same `GET …/email-templates` 500.
- Template heuristic `grep -nE ">[A-Z][a-z]+ [a-z]+[^<{]*<" themes/default/templates/*.html` finds nothing.
- Not run: `tests/e2e/run.sh sqlite specs/login.spec.ts specs/a11y.spec.ts`, because Docker is unavailable. Left for CI / the wave merge. The English sentences, ids and selectors are unchanged.

## Next Phase Readiness
- Later Phase 4 pages (upstream buttons, email OTP, logout, select-account, profile, linked accounts, branding preview) should use `RequestLocale` + `PageContext::for_tenant(.., &loc, "title.x")` + `t()` and ship their own `locales/en/<feature>.ftl`.
- 04-15 (email templates) may reuse `Catalogs` for localized subjects if desired.

## Self-Check: PASSED
- Files exist: themes/default/locales/en/main.ftl, crates/anvil-web/tests/i18n.rs, crates/anvil-web/tests/snapshots/i18n__login_page_en.snap, crates/anvil-web/src/i18n.rs
- Commits in history: 04f1520, 41861f6, 4f7cf34
