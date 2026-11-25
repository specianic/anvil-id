---
phase: 02-release-0-1-first-login
plan: 03
subsystem: ui
tags: [minijinja, theme, templates, email, css, no-js]
requires: []
provides:
  - "themes/default/templates/*.html page templates rendered from FormDescription"
  - "form.html render(form, submit_label) macro"
  - "Stable selector and error-text contract (login-submit, mgmt-client-secret, redirect URI marker)"
  - "Email templates (txt + html) for verification, recovery, invitation, password_changed"
  - "themes/default/README.md template context and email payload contract"
affects: [02-09, 02-11, 02-12, tests/e2e, tests/conformance]
tech-stack:
  added: []
  patterns:
    - "Pages extend base.html and import form.html as forms; forms.render(form, label)"
    - "error.html maps error_key to fixed sentences; unknown keys fall back to 'Something went wrong.'"
    - "Single-use tokens only consumed by POST of a hidden field (link-scanner safe)"
key-files:
  created:
    - themes/default/templates/base.html
    - themes/default/templates/form.html
    - themes/default/templates/login.html
    - themes/default/templates/registration.html
    - themes/default/templates/verification.html
    - themes/default/templates/recovery.html
    - themes/default/templates/recovery_reset.html
    - themes/default/templates/setup.html
    - themes/default/templates/setup_done.html
    - themes/default/templates/message.html
    - themes/default/templates/error.html
    - themes/default/emails/{verification,recovery,invitation,password_changed}.{txt,html}
    - themes/default/README.md
  modified:
    - themes/default/static/anvil.css
decisions:
  - "render macro takes an optional submit_label (default 'Continue'); pages pass their own label"
  - "Forms use novalidate so validation errors always come from the server-side FormDescription messages"
  - "Error/message pages expose data-error-key / data-message-key attributes alongside fixed ids for test selectors"
  - "form.html avoids selectattr/equalto tests (uncertain minijinja support); uses 'error' in messages|map(attribute='level')|list"
metrics:
  duration: 10min
  completed: 2026-11-25
  tasks: 2
  files: 21
---

# Phase 2 Plan 03: Default Theme Summary

The built-in no-JS login theme: eleven minijinja page templates driven by `FormDescription` through a shared `render` macro, eight text and HTML email templates, an extended `anvil.css`, and a README that documents the selector, error-text and payload contract.

## What was built

- **Task 1 (7bbd4d3):** `base.html` links only `{{ page.asset_base }}/anvil.css` and has a dev-mode banner. `form.html` renders the form, the hidden `csrf_token` input, labelled inputs with id = name = field name, never writes password values back, marks error messages `role="alert"` and wires up `aria-describedby`/`aria-invalid`, then adds the `{form.id}-submit` button. Pages added: login, registration, verification (token in a hidden field and consumed only on POST), recovery, recovery_reset, setup, setup_done (`mgmt-client-id`, `mgmt-client-secret`, token endpoint, admin API base, warning that the secret is shown once), message, and error (the seven fixed sentences). Page links appear only when `page.links.*` is non-null. CSS adds the card layout, focus outlines for links, error and warning colours in light and dark modes, credential list styling, and the banner.
- **Task 2 (c05cf9d):** text and HTML emails for verification, recovery, invitation and password_changed. They use only `tenant_name`, `email`, `link` and `expires_in`. Recovery and invitation state the expiry and that the recipient can ignore the mail. The HTML versions are table-based with no images and no URLs. The README documents the page context, the FormDescription shape, the stable ids and sentences (labelled as the contract used by tests/conformance and tests/e2e), the payload keys, and theme-directory override with fallback to the embedded files.

## Verification

- Both plan `<automated>` checks pass: files exist; no script tags, external URLs, inline handlers or `style=`; selectors and marker present; delimiters and blocks balanced.
- Extra check: every page and email template rendered with Python Jinja2 using `StrictUndefined` and auto-escape and sample contexts. Output was correct: `login-submit`, password value not echoed, escaped messages, the redirect-URI sentence, and links omitted when null. minijinja rendering is still proven later by the 02-12 and 02-11 snapshot tests.

## Deviations from Plan

None. The plan was executed as written.

## Self-Check: PASSED
