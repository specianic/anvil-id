# AnvilID default theme

This directory holds the built-in login UI: page templates, email templates and the stylesheet. The
files are embedded in the `anvilid` binary at compile time, so the UI works with no external assets
and no network access (requirement UI-01). JavaScript is optional: it adds the passkey ceremony and
the automatic `form_post` submission, and every other flow works without it.

```
themes/default/
  templates/   page templates (minijinja, auto-escaped because of the .html extension)
  emails/      email templates (.txt plain text and .html variants)
  static/      anvil.css, webauthn.js, form_post.js, served under the page's asset base
```

## Ground rules

- Scripts only as self-hosted files from the asset base (`<script src="{{ page.asset_base }}/….js"
  defer>`). No inline `<script>` blocks, no inline `style` attributes, no inline event handlers
  (`onclick=` and friends) and no absolute URLs to any host. The strict Content-Security-Policy
  (`script-src 'self'`) would block them anyway, and a test scans rendered HTML for them.
- The one exception is `captcha.html`: when an operator enables a CAPTCHA for a tenant, that partial
  loads the provider's script (Turnstile or hCaptcha), and only the page that shows the widget gets
  a CSP allowing that provider. This is the operator's choice; a CAPTCHA can conflict with WCAG 2.2
  SC 3.3.8 (accessible authentication).
- No web fonts, `@import` or `url()` pointing at external hosts in CSS.
- No favicon link: some browsers fetch it from outside the asset base.
- Every flow works without JavaScript. Forms are plain `POST` forms. Script-driven controls (the
  passkey buttons) are rendered `hidden` and shown by the script only when WebAuthn is available;
  `form_post.html` has a visible "Continue" button for browsers without JavaScript.
- Single-use tokens (email verification, password recovery, invitations) are only consumed by a form
  `POST`. Opening the emailed link shows a page with a button; mail link scanners that `GET` the URL
  never use the token up.

## Page context

Every page receives `page`:

| Key | Type | Meaning |
|---|---|---|
| `page.title` | string | Page title; also the default `<h1>` |
| `page.tenant_name` | string or null | Display name of the tenant |
| `page.dev_mode` | bool | Renders the "Development mode: not for production use" banner |
| `page.asset_base` | string | `/assets` or `/t/{slug}/assets`; the stylesheet is `{asset_base}/anvil.css` |
| `page.links.login` | string or null | Link to the sign-in page; omitted when null |
| `page.links.registration` | string or null | Link to self-registration; omitted when null |
| `page.links.recovery` | string or null | Link to password recovery; omitted when null |

Form pages (`login.html`, `second_factor.html`, `registration.html`, `verification.html`,
`recovery.html`, `recovery_reset.html`, `setup.html`) also receive `form`, a serialised `FormDescription` from
`anvil-core` (`flow/form.rs`):

```
form = {
  id:         "login" | "second-factor" | "registration" | "recovery" | "recovery-reset" | "verification" | "setup",
  action:     "/t/acme/ui/login?flow=...",
  method:     "post",
  csrf_token: "...",
  fields: [
    { name, kind: "text" | "email" | "password" | "hidden", label, value (or null), required,
      autocomplete (or null), messages: [ { level: "info" | "error", key, text } ] }
  ],
  messages: [ { level, key, text } ]
}
```

`form.html` defines the `render(form, submit_label)` macro that every form page uses:

```
{% import "form.html" as forms %}
{{ forms.render(form, "Sign in") }}
```

It writes the `<form>`, a hidden `csrf_token` input, one labelled input per field (hidden fields have no
label), field messages, form-level messages and the submit button. Password values are never written
back into the page. Error messages carry `role="alert"`.

Other pages receive extra keys:

| Template | Extra keys |
|---|---|
| `message.html` | `heading`, `body_key`, `body` |
| `error.html` | `status`, `error_key`, `heading`, `detail` (or null) |
| `setup_done.html` | `admin_email`, `mgmt_client_id`, `mgmt_client_secret`, `token_endpoint`, `admin_api_base` |
| `login.html` | `passkey` (or null): `{ action, options_url }` for the passkey form; `captcha` (or null): `{ provider: "turnstile" \| "hcaptcha", site_key }`, rendered through `captcha.html` |
| `second_factor.html` | `factor_token` (sealed value naming the user for throttling; posted back as a hidden field), `has_error` |
| `captcha.html` (partial) | `captcha` as above |
| `consent.html` | `action`, `csrf_token`, `client_name`, `scopes` (`[{ name, description (or null) }]`), `messages` |
| `form_post.html` | `action` (the redirect URI), `fields` (name/value pairs: `code` or `error`, `state`, `iss`, …) |
| `account_base.html` | `current` (`security` \| `sessions` \| `apps`); the account pages extend it |
| `account_security.html` | `csrf_token`, `messages`, `recent_auth`, `login_url`, `passkeys` (`[{ id, label, created, created_iso, last_used, last_used_iso, delete_url }]`), `passkey_url`, `passkey_options_url`, `totp` (or null, same timestamps + `delete_url`), `totp_url`, `recovery_codes_remaining`, `recovery_codes_url` |
| `totp_enroll.html` | `qr_svg` (trusted inline SVG), `secret_groups`, `confirm_url`, `csrf_token`, `code_error` (or null), `security_url` |
| `recovery_codes.html` | `codes`, `codes_text`, `message`, `security_url` (shown once) |
| `account_sessions.html` | `csrf_token`, `messages`, `sessions` (`[{ id, current, device, ip, created, created_iso, last_seen, last_seen_iso, revoke_url }]`), `other_count`, `revoke_others_url` |
| `account_apps.html` | `csrf_token`, `messages`, `apps` (`[{ client_id, client_name, scopes, granted, granted_iso, revoke_url }]`) |

Timestamps are rendered in UTC; the `*_iso` variants go into `<time datetime>`.

## Selector and text contract

The ids and sentences below are a **contract**. The conformance browser automation
(`tests/conformance`), the Playwright suite (`tests/e2e`) and the renderer snapshot tests depend on
them. Changing one is a breaking change for those suites and for any operator automation built on
them; update all of them together.

Stable ids and names:

- Every input has `id` = `name` = the field name: `identifier`, `password`, `email`, `token`, and so on.
- Every form has `id` = `form.id`, and its submit button has `id="{form.id}-submit"`: `login-submit`,
  `registration-submit`, `verification-submit`, `recovery-submit`, `recovery-reset-submit`,
  `setup-submit`.
- The hidden CSRF input is `name="csrf_token"`.
- `setup_done.html`: `mgmt-client-id`, `mgmt-client-secret`, `token-endpoint`, `admin-api-base`,
  `admin-email`.
- `error.html`: the sentence is in `id="error-message"` with `data-error-key="{error_key}"`.
- `message.html`: the body is in `id="message-body"` with `data-message-key="{body_key}"`.
- Links between pages: `link-login`, `link-registration`, `link-recovery`.
- Development banner: `dev-mode-banner`.
- Optional detail line of `error.html`: `error-detail` (e.g. the wait time of a 429).
- In-page messages (account, consent, sessions, apps) carry `data-message-key="{key}"` and the ids
  `account-msg-{n}` / `consent-msg-{n}`; tests match on the key, not the sentence.

Release 0.2 pages:

- Login, passkey: `login-passkey` (the form, `data-webauthn="authenticate"`),
  `login-passkey-submit` (`data-webauthn-trigger`, hidden until `webauthn.js` runs),
  `login-passkey-status` (`data-webauthn-status`, `aria-live`).
- Second factor: form `second-factor`, inputs `code` and `recovery_code` (the latter inside the
  `<details>` toggled by `recovery-code-toggle`), hidden `factor_token`, submit `second-factor-submit`.
- CAPTCHA: `captcha-widget`, `captcha-noscript`.
- Consent: `consent-form`, `consent-client`, `consent-scopes` with one `consent-scope-{n}`
  (`data-scope="{name}"`) per scope, the decision buttons `consent-allow` and `consent-deny`
  (`name="decision"`), `consent-note`, `consent-messages`.
- form_post: `form-post` (the auto-submitted form), `form-post-continue` (no-JS button),
  `form-post-status`.
- Account navigation: `account-nav` with `account-nav-security`, `account-nav-sessions`,
  `account-nav-apps`; content in `account-content`.
- Account security: `passkeys`, `passkey-list`, `passkey-{id}`, `passkeys-empty`, `passkey-register`
  (`data-webauthn="register"`), input `label`, `passkey-register-submit`, `passkey-register-status`,
  `passkey-register-nojs`, hidden `response`; `totp`, `totp-status`, `totp-begin` /
  `totp-begin-submit`; `recovery-codes-count`, `recovery-codes-remaining`,
  `recovery-codes-regenerate` / `recovery-codes-regenerate-submit`; removal forms
  `credential-delete-{id}` / `credential-delete-{id}-submit`; re-authentication notice
  `account-reauth` with `link-reauth`.
- TOTP enrolment: `totp-qr`, `totp-manual`, `totp-secret`, `totp-instructions`, form `totp-confirm`
  with input `code` and `totp-confirm-submit`, `link-account-security`.
- Recovery codes: `recovery-codes` (list), `recovery-codes-text` (copy box), `recovery-codes-help`.
- Sessions: `session-list`, `session-{id}` (current one has `data-current` and
  `session-current-marker`), `session-revoke-{id}` / `session-revoke-{id}-submit`,
  `sessions-revoke-others` / `sessions-revoke-others-submit`.
- Connected apps: `app-list`, `app-{n}` (`data-client-id`), `app-{n}-name`, `app-revoke-{n}` /
  `app-revoke-{n}-submit`, `apps-empty`.

`webauthn.js` DOM contract: `form[data-webauthn=register|authenticate]` with a hidden input
`name="response"`, a `[data-webauthn-trigger]` button, a `[data-webauthn-status]` live region,
optional `data-options-url` and `data-webauthn-msg-cancelled` / `data-webauthn-msg-failed` sentences
on the form. `form_post.js` submits `#form-post` once on load.

Error sentences in `error.html`, keyed by `error_key`:

| `error_key` | Sentence |
|---|---|
| `redirect_uri_mismatch` | The redirect URI in this request is not registered for this client. |
| `unknown_client` | This application is not registered. |
| `invalid_request` | The sign-in request is invalid. |
| `flow_expired` | This sign-in attempt expired. Please start again. |
| `csrf` | This form submission could not be verified. Please try again. |
| `not_found` | Page not found. |
| `too_many_requests` | Too many attempts. Please wait a moment and try again. |
| `server_error` (and any unknown key) | Something went wrong. |

In-page sentence on the login and second-factor forms when an attempt is locked (429 with
`Retry-After`), message key `login.too_many_attempts`: "Too many attempts. Try again in N second(s)."

## Stylesheet classes

Besides the 0.1 classes (`anvil-field`, `anvil-field-invalid`, `anvil-form-messages`, `anvil-links`,
`anvil-muted`, `anvil-optional`, …), `anvil.css` styles these 0.2 classes. Overriding themes that
replace `anvil.css` should keep rules for them:

| Class | Used for |
|---|---|
| `anvil-passkey`, `anvil-secondary` | Passkey section on the login page; secondary buttons (passkey, consent Deny) |
| `anvil-disclosure` | `<details>` for the recovery-code input |
| `anvil-captcha` | CAPTCHA widget container (scrolls inside the card on narrow screens) |
| `anvil-actions` | Button rows (consent decision) |
| `anvil-consent-scopes`, `anvil-scope-list` | Requested and granted scope lists |
| `anvil-account`, `anvil-account-nav`, `anvil-account-section` | Account pages (wider card) and their navigation |
| `anvil-table` | Credential and session tables. Cells carry `data-label="{column}"`: below 30rem each row stacks into a block and the label is shown from that attribute |
| `anvil-app-list` | Connected-apps list |

The templates also put `anvil-credential-label`, `anvil-session-device` and `anvil-session-ip` on
table cells as styling hooks for themes; the default stylesheet has no rules for them.
| `anvil-qr` | TOTP QR code: max 13rem, dark modules on a white box in every colour scheme |
| `anvil-secret` | The TOTP secret for manual entry |
| `anvil-recovery-codes` | The one-time list of recovery codes |
| `anvil-message`, `anvil-message-info`, `anvil-message-error` | In-page messages |
| `anvil-lead` | Lead sentence (form_post page) |

## Email templates

Each email exists as `emails/{name}.txt` (complete on its own) and `emails/{name}.html` (simple
tables, no images, no external resources). The mail worker renders both from a payload, a
`BTreeMap<String, String>`. Templates use only these payload keys:

| Email | Payload keys |
|---|---|
| `verification` | `tenant_name`, `email`, `link`, `expires_in` |
| `recovery` | `tenant_name`, `email`, `link`, `expires_in` |
| `invitation` | `tenant_name`, `email`, `link`, `expires_in` |
| `password_changed` | `tenant_name`, `email` |
| `recovery_code_used` | `tenant_name`, `remaining` |

Tenants can override these per kind through the management API (`email-templates/{kind}`). An
override is checked when it is saved: valid syntax, only the payload keys above, no `include` /
`extends` of theme files, and a fuel limit on rendering.

`expires_in` is human-readable text such as `1 hour`. No email reveals whether any other account
exists.

## Overriding the theme

Operators can change the UI without recompiling. Configure a theme directory with the same layout as
this one (`templates/`, `emails/`, `static/`). At runtime the template loader looks in the operator's
directory first and falls back to these embedded defaults for any file it does not find
(ARCHITECTURE section 10.4), so a theme only needs the files it changes. Typical overrides:

- `static/anvil.css` to change colours and layout. The CSS custom properties at the top of the file
  (`--anvil-primary`, `--anvil-bg`, ...) are the easiest place to start.
- `templates/base.html` to change the page frame.
- Individual email templates to change wording.

Overridden templates must keep the selector and text contract above, and they are subject to the
same ground rules: the Content-Security-Policy blocks inline and third-party scripts, inline styles
and external assets.
