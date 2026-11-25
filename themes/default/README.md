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
  locales/     page text: Fluent catalogs, locales/{lang}/{feature}.ftl (since 0.3)
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
| `page.title` | string | Page title (already translated); also the default `<h1>` |
| `page.lang` | string | Negotiated language tag (`en`, …); `base.html` writes it to `<html lang>`. `t()` reads it |
| `page.dir` | string | `ltr` or `rtl` (Arabic, Hebrew, Persian, Urdu, Pashto, Yiddish); `base.html` writes it to `<html dir>`. `anvil.css` uses logical properties, so layouts mirror |
| `page.tenant_name` | string or null | Display name of the tenant |
| `page.dev_mode` | bool | Renders the "Development mode: not for production use" banner |
| `page.asset_base` | string | `/assets` or `/t/{slug}/assets`; the stylesheet is `{asset_base}/anvil.css` |
| `page.theme_css` | string or null | Tenant pages: the generated theme stylesheet `{tenant_base}/theme/theme.css` (plus `?flow={id}` on flow pages, `?preview={token}` on the preview), linked after `anvil.css`; it also styles the `.anvil-logo` element (hidden without a logo). Null on installation pages |
| `page.links.login` | string or null | Link to the sign-in page; omitted when null |
| `page.links.registration` | string or null | Link to self-registration; omitted when null |
| `page.links.recovery` | string or null | Link to password recovery; omitted when null |

Form pages (`login.html`, `second_factor.html`, `registration.html`, `verification.html`,
`recovery.html`, `recovery_reset.html`, `setup.html`; since 0.3 also `mfa_enroll.html`,
`email_code.html` and `upstream_link.html`) also receive `form`, a serialised `FormDescription` from
`anvil-core` (`flow/form.rs`):

```
form = {
  id:         "login" | "second-factor" | "registration" | "recovery" | "recovery-reset" | "verification" | "setup"
              | "mfa-enroll" | "email-code" | "upstream-link",
  action:     "/t/acme/ui/login?flow=...",
  method:     "post",
  csrf_token: "...",
  fields: [
    { name, kind: "text" | "email" | "password" | "hidden", label_key, label, value (or null),
      required, autocomplete (or null), messages: [ { level: "info" | "error", key, args, text } ] }
  ],
  messages: [ { level, key, args, text } ]
}
```

Since 0.3 core sends only keys (`label_key`, message `key` and `args`); the web layer fills `label`
and `text` in the page language just before rendering, so templates keep using `label` and `text`.

`form.html` defines the `render(form, submit_label)` macro that every form page uses:

```
{% import "form.html" as forms %}
{{ forms.render(form, t("login.submit")) }}
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
| `login.html` | `passkey` (or null): `{ action, options_url }` for the passkey form; `captcha` (or null): `{ provider: "turnstile" \| "hcaptcha", site_key }`, rendered through `captcha.html`; since 0.3 `upstream` (list of `{ slug, name, action }`, one sign-in button per enabled connection) and `email_code` (`{ action, value }` or null, the "Email me a sign-in code" form; `value` is the address prefilled from `login_hint`) |
| `second_factor.html` | `factor_token` (sealed value naming the user for throttling; posted back as a hidden field), `has_error` |
| `captcha.html` (partial) | `captcha` as above |
| `consent.html` | `action`, `csrf_token`, `client_name`, `client_id`, `scopes` (`[{ name, description (or null) }]`), `resources` (0.3: requested RFC 8707 resources, list of strings, may be empty), `messages` |
| `form_post.html` | `action` (the redirect URI), `fields` (name/value pairs: `code` or `error`, `state`, `iss`, …) |
| `account_base.html` | `account_base` (tenant base path prefixed to the navigation links), `account_nav` (`profile` \| `email` \| `password` \| `security` \| `sessions` \| `apps` \| `linked`, sets `aria-current`); the account pages extend it and fill `{% block account %}` |
| `account_security.html` | `csrf_token`, `messages`, `recent_auth`, `login_url`, `passkeys` (`[{ id, label, created, created_iso, last_used, last_used_iso, delete_url }]`), `passkey_url`, `passkey_options_url`, `totp` (or null, same timestamps + `delete_url`), `totp_url`, `recovery_codes_remaining`, `recovery_codes_url` |
| `totp_enroll.html` | `qr_svg` (trusted inline SVG), `secret_groups`, `confirm_url`, `csrf_token`, `code_error` (or null), `security_url` |
| `recovery_codes.html` | `codes`, `codes_text`, `message`, `security_url` (shown once) |
| `account_sessions.html` | `csrf_token`, `messages`, `sessions` (`[{ id, current, device, ip, created, created_iso, last_seen, last_seen_iso, revoke_url }]`), `other_count`, `revoke_others_url` |
| `account_apps.html` | `csrf_token`, `messages`, `apps` (`[{ client_id, client_name, scopes, granted, granted_iso, revoke_url }]`) |
| `account_profile.html` (0.3) | `csrf_token`, `messages`, `action`, `profile` (`{ name, given_name, family_name, locale }`) |
| `account_email.html` (0.3) | `messages`, `mode`: `change` (`csrf_token`, `action`, `email`, `email_verified`, `recent_auth`, `login_url`), `confirm` (`confirm_action`, `token`), or `done` |
| `account_password.html` (0.3) | `csrf_token`, `messages`, `action`, `has_password`, `recent_auth`, `login_url`, `revoke_others` |
| `account_linked.html` (0.3) | `csrf_token`, `messages`, `recent_auth`, `login_url`, `linked` (`[{ id, provider, email, created, created_iso, last_used, last_used_iso, unlink_url }]`), `available` (`[{ slug, name, connect_url }]`) |
| `mfa_enroll.html` (0.3) | Enrolment mode: `form` (id `mfa-enroll`, field `code`), `qr_svg`, `secret_groups`, `factor_token`. Done mode: `codes`, `codes_text`, `continue_url` (recovery codes, shown once) |
| `email_code.html` (0.3) | `form` (id `email-code`, field `code`), `factor_token` (or null), `resend_action` (or null) |
| `magic_link.html` (0.3) | `action`, `csrf_token`, `token` (posted back by the button) |
| `upstream_link.html` (0.3) | `form` (id `upstream-link`, fields `identifier`, `password`; the first message names the provider), `passkey` (as on the sign-in page) |
| `select_account.html` (0.3) | `client_name`, `user_name` (or null), `user_email`, `messages`, `csrf_token`, `action` |
| `logout_confirm.html` (0.3) | `client_name` (or null), `csrf_token`, `action`, `cancel_url` |
| `logged_out.html` (0.3) | `heading_key`, `message_key`, `message`, `error` (bool); signed-out page and sign-out error page |
| `preview.html` (0.3) | none besides `page` (whose `theme_css` is the draft stylesheet); static sample markup, nothing can be submitted |

Timestamps are rendered in UTC; the `*_iso` variants go into `<time datetime>`.

## Translations (since 0.3)

Templates contain no literal sentences. Every string comes from a catalog through the global
template function `t()`:

```
{{ t("title.login") }}
{{ t("upstream.continue_with", provider=c.name) }}
{{ t("login.too_many_attempts", seconds=n) }}
```

- `t(key, name=value, …)` looks the key up in the language of `page.lang` (English when it is
  missing), works inside imported macros and included partials, and returns an auto-escaped plain
  string (never marked safe). Numbers stay numbers, so Fluent plurals work.
- A user-supplied value that sits inside translated text (a provider name, an app name, an email
  address) is wrapped in `<bdi>` by the template, because isolation marks are turned off in the
  catalogs.
- If a message is missing in the page language it falls back to English, and if English lacks it
  too the dotted key itself is shown (and logged at debug level).

Catalog layout: `locales/{lang}/{feature}.ftl` (Fluent syntax), for example `locales/en/main.ftl`,
`locales/en/logout.ftl`, `locales/en/upstream.ftl`.

- **One file per feature.** Every `.ftl` file of a language directory is loaded, in file-name
  order. A new page or feature ships its own file instead of editing `main.ftl`.
- **Message ids** are the dotted keys with `.` replaced by `-`: `t("upstream.continue_with")` reads
  `upstream-continue_with`. The same id in two files of one language fails startup and names both
  files; a malformed file fails startup with its name and line.
- Fluent trims spaces at the start and end of a value; keep spacing in the template, not in the
  message.
- Do not reword the sentences marked as a contract below (they are matched by the conformance and
  e2e suites); translate them in other languages as usual.
- **Completeness:** English must define every key the code and templates use; the test
  `embedded_english_has_every_message_key_in_use` (crates/anvil-web/tests/i18n.rs) fails
  otherwise. Other languages may be partial and fall back to English per message.
- A new language is a new directory `locales/{lang}/` with the same file names. Discovery lists the
  languages that have a catalog in `ui_locales_supported`.

Operators override single messages, or add a language, without recompiling: put `.ftl` files in
`{theme_dir}/locales/{lang}/`. A message there wins over the embedded one with the same id; every
other message keeps its embedded text.

The page language is negotiated in this order: `ui_locales` (from the authorization request, or a
`ui_locales` query parameter), the user's `locale` claim (account pages only), the browser's
`Accept-Language`, the tenant's default language, then English. Pages that honour an explicit
`ui_locales` carry it on their form actions (`&ui_locales=`), so the language survives the POST.

Emails are not translated in 0.3; they use the templates under `emails/`.

## Selector and text contract

The ids and sentences below are a **contract**. The conformance browser automation
(`tests/conformance`), the Playwright suite (`tests/e2e`) and the renderer snapshot tests depend on
them. Changing one is a breaking change for those suites and for any operator automation built on
them; update all of them together.

Stable ids and names:

- Every input has `id` = `name` = the field name: `identifier`, `password`, `email`, `token`, and so on.
- Every form has `id` = `form.id`, and its submit button has `id="{form.id}-submit"`: `login-submit`,
  `registration-submit`, `verification-submit`, `recovery-submit`, `recovery-reset-submit`,
  `setup-submit`; since 0.3 also `mfa-enroll-submit`, `email-code-submit` and
  `upstream-link-submit`.
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
  `account-nav-apps`; content in `account-content`. Since 0.3 the navigation has seven entries, in
  this order: `account-nav-profile`, `account-nav-email`, `account-nav-password`,
  `account-nav-security`, `account-nav-sessions`, `account-nav-apps`, `account-nav-linked`.
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

Release 0.3 pages:

- Sign-in page, upstream buttons: one form per enabled connection, `upstream-{slug}-form`, with the
  button `upstream-{slug}` (`data-connection="{slug}"`, text "Continue with {provider}"), inside a
  group with class `anvil-upstream`.
- Sign-in page, email sign-in: disclosure `email-code-toggle` (open when an address is prefilled),
  form `email-code-request`, input `email-code-email`, button `email-code-request-submit`.
- "Check your email" page: form `email-code`, input `code` (`inputmode="numeric"`,
  `autocomplete="one-time-code"`), button `email-code-submit`, messages `email-code-msg-{n}`;
  resend form `email-code-resend` with `email-code-resend-submit`; link `link-login`.
- Magic link page: form `magic-link`, button `magic-link-submit`, link `link-login`.
- Link confirmation (`upstream_link.html`): form `upstream-link` (inputs `identifier`, `password`),
  button `upstream-link-submit`, the passkey form as on the sign-in page (`login-passkey`, …), link
  `link-cancel` (back to sign-in, nothing is linked).
- MFA enrolment during sign-in (`mfa_enroll.html`): notice `mfa-enroll-required`, `totp-qr`,
  `totp-manual`, `totp-secret`, `totp-instructions`, form `mfa-enroll` with input `code` and
  `mfa-enroll-submit`, messages `mfa-enroll-msg-{n}`; after confirmation `recovery-codes`,
  `recovery-codes-text`, `recovery-codes-help` and the link `link-continue`.
- Account chooser (`select_account.html`, `prompt=select_account`): form `select-account-form`,
  `select-account-client`, `select-account-current` (with `select-account-name`,
  `select-account-email`), buttons `select-account-continue` and `select-account-other` (both
  `name="choice"`, values `continue` / `other`), messages `select-account-messages` /
  `select-account-msg-{n}`.
- Consent, requested resources (only when a client asked for RFC 8707 resources):
  `consent-resources` with one `consent-resource-{n}` (`data-resource="{value}"`) per resource.
- Sign-out confirmation (`logout_confirm.html`, always served under `/ui/logout`): form
  `logout-confirm-form`, button `logout-confirm-submit` (text "Sign out"), `logout-confirm-text`,
  `logout-client` (when a client asked), link `logout-cancel` ("Stay signed in", to the sessions
  page).
- Signed-out and sign-out error page (`logged_out.html`, never served under `/ui/logout`): the
  sentence is in `logout-message` with `data-message-key="{key}"` (`role="alert"` for errors).
- Account profile: form `profile-form` with inputs `name`, `given_name`, `family_name`, `locale`,
  button `profile-form-submit`.
- Account email: `current-email` (`email-verified` or `email-unverified` badge), form
  `email-change` with input `new_email` and `email-change-submit`; confirmation form
  `email-confirm` (hidden `token`) with `email-confirm-submit`; re-authentication notice
  `account-reauth` with `link-reauth`.
- Account password: form `password-form` with inputs `new_password` and `revoke_others`
  (checkbox), button `password-form-submit`, `password-none` when the account has no password yet;
  `account-reauth` / `link-reauth`.
- Linked accounts: table `linked-list` with rows `linked-{id}`, unlink forms `linked-unlink-{id}`
  (button `linked-unlink-{id}-submit`), empty state `linked-none`, available providers
  `linked-available` with connect forms `linked-connect-{slug}` (button
  `linked-connect-{slug}-submit`); `account-reauth` / `link-reauth`. Cells carry `data-label` like
  the sessions table.
- Theme preview (`preview.html`): `preview-banner`, `preview-login`, `preview-consent` (sample
  markup only).
- Logo: `base.html` renders `<span class="anvil-logo" role="img" aria-label="{tenant name}">`
  before the tenant name on tenant pages (when `page.theme_css` is set). The generated theme
  stylesheet shows the logo as its background, or hides the element when there is none.

Contract sentences of the logout pages (`locales/en/logout.ftl`). The conformance browser
configuration (`tests/conformance/config.template.json`) waits for these exact English texts:

| Key | Sentence |
|---|---|
| button `logout-confirm-submit` (`logout.confirm_submit`) | Sign out |
| `logout.signed_out` | You have been signed out. |
| `logout.invalid_id_token_hint` | The sign-out request is invalid: the id_token_hint could not be verified. |
| `logout.redirect_uri_not_registered` | The sign-out request is invalid: the post_logout_redirect_uri is not registered for this client. |
| `logout.id_token_hint_required` | The sign-out request is invalid: post_logout_redirect_uri requires id_token_hint or client_id. |
| `logout.client_mismatch` | The sign-out request is invalid: client_id does not match the id_token_hint. |
| `logout.unknown_client` | The sign-out request is invalid: this application is not registered. |

The URL layout is part of the same contract: the confirmation page is under `/ui/logout`, the
signed-out page is at `/logout` or `/ui/signed-out` (never under `/ui/logout`), and error pages are
answered at `/logout`.

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
| `anvil-qr` | TOTP QR code: max 13rem, dark modules on a white box in every colour scheme |
| `anvil-secret` | The TOTP secret for manual entry |
| `anvil-recovery-codes` | The one-time list of recovery codes |
| `anvil-message`, `anvil-message-info`, `anvil-message-error` | In-page messages |
| `anvil-lead` | Lead sentence (form_post page, logout pages) |
| `anvil-error-text` | Error sentence of the sign-out error page (0.3) |

The templates also put `anvil-credential-label`, `anvil-session-device` and `anvil-session-ip` on
table cells as styling hooks for themes; the default stylesheet has no rules for them. The same
holds for the 0.3 hooks `anvil-upstream` (the group of upstream sign-in buttons) and
`anvil-consent-resources` (the requested-resources section of the consent screen).

`anvil-logo` (0.3) has no rule in `anvil.css` either: the generated theme stylesheet styles it (logo
as background image, or `display:none` without a logo). A theme that replaces `base.html` and wants
the console's logo upload to work should keep the element.

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
| `login_code` (0.3) | `tenant_name`, `code`, `link`, `expires_minutes` |
| `email_change` (0.3, sent to the new address) | `tenant_name`, `link`, `new_email`, `expires_minutes` |
| `email_changed` (0.3, sent to the old address) | `tenant_name`, `new_email` |

Tenants can override these per kind through the management API (`email-templates/{kind}`). An
override is checked when it is saved: valid syntax, only the payload keys above, no `include` /
`extends` of theme files, and a fuel limit on rendering.

`expires_in` is human-readable text such as `1 hour`; `expires_minutes` is a number. No email
reveals whether any other account exists. The `login_code` email carries both the code and the
magic link. Emails are not translated in 0.3.

## Overriding the theme

Most branding needs no theme directory: since 0.3 the console (**Branding**) and the management API
set colours (with an optional dark set), font family, corner radius, a logo and custom CSS per tenant
or per client, with a live preview. These are served as the generated stylesheet in
`page.theme_css` (same origin, under the same CSP), and custom CSS is checked by an allow-list
validator (no `url()`, `@import` or external resources).

Operators can change the UI further without recompiling. Configure a theme directory with the same
layout as this one (`templates/`, `emails/`, `static/`, `locales/`). At runtime the template loader looks in the operator's
directory first and falls back to these embedded defaults for any file it does not find
(ARCHITECTURE section 10.4), so a theme only needs the files it changes. Typical overrides:

- `static/anvil.css` to change colours and layout. The CSS custom properties at the top of the file
  (`--anvil-primary`, `--anvil-bg`, ...) are the easiest place to start.
- `templates/base.html` to change the page frame.
- Individual email templates to change wording.
- `locales/{lang}/*.ftl` to change single page sentences or add a language (see Translations).

Overridden templates must keep the selector and text contract above, and they are subject to the
same ground rules: the Content-Security-Policy blocks inline and third-party scripts, inline styles
and external assets.
