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
- No external fonts; the default theme self-hosts Hanken Grotesk and IBM Plex Mono (OFL, see
  `static/fonts/SOURCES.md`), served from the asset base under `font-src 'self'`. No `@import` or
  `url()` pointing at external hosts in CSS.
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
| `page.links.account` (rc.4) | string, absent when unset | The account page (`#link-account`) |
| `page.links.sign_out` (rc.4) | string, absent when unset | Action of the sign-out form (`#form-sign-out`, `method="post"`): the end-session endpoint, which asks for confirmation. Never a `GET` that signs out |
| `page.links.continue_to` (rc.4) | `{ href, name }`, absent when unset | "Continue to {app}" of a live authorization request (`#link-continue`) |
| `page.links.console` (rc.4) | string, absent when unset | The admin console (`#link-console`, system tenant only) |
| `page.links.app_home` (rc.4) | `{ href, name }`, absent when unset | "Back to {app}" (`#link-back-to-app`): the stored `initiate_login_uri` or `client_uri` of a static (administrator-registered) client. Never a request value, never a dynamic or CIMD client |
| `page.links.home` (rc.4) | string, absent when unset | The installation's start page (`#link-home`), on pages without a tenant |

Since rc.4 flow pages build every link from the flow's navigation context: a live authorization
request travels as `?request=` on `link-login`, `link-registration`, `link-recovery`, `link-cancel`
and `link-continue`, so a detour returns to the application. An unknown, expired, malformed or
foreign `request=` on `GET /ui/login`, `/ui/registration` or `/ui/recovery` answers the 400
`flow_expired` page (no form, the id is not echoed).

Since rc.4 a refused form `POST` on a flow page answers `303` to the same page with `?flow=`
(post/redirect/get); the error travels in a sealed one-shot flash cookie, and the `GET` answers 400
with the form and its messages. Themes and scripts that read the body of a refused `POST` must
follow the redirect. Locks (429) and CAPTCHA demands are still direct answers.

Form pages (`login.html`, `second_factor.html`, `registration.html`, `verification.html`,
`recovery.html`, `recovery_reset.html`, `setup.html`; since 0.3 also `mfa_enroll.html`,
`email_code.html` and `upstream_link.html`; since 1.0 also `login_identify.html`) also receive `form`, a serialised `FormDescription` from
`anvil-core` (`flow/form.rs`):

```
form = {
  id:         "login" | "second-factor" | "registration" | "recovery" | "recovery-reset" | "verification" | "setup"
              | "mfa-enroll" | "email-code" | "upstream-link" | "login-identify" | "login-sso-choice",
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
| `message.html` | `heading`, `body_key`, `body`; since rc.4 `sent_to` (or null, the address of the check-email page, `#message-sent-to`) and the way-forward links of `page.links` |
| `error.html` | `status`, `error_key`, `heading`, `detail` (or null; since rc.4 rendered only when `page.dev_mode`); since rc.4 a friendly heading and explanation per key and the way-forward links of `page.links` |
| `setup_done.html` | `admin_email`, `mgmt_client_id`, `mgmt_client_secret`, `token_endpoint`, `admin_api_base`; since rc.4 the primary action is `#link-console` and the credentials sit under "For automation" (`#setup-automation`) |
| `root.html` (rc.4) | `signed_in`, `administration` (default tenant: show the discreet `#link-administration`), plus `page.links` (`login`, `account`, `sign_out`, `console`). Served at `/` and `/ui` of every tenant, `no-store` |
| `console_setup_pending.html` (rc.4) | none besides `page`; shown by `/console/` and the root page before setup, names `anvilid admin setup-url` (`#setup-command`) |
| `org_not_member.html` (rc.4) | `user_email`, `requested_org` (bool), `messages`, `csrf_token`, `action`; served at `/ui/select-organization/not-member?request=` when the signed-in user is not a member of the requested organization |
| `account_confirm.html` (rc.4) | `action_id`, `post_url`, `csrf_token`, `cancel_url`: the server-rendered confirmation of a destructive account action (no JavaScript dialog); the confirming `POST` carries `confirm=yes` |
| `recovery_codes_flow.html` (rc.4) | `codes`, `codes_text`, `app_name` (or null), `csrf_token`, `action`: the recovery codes shown once after MFA enrolment during sign-in, `no-store`, bound to the flow cookie |
| `login.html` | `passkey` (or null): `{ action, options_url }` for the passkey form; `captcha` (or null): `{ provider: "turnstile" \| "hcaptcha", site_key }`, rendered through `captcha.html`; since 0.3 `upstream` (list of `{ slug, name, action }`, one sign-in button per enabled connection) and `email_code` (`{ action, value }` or null, the "Email me a sign-in code" form; `value` is the address prefilled from `login_hint`); since 1.0 `change_email` (`{ action, email }` or null): set on the password step that follows the email-first page of a tenant with a routed domain. The entered address then travels in a hidden `identifier` field (hidden fields render without a label, also in the CAPTCHA variant) and is shown read-only, with a form that posts `choice=change` back to the email page. Null on the combined form, which then renders exactly as before |
| `second_factor.html` | `factor_token` (sealed value naming the user for throttling; posted back as a hidden field), `has_error`; since 0.4 `passkey_second_factor` (or null): `{ action, options_url }` for the passkey assertion form, set when the user has a passkey (the form then carries the hidden marker field `passkey`, never rendered; a passkey-only user's form has no `code`/`recovery_code` field and the authenticator-app form is not rendered) |
| `captcha.html` (partial) | `captcha` as above |
| `consent.html` | `action`, `csrf_token`, `client_name`, `client_id`, `scopes` (`[{ name, description (or null) }]`), `resources` (0.3: requested RFC 8707 resources, list of strings, may be empty), `messages` |
| `form_post.html` | `action` (the redirect URI), `fields` (name/value pairs: `code` or `error`, `state`, `iss`, …) |
| `account_base.html` | `account_base` (tenant base path prefixed to the navigation links), `account_nav` (`profile` \| `email` \| `password` \| `security` \| `sessions` \| `apps` \| `linked`, sets `aria-current`); the account pages extend it and fill `{% block account %}`. Since rc.4 `header` (`{ email, sign_out_url, back_to_app }`, `back_to_app` is `{ href, name }` of a static client or null) |
| `account_security.html` | `csrf_token`, `messages`, `recent_auth`, `login_url`, `passkeys` (`[{ id, label, created, created_iso, last_used, last_used_iso, delete_url }]`), `passkey_url`, `passkey_options_url`, `totp` (or null, same timestamps + `delete_url`), `totp_url`, `recovery_codes_remaining`, `recovery_codes_url` |
| `totp_enroll.html` | `qr_svg` (trusted inline SVG), `secret_groups`, `confirm_url`, `csrf_token`, `code_error` (or null), `security_url`; since rc.4 `otpauth_uri` (the escaped `otpauth://` link, `#link-otpauth`, only on this `no-store` page) |
| `recovery_codes.html` | `codes`, `codes_text`, `message`, `security_url` (shown once) |
| `account_sessions.html` | `csrf_token`, `messages`, `sessions` (`[{ id, current, device, ip, created, created_iso, last_seen, last_seen_iso, revoke_url }]`), `other_count`, `revoke_others_url` |
| `account_apps.html` | `csrf_token`, `messages`, `apps` (`[{ client_id, client_name, scopes, granted, granted_iso, revoke_url }]`) |
| `account_profile.html` (0.3) | `csrf_token`, `messages`, `action`, `profile` (`{ name, given_name, family_name, locale }`) |
| `account_email.html` (0.3) | `messages`, `mode`: `change` (`csrf_token`, `action`, `email`, `email_verified`, `recent_auth`, `login_url`), `confirm` (`confirm_action`, `token`), or `done` |
| `account_password.html` (0.3) | `csrf_token`, `messages`, `action`, `has_password`, `recent_auth`, `login_url`, `revoke_others` |
| `account_linked.html` (0.3) | `csrf_token`, `messages`, `recent_auth`, `login_url`, `linked` (`[{ id, provider, email, created, created_iso, last_used, last_used_iso, unlink_url }]`), `available` (`[{ slug, name, connect_url }]`) |
| `mfa_enroll.html` (0.3) | Enrolment mode: `form` (id `mfa-enroll`, field `code`), `qr_svg`, `secret_groups`, `factor_token`; since 0.4 `passkey_enroll` (`{ options_url, action }` of the webauthn.js registration form, or null); since rc.4 `otpauth` (the escaped `otpauth://` link, `#link-otpauth`). Since rc.4 the recovery codes after enrolment are on `recovery_codes_flow.html` |
| `email_code.html` (0.3) | `form` (id `email-code`, field `code`), `factor_token` (or null), `resend_action` (or null) |
| `magic_link.html` (0.3) | `action`, `csrf_token`, `token` (posted back by the button) |
| `upstream_link.html` (0.3) | `form` (id `upstream-link`, fields `identifier`, `password`; the first message names the provider; no fields, with the message `upstream.link_no_method`, when the revealed account has no way to confirm), `passkey` (as on the sign-in page); since 1.0 `upstream` (`{ slug, name, action }`: the revealed account's linked providers, or, when the account may not be revealed, the tenant's other providers, the same list whatever account matched), `email_code` (`{ action, value, hidden }` or null; `hidden`: the account may not be revealed, render a plain "Email me a code" button without any address field) and `account_linked` (URL of `/ui/account/linked`) |
| `select_account.html` (0.3) | `client_name`, `user_name` (or null), `user_email`, `messages`, `csrf_token`, `action` |
| `logout_confirm.html` (0.3) | `client_name` (or null), `csrf_token`, `action`, `cancel_url` (since rc.4 the static client's home when there is one, otherwise the account sessions page) |
| `logged_out.html` (0.3) | `heading_key`, `message_key`, `message`, `error` (bool); signed-out page and sign-out error page. Since rc.4 the way-forward links of `page.links` (`link-back-to-app`, `link-login` "Sign in again" or "Go to sign in" on errors, `link-account`, `link-console`, `form-sign-out`); `/ui/signed-out?client_id=` adds "Back to {app}" for a static client only |
| `preview.html` (0.3) | none besides `page` (whose `theme_css` is the draft stylesheet); static sample markup, nothing can be submitted |
| `login_identify.html` (1.0) | Identifier-first sign-in (home-realm discovery), rendered only for tenants with a verified, routed domain. `form` with id `login-identify` (the email page: one `identifier` field of kind `email`, `autocomplete="username"`) or `login-sso-choice` (the address uses single sign-on and its organization still allows passwords: no fields, the template writes two buttons posting `choice=sso` and `choice=password` to `form.action`); `change_email` (`{ action, email }` or null, as on `login.html`); `upstream` and `passkey` as on `login.html` (email page only) |
| `select_organization.html` (1.0) | Organization switcher for clients whose organization policy is `required`: `client_name`, `organizations` (`[{ id, slug, display_name }]`, the signed-in user's own memberships only, sorted by display name), `messages` (`[{ level, key, text }]`), `csrf_token`, `action`. The form posts `organization` = the chosen org id |
| `invitation.html` (1.0) | Organization invitation page. `view`: `offer`, `invalid`, `signed_out`, `wrong_account`, `verify_email`, `already_member`, `accepted`, `registered` or `email_taken`; `message_key` (the `invitation.*` message of the view); `org` (organization display name); `email` (the invited address, signed-out view only; shown read-only, never a form field); `action` (accept POST), `register_action` (registration POST), `csrf_token`, `token` (posted back as a hidden field); `registration_allowed`, `password_error` (`{ key, text }` or null), `name` (echoed); `login_url` (on the `signed_out` and `email_taken` views it carries `return_to`, so the sign-in comes back to the invitation), `logout_url`, `continue_url` (the account profile page; the `registered` view links to it because registering signs in). The GET only shows the offer; nothing is consumed before the button is pressed |

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
`locales/en/logout.ftl`, `locales/en/upstream.ftl`. 1.0 adds `hrd.ftl` (identifier-first sign-in),
`select_organization.ftl`, `invitation.ftl` and `saml.ftl`, each in English and German.

- **One file per feature.** Every `.ftl` file of a language directory is loaded, in file-name
  order. A new page or feature ships its own file instead of editing `main.ftl`.
- **Message ids** are the dotted keys with `.` replaced by `-`: `t("upstream.continue_with")` reads
  `upstream-continue_with`. The same id in two files of one language fails startup and names both
  files; a malformed file fails startup with its name and line.
- Fluent trims spaces at the start and end of a value; keep spacing in the template, not in the
  message.
- Do not reword the sentences marked as a contract below (they are matched by the conformance and
  e2e suites); translate them in other languages as usual.
- **Completeness:** English must define every key the code and templates use (test
  `embedded_english_has_every_message_key_in_use` in `crates/anvil-web/tests/i18n.rs`). Every
  language shipped under `themes/default/locales/` must define exactly the English message ids,
  file by file, use no variables English does not declare and keep English's plural selectors
  (`crates/anvil-web/tests/i18n_catalogs.rs`). So a new `en/{feature}.ftl` needs a counterpart in
  every shipped language in the same change.
- **Contributing a language:** add a directory `locales/{lang}/` with the same file names as `en/`
  and translate every message; the parity test above tells you what is missing. Discovery lists
  the languages that have a catalog in `ui_locales_supported`. At runtime a message missing from an
  operator override falls back to English.

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
  Since 0.4, when the user has a passkey: section `second-factor-passkey` with form
  `second-factor-passkey-form` (`data-webauthn="authenticate"`, posts `response` to
  `/ui/login/second-factor/passkey/finish?flow=`), button `second-factor-passkey-submit`
  (`data-webauthn-trigger`, hidden until `webauthn.js` runs), status `second-factor-passkey-status`,
  messages `second-factor-passkey-msg-N` (a refusal is `second_factor.passkey_failed`), noscript
  note `second-factor-passkey-nojs`. Keys: `second_factor.{passkey_heading, passkey_help,
  passkey_button, passkey_nojs, passkey_failed}`, `second_factor.webauthn.{cancelled, failed}`.
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
- Sign-in page, email sign-in: button `email-code-request-submit` with hint `email-code-request-hint`.
  Since rc.4 the button sits inside form `login` and posts the `identifier` field to its
  `formaction`; the disclosure `email-code-toggle`, form `email-code-request` and input
  `email-code-email` are gone (also on the revealed link-confirmation page).
- "Check your email" page: form `email-code`, input `code` (`inputmode="numeric"`,
  `autocomplete="one-time-code"`), button `email-code-submit`, messages `email-code-msg-{n}`;
  resend form `email-code-resend` with `email-code-resend-submit`; link `link-login`.
- Magic link page: form `magic-link`, button `magic-link-submit`, link `link-login`.
- Link confirmation (`upstream_link.html`): form `upstream-link` (inputs `identifier`, `password`;
  without fields the messages sit in an element with that id), button `upstream-link-submit`, the
  passkey form as on the sign-in page (`login-passkey`, …), confirming providers
  `upstream-{slug}-form` / `upstream-{slug}`, the email code form as on the sign-in page
  (`email-code-request`, …) or, when the account may not be revealed (`email_code.hidden`), the
  button-only form `email-code-link-request` with hint `email-code-link-hint` and button
  `email-code-link-request-submit`, `link-other-way` with link `link-account-linked`, link
  `link-cancel` (back to sign-in, nothing is linked).
- MFA enrolment during sign-in (`mfa_enroll.html`): notice `mfa-enroll-required`, `totp-qr`,
  `totp-manual`, `totp-secret`, `totp-instructions`, form `mfa-enroll` with input `code` and
  `mfa-enroll-submit`, messages `mfa-enroll-msg-{n}`; since rc.4 `link-otpauth`. After
  confirmation (since rc.4 on `recovery_codes_flow.html`): `recovery-codes`, `recovery-codes-text`,
  `recovery-codes-help` and form `recovery-codes-confirm` with button
  `recovery-codes-confirm-submit` (replaces the former `link-continue`).
- Account chooser (`select_account.html`, `prompt=select_account`): form `select-account-form`,
  `select-account-client`, `select-account-current` (with `select-account-name`,
  `select-account-email`), buttons `select-account-continue` and `select-account-other` (both
  `name="choice"`, values `continue` / `other`), messages `select-account-messages` /
  `select-account-msg-{n}`.
- Consent, requested resources (only when a client asked for RFC 8707 resources):
  `consent-resources` with one `consent-resource-{n}` (`data-resource="{value}"`) per resource.
- Sign-out confirmation (`logout_confirm.html`, always served under `/ui/logout`): form
  `logout-confirm-form`, button `logout-confirm-submit` (text "Sign out"), `logout-confirm-text`,
  `logout-client` (when a client asked), link `logout-cancel` ("Stay signed in"; since rc.4 to the
  static client's home when there is one, otherwise to the sessions page).
- Signed-out and sign-out error page (`logged_out.html`, never served under `/ui/logout`): the
  sentence is in `logout-message` with `data-message-key="{key}"` (`role="alert"` for errors).
  Since rc.4 also `link-back-to-app`, `link-login`, `link-account`, `link-console` and
  `form-sign-out` (see `page.links`). Without an active session the end-session endpoint no longer
  asks for confirmation and shows this page directly.
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
  the sessions table. After a successful Connect the provider's return answers 303 back to
  `/ui/account/linked`, where the new row is listed (there is no separate "linked" message page).
- Theme preview (`preview.html`): `preview-banner`, `preview-login`, `preview-consent` (sample
  markup only).
- Logo: `base.html` renders `<span class="anvil-logo" role="img" aria-label="{tenant name}">`
  before the tenant name on tenant pages (when `page.theme_css` is set). The generated theme
  stylesheet shows the logo as its background, or hides the element when there is none.

Release 1.0 pages:

- Identifier-first sign-in, email page (`login_identify.html`, form `login-identify`): form
  `login-identify-form` with input `identifier` (type `email`) and button `login-identify-submit`
  (text from `form.continue`); field errors use `email.invalid`. The upstream buttons
  (`upstream-{slug}-form` / `upstream-{slug}`) and the passkey form (`login-passkey`, …) follow,
  exactly as on `login.html`. Organization connections never get a button.
- Identifier-first sign-in, single-sign-on choice (form `login-sso-choice`): `login-email-locked`
  (message `hrd.signing_in_as` with `$email`), form `login-sso-form` with button
  `login-sso-continue` (`choice=sso`), form `login-use-password-form` with button
  `login-use-password` (`choice=password`), form `login-change-email-form` with button
  `login-change-email` (`choice=change`). The explanation is the info message `hrd.sso_explain`.
- Password step after the email page (`login.html` with `change_email`): form `login` as before,
  with a hidden `identifier`; `login-email-locked` above it; `login-change-email-form` /
  `login-change-email` after it. The email-code request form is prefilled with the locked address.
- Refusal of password, email-code and magic-link sign-in for an address whose organization forces
  single sign-on: message key `hrd.use_sso` (status 400, on the form or on the message page).
- Organization switcher (`select_organization.html`): form `select-organization-form` (POST, no
  JavaScript), messages `select-organization-messages` / `select-organization-msg-{n}` (with
  `data-message-key`: `select_organization.expired`, `select_organization.not_member`), fieldset
  `select-organization-list` with a legend holding the client name
  `select-organization-client`, one radio per membership `organization-{slug}`
  (`name="organization"`, `value` = org id, the first one checked) with its label
  `organization-{slug}-label` (display name and slug), submit `select-organization-form-submit`.
  Title key `title.select_organization`.
- Organization invitation (`invitation.html`): the message in `invitation-message` with
  `data-message-key="invitation.{offer|invalid|signed_out|wrong_account|verify_email|already_member|accepted|registered|email_taken}"`;
  accept form `invitation-accept` with button `invitation-accept-submit`; registration form
  `invitation-register-form` with inputs `invitation-email` (read-only, not submitted),
  `password` and `name`, button `invitation-register-submit`, and the error
  `invitation-password-error` (`data-message-key` `password.too_short`, `password.too_long`,
  `password.breached` or `service.overloaded`); links `invitation-sign-in` (signed-out and
  email-taken views; returns here after signing in), `invitation-sign-out`, `invitation-continue`
  (registered view: the new account is signed in), hint `invitation-sign-in-hint`, notice
  `invitation-registration-disabled`. Every invalid token renders the same `invitation.invalid`
  view (status 400). Keys changed in 1.0 (06-31): `invitation-sign_in_hint`,
  `invitation-email_taken` and `invitation-registered` no longer ask to reopen the link or to sign
  in; `invitation-continue` is new.
- SAML sign-in failure (experimental): `error.html` with `error_key` `saml_login_failed`; the
  sentence is `saml.login_failed`. It never shows the NameID, attributes or XML.

Release 1.0 rc.4 pages and ids:

- Way-forward links (from `page.links`, on the message, error, signed-out and root pages):
  `link-continue` ("Continue to {app}"), `link-back-to-app` ("Back to {app}", static clients only),
  `link-login`, `link-account`, `link-console`, `link-home`, and the sign-out form `form-sign-out`
  with button `sign-out-submit` (a `POST` to the end-session endpoint, which asks for confirmation).
- Check-email page (`message.html`): `message-sent-to` holds the address.
- Error page (`error.html`): `error-label` (text label next to the icon), `error-explanation`
  (friendly explanation per key); `error-message` keeps the contract sentence below byte for byte;
  `error-detail` appears only in development mode.
- Root page (`root.html`): `root-lead`, `link-login`, `link-account`, `form-sign-out` /
  `sign-out-submit`, `link-console` (system tenant), `link-administration` (default tenant).
- Setup: `setup-command` (`console_setup_pending.html`, the `anvilid admin setup-url` command),
  `setup-automation` / `setup-automation-heading` (`setup_done.html`), `link-console`.
- Account header (`account_base.html`, every account page): `account-header`, `account-identity`
  (the signed-in address), `form-sign-out` / `sign-out-submit`, `link-back-to-app`; the navigation
  gains `account-nav-attributes`. Navigation links carry `?client_id=` only for a resolved static
  client. Signing out from the account pages is two steps: the header button, then
  `logout-confirm-submit` on `/ui/logout`.
- Account confirmation (`account_confirm.html`): `account-confirm`, `confirm-heading`,
  `confirm-explain`, form `form-confirm` (`data-action` names the action) with
  `form-confirm-submit`, link `link-confirm-cancel`.
- TOTP enrolment (account and in-flow): `link-otpauth` (opens an authenticator app on the same
  device).
- Consent: `consent-account` / `consent-account-email` (who is signing in), form
  `consent-switch-form` with button `consent-other` ("Use another account", `choice=other`),
  `consent-agent-explain`, `consent-offline-note`. Keyboard order of the buttons: `consent-other`,
  `consent-allow`, `consent-deny`.
- Organization non-member page (`org_not_member.html`): `org-not-member-lead`,
  `org-not-member-account` / `org-not-member-email`, `org-not-member-help`, messages
  `org-not-member-messages` / `org-not-member-msg-{n}`, form `org-not-member-form` with the buttons
  `link-return-to-app` (a `POST` button: returns `access_denied` to the application) and
  `org-not-member-other` ("Use another account").
- Magic link page: `magic-link-explain`, `magic-link-other-browser` (the link was opened in a
  browser without the sign-in), `magic-link-code-hint` (when the tenant emails codes), `link-login`
  ("Start signing in again here", keeps `request=`).
- The first field of a sign-in form has `autofocus`.

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
| `saml_login_failed` (1.0) | Signing in with your organization's identity provider did not work. Go back to the application and start the sign-in again. |
| `server_error` (and any unknown key) | Something went wrong. |

In-page sentence on the login and second-factor forms when an attempt is locked (429 with
`Retry-After`), message key `login.too_many_attempts`: "Too many attempts. Try again in N second(s)."

## Stylesheet classes

Since rc.4 `anvil.css` declares `--anvil-link` (links, outlined buttons, the disclosure summary,
the active navigation bar), `--anvil-card-radius` (cards, panels, callouts, the QR frame) and
`--anvil-font-mono` (codes, secrets) next to `--anvil-success`, `--anvil-text-body`,
`--anvil-text-small` and the spacing scale `--anvil-space-{1,2,3,4,6,8,12,16}`. Orange
(`--anvil-primary`) is a fill only and never a text colour.

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
| `login_code` (0.3) | `tenant_name`, `code`?, `link`?, `expires_minutes` |
| `email_change` (0.3, sent to the new address) | `tenant_name`, `link`, `new_email`, `expires_minutes` |
| `email_changed` (0.3, sent to the old address) | `tenant_name`, `new_email` |
| `org_invitation` (1.0) | `tenant_name`, `org_name`, `inviter`, `email`, `link`, `expires_in` |

Tenants can override these per kind through the management API (`email-templates/{kind}`). An
override is checked when it is saved: valid syntax, only the payload keys above, no `include` /
`extends` of theme files, and a fuel limit on rendering.

`?` marks an optional key. The `login_code` email carries `code` when the tenant's `email_otp` is
on and `link` when `magic_link` is on; at least one of them is always present. Rendering is strict,
so a template must guard each optional key with `is defined` (a bare `{% if code %}` fails when the
key is absent):

```
{% if code is defined %}Your code: {{ code }}{% endif %}
{% if link is defined %}Sign in: {{ link }}{% endif %}
```

The check on save renders an override with code only, link only and both, and refuses one that
uses `code` or `link` unguarded (the error names the key and the line).

In `org_invitation`, `inviter` is a display string (the inviting organization admin's address,
or the tenant's name when a tenant administrator sent it), `email` is the invited address and
`link` is the invitation page (`{issuer}/ui/invitation?token=…`, valid 7 days, single use). The
default templates use every key, and overrides are checked like the other kinds.

`expires_in` is human-readable text such as `1 hour`; `expires_minutes` is a number. No email
reveals whether any other account exists. Emails are not translated in 0.3.

## Overriding the theme

Most branding needs no theme directory: since 0.3 the console (**Branding**) and the management API
set colours (with an optional dark set), font family, corner radius, a logo and custom CSS per tenant
or per client, and since 1.0 per organization, with a live preview. Precedence per field is client >
organization > tenant; the organization layer applies to sign-in pages whose authorization request
names the organization (`organization=`). These are served as the generated stylesheet in
`page.theme_css` (same origin, under the same CSP), and custom CSS is checked by an allow-list
validator (no `url()`, `@import` or external resources).

Custom CSS cannot add fonts: `@font-face` is refused. The font family setting takes a font stack of
fonts the page already has, which means the bundled Hanken Grotesk and IBM Plex Mono or fonts
installed on the visitor's system. A different web font has to be shipped in a theme directory
(`static/`, loaded by an `@font-face` rule in `static/anvil.css`).

The default theme draws links, the focus ring and cards from their own variables (`--anvil-link`,
`--anvil-focus`, `--anvil-card-radius`). So that branded pages keep their look, a customised primary
colour also sets the link colour and, unless the focus colour is customised too, the focus colour; a
customised corner radius also applies to cards. When only one of primary and primary text is
customised, the other keeps the pre-1.0 default (`#2f5bd3` blue / `#ffffff` white in light,
`#6d8ef0` / `#0d1020` in dark), so a branded button never pairs with half of the orange default.

Operators can change the UI further without recompiling. Configure a theme directory with the same
layout as this one (`templates/`, `emails/`, `static/`, `locales/`). At runtime the template loader looks in the operator's
directory first and falls back to these embedded defaults for any file it does not find
(ARCHITECTURE section 10.4), so a theme only needs the files it changes. Typical overrides:

- `static/anvil.css` to change colours and layout. The CSS custom properties at the top of the file
  (`--anvil-primary`, `--anvil-bg`, `--anvil-link`, ...) are the easiest place to start. The default
  palette is orange buttons with dark text; orange is never used as a text colour (links and focus
  use `--anvil-link` and `--anvil-focus`).
- `templates/base.html` to change the page frame.
- Individual email templates to change wording.
- `locales/{lang}/*.ftl` to change single page sentences or add a language (see Translations).

Overridden templates must keep the selector and text contract above, and they are subject to the
same ground rules: the Content-Security-Policy blocks inline and third-party scripts, inline styles
and external assets.
