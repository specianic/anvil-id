# AnvilID default theme

This directory holds the built-in login UI: page templates, email templates and the stylesheet. The
files are embedded in the `anvilid` binary at compile time, so the UI works with no external assets,
no JavaScript and no network access (requirement UI-01).

```
themes/default/
  templates/   page templates (minijinja, auto-escaped because of the .html extension)
  emails/      email templates (.txt plain text and .html variants)
  static/      anvil.css, served under the page's asset base
```

## Ground rules

- No `<script>`, no inline `style` attributes, no inline event handlers (`onclick=` and friends) and
  no absolute URLs to any host. The strict Content-Security-Policy that the server sends would block
  them anyway, and a test scans rendered HTML for them.
- No web fonts, `@import` or `url()` pointing at external hosts in CSS.
- No favicon link: some browsers fetch it from outside the asset base.
- Every flow works without JavaScript. Forms are plain `POST` forms.
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

Form pages (`login.html`, `registration.html`, `verification.html`, `recovery.html`,
`recovery_reset.html`, `setup.html`) also receive `form`, a serialised `FormDescription` from
`anvil-core` (`flow/form.rs`):

```
form = {
  id:         "login" | "registration" | "recovery" | "recovery-reset" | "verification" | "setup",
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

Error sentences in `error.html`, keyed by `error_key`:

| `error_key` | Sentence |
|---|---|
| `redirect_uri_mismatch` | The redirect URI in this request is not registered for this client. |
| `unknown_client` | This application is not registered. |
| `invalid_request` | The sign-in request is invalid. |
| `flow_expired` | This sign-in attempt expired. Please start again. |
| `csrf` | This form submission could not be verified. Please try again. |
| `not_found` | Page not found. |
| `server_error` (and any unknown key) | Something went wrong. |

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
same ground rules: the Content-Security-Policy blocks scripts, inline styles and external assets.
