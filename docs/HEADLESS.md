# Headless flow API

The headless flow API lets your own client drive a tenant's login, registration, recovery and
verification flows with JSON instead of the built-in pages. It runs the same flow engine as the
built-in pages, with the same brute-force limits, CAPTCHA, flow binding and sessions. It is a
second renderer: the server describes each step (fields, messages, ways to sign in) and your
client renders it.

- Contract: [`docs/openapi/flows-v1.json`](openapi/flows-v1.json) (OpenAPI 3.1, generated from the
  handlers and checked by a drift test).
- Version: `v1`, in the path (`/api/flows/v1`).
- Supported clients: single-page apps in the browser ("browser mode", below). Native apps are
  covered in [Native apps](#native-apps).

## Endpoints

Paths are relative to the tenant base: `/t/{slug}` for a path tenant, the root for the default
tenant, or the tenant's own host. `{kind}` is `login`, `registration`, `recovery` or
`verification`.

| Method and path | Purpose |
|---|---|
| `POST /api/flows/v1/{kind}` | Start a flow. Body (all optional): `request` (the authorization request id from the sign-in redirect `…/ui/login?request=…`), `token` (verification and recovery: the token from the emailed link). Sets the flow cookie. |
| `GET /api/flows/v1/{kind}/{flow_id}` | The current step again (without one-time values; keep the hidden fields from the answer that produced the step). |
| `POST /api/flows/v1/{kind}/{flow_id}` | Submit the current step. |
| `POST /api/flows/v1/login/{flow_id}/passkey/options` | Passkey sign-in: WebAuthn request options (JSON for `PublicKeyCredential.parseRequestOptionsFromJSON`). |
| `POST /api/flows/v1/login/{flow_id}/passkey` | Passkey sign-in: `{"response": PublicKeyCredential.toJSON()}`. |
| `POST /api/flows/v1/login/{flow_id}/enroll/passkey/start` and `…/finish` | Passkey at the enrolment step (MFA policy `required`). |
| `POST /api/flows/v1/login/{flow_id}/second-factor/passkey/start` and `…/finish` | Passkey as the second factor. |

Add `?ui_locales=de` (space-separated tags) to any request to get display texts (`label`, `text`)
in that locale, from the same catalogs as the built-in pages. Without it, only keys are returned.

## Responses

Every answer that is not an error is a `FlowResponse`:

```json
{
  "flow": { "id": "0192…", "kind": "login", "expires_at": "2026-11-25T12:15:00Z" },
  "step": "form",
  "csrf_token": "…",
  "form": {
    "id": "login",
    "fields": [
      { "name": "identifier", "kind": "email", "label_key": "field.email", "required": true,
        "autocomplete": "username", "messages": [] },
      { "name": "password", "kind": "password", "label_key": "field.password", "required": true,
        "autocomplete": "current-password", "messages": [] }
    ],
    "messages": [],
    "methods": [ { "kind": "password" }, { "kind": "passkey" } ]
  }
}
```

`step` is one of:

| `step` | Meaning |
|---|---|
| `form` | Render `form` and submit it. `form.id` names the step: `login`, `login-identify` (email first), `login-sso-choice`, `second-factor`, `mfa-enroll` (with `form.totp`), `email-code`, `registration`, `recovery`, `recovery-reset`, `verification`. |
| `message` | The flow finished with `message` (for example "check your email"). |
| `completed` | Signed in (or stepped up). The session cookie is set on the AnvilID origin. Navigate the top-level window to `result.continue_to`. Show `result.recovery_codes` first if present. |
| `browser_required` | Navigate the top-level window to `url`, the built-in sign-in page. Social, OIDC, SAML and enterprise single sign-on need top-level redirects and the provider's callback, so the built-in pages finish them. |

`result.continue_to` is an absolute URL on the AnvilID origin, for an authorization request
`{issuer}/authorize/continue?request=…`. Following it issues the authorization code to the
relying party exactly as after a sign-in on the built-in page.

Fields carry `label_key` and messages carry `key` plus `args`. A field's `value` is a prefill and
is never present for `password` fields. Hidden fields (for example `factor_token` on the
second-factor, enrolment and email-code steps) must be submitted back unchanged.

### Submitting

```json
{ "method": "password", "values": { "identifier": "alice@example.com", "password": "…" } }
```

`values` holds the form's field values by name. `method` defaults to `password` (login),
`register` (registration), `verify` (verification), and `recovery_reset` when `values.token` is
present, else `recovery_request` (recovery). Other login methods:

| `method` | Values |
|---|---|
| `identify` | `identifier`; on `login-sso-choice` also `choice` = `sso`, `password` or `change` |
| `totp` | `code`, `factor_token` (second factor and enrolment confirmation) |
| `recovery_code` | `recovery_code`, `factor_token` |
| `email_code_request` | `email` (or only `factor_token` for a new email) |
| `email_code` | `code`, `factor_token` |
| `upstream` | `slug` (answers `browser_required`) |

When `form.captcha` is present, the next submission must include the widget response:
`"captcha": {"turnstile": "…"}` or `{"hcaptcha": "…"}`.

## Versioning rules

- Additions are not breaking and stay in `v1`: new response fields, new `step` values, new form
  ids, new field kinds, new method kinds, new message keys and new problem codes.
- Clients must ignore unknown fields, steps and methods. A field `kind` of `unknown` (or any kind
  you do not know) is not rendered and gets no value.
- Removing or renaming anything, or changing a meaning, requires a new version (`/api/flows/v2`).
- The internal form description of the engine is never part of the contract.

## Browser mode (single-page apps)

Browser mode keeps the built-in pages' CSRF model.

1. **Same-site with the issuer.** The SPA must be on the same site as AnvilID (for example
   `https://app.example.com` and `https://id.example.com`, or two ports of one host). The flow and
   session cookies live on the AnvilID origin and are `SameSite`. Browsers block third-party cookies
   on cross-site requests, so a cross-site SPA cannot use browser mode.
2. **Exact-origin allow-list.** Add the SPA's origin to the tenant setting
   `headless.allowed_origins`. Entries are exact origins (`https://host[:port]`, lowercase, no
   path, no wildcard; `http://localhost` and `http://127.0.0.1` only in development mode).
   Requests are admitted from the tenant's own origin and from listed origins only. Anything else
   gets 403 `forbidden_origin`, including a browser request without `Origin` that is not
   same-origin.
3. **Credentialed CORS for listed origins only.** Listed origins get
   `Access-Control-Allow-Origin: <that origin>`, `Access-Control-Allow-Credentials: true`,
   `Vary: Origin`, methods `GET` and `POST`, request headers `Content-Type` and `X-CSRF-Token`.
   The API never answers `*`. Requests and preflights from other origins get no
   `Access-Control-Allow-Origin`, so the browser withholds the answer.
4. **CSRF header.** The start answer returns `csrf_token`. Send it in the `X-CSRF-Token` header
   with every later request about the flow, with `credentials: "include"` so the flow cookie goes
   along. A missing or wrong token, or a missing flow cookie, is 403 `csrf`. The custom header
   also forces a CORS preflight.
5. **JSON only.** `POST` bodies must be `Content-Type: application/json`, otherwise 415
   `unsupported_media_type`. HTML forms cannot send JSON, so a cross-site form cannot submit to the
   API.

The built-in pages keep their own, unchanged Fetch-Metadata protection: allow-listing an origin
for the API never admits it on `/ui/*`.

Example:

```js
const api = 'https://id.example.com/t/acme/api/flows/v1';
let flow, csrf;
async function call(path, body) {
  const headers = { 'content-type': 'application/json' };
  if (csrf) headers['x-csrf-token'] = csrf;
  const res = await fetch(api + path, {
    method: 'POST', credentials: 'include', headers, body: JSON.stringify(body),
  });
  const answer = await res.json();
  if (answer.csrf_token) csrf = answer.csrf_token;
  if (answer.flow) flow = answer.flow;
  return answer;
}
let answer = await call('/login', { request });        // render answer.form
answer = await call(`/login/${flow.id}`, {
  method: 'password', values: { identifier, password },
});
if (answer.step === 'completed') location.assign(answer.result.continue_to);
```

A runnable fixture is in `tests/e2e/fixtures/headless-spa/`.

## CAPTCHA

The API uses the tenant's CAPTCHA exactly like the built-in sign-in page. After repeated failed
attempts for an identifier, a form comes back with `form.captcha: {provider, site_key}`. Render the
provider's widget with that site key and send its response in `captcha`. The server verifies it
before it looks at the password. Without a response the answer is 403 `captcha_required`, and with
a response the provider refuses it is 403 `captcha_failed`. Both carry `captcha` again.

## Rate limits and locks

The per-IP route limit treats every `POST` below `/api/flows` as an authentication request. Its
429 is a JSON problem with `Retry-After`.

Failed sign-ins count against the same limiter keys as the built-in pages: failures through the API
lock the built-in page for the same identifier, and the other way round. A locked password or
passkey step answers 429 with the form, a `login.too_many_attempts` message, `retry_after` and
`Retry-After`. A locked second-factor or email-code step answers 429 `too_many_requests`.

## Errors

Errors are RFC 9457 problems (`application/problem+json`) with a stable `code`:

| Status | `code` |
|---|---|
| 400 | `invalid_request` (malformed JSON or ids), `method_not_available` (a method of another flow kind), `invalid_flow_state` (the step does not accept this submission, or a binding token does not open; start a new flow), `passkey_failed` |
| 403 | `forbidden_origin`, `csrf`, `registration_disabled`, `captcha_required`, `captcha_failed` |
| 404 | `not_found` (unknown kind or path), `method_not_available` (email sign-in is off for the tenant), `flow_not_found` (unknown or expired flow on `GET`) |
| 415 | `unsupported_media_type` |
| 429 | `too_many_requests` |
| 500 | `server_error` |

A form answer with an error message (wrong credentials, validation) is a `FlowResponse` with
status 400, not a problem. A submission to an expired flow starts a new one: the answer carries
the new `flow.id` and `csrf_token` and the message `flow.expired`.

## Native apps

Covered by a later release step (plan 07-18).
