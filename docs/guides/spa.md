# Single-page apps with your own login screen

A single-page app (SPA) can render its own sign-in screen and drive AnvilID's login flow through
the [headless flow API](../HEADLESS.md) in **browser mode**, then get tokens with a normal
authorization code request with PKCE. The flow engine, brute-force limits, CAPTCHA and sessions
are the same as on the built-in pages.

If you do not need your own login screen, skip the headless API: redirect to `/authorize` and let
AnvilID's built-in pages sign the user in, as in the [web application guide](oidc-app.md) (with a
public client and PKCE).

## Requirements

- **Same site as AnvilID.** The SPA must be on the same site as the issuer, for example
  `https://app.example.com` with `https://id.example.com`. The flow and session cookies live on
  the AnvilID origin; browsers block them on cross-site requests, so a cross-site SPA cannot use
  browser mode.
- **The SPA's origin is allow-listed** in the tenant setting `headless.allowed_origins` (exact
  origins, `https://host[:port]`, no path, no wildcard). `http://localhost` and
  `http://127.0.0.1` origins are accepted only in development mode.
- **A public client** with PKCE for the token request.

## 1. Configure the tenant and the client

Allow the SPA's origin (console tenant settings, tenant YAML `tenant.settings.headless`, or the
management API):

```sh
curl -sS -X PATCH "https://id.example.com/api/admin/v1/tenants/default" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"settings": {"headless": {"allowed_origins": ["https://app.example.com"]}}}'
```

Register a public client:

```sh
curl -sS -X POST "https://id.example.com/api/admin/v1/tenants/default/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name": "Example SPA",
    "client_type": "public",
    "redirect_uris": ["https://app.example.com/callback"],
    "consent_mode": "skip_first_party",
    "scopes": ["openid", "profile", "email"]
  }'
```

`consent_mode: skip_first_party` is for your own app only; leave the default (`required`) if the
consent screen should appear.

## 2. Sign the user in through the API

Every call goes to `{issuer}/api/flows/v1` with `credentials: "include"`, a JSON body, and, after
the first answer, the `X-CSRF-Token` header:

```js
const issuer = 'https://id.example.com';
const api = `${issuer}/api/flows/v1`;
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

let answer = await call('/login', {});                // render answer.form
answer = await call(`/login/${flow.id}`, {
  method: 'password', values: { identifier: email, password },
});
// answer.step: "form" (render the next step or the error messages), "completed",
// "message" or "browser_required"
```

- Render `answer.form` from its description: fields with `name`, `kind`, `label_key` (or `label`
  with `?ui_locales=`), `messages`, and the available `methods`. Ignore field kinds, steps and
  methods you do not know.
- Hidden fields (such as `factor_token` on the second-factor step) go back unchanged.
- When `form.captcha` is present, render the provider's widget and send its response as
  `captcha`.
- `step: "browser_required"`: navigate the top-level window to `answer.url`. Social, OIDC, SAML
  and enterprise single sign-on need full-page redirects, so the built-in pages finish them.

On `step: "completed"`, the session cookie is set on the AnvilID origin.

## 3. Get tokens

Now run an authorization code request with PKCE as a **top-level navigation** (not `fetch`):

```js
location.assign(`${issuer}/authorize?` + new URLSearchParams({
  response_type: 'code', client_id, redirect_uri: 'https://app.example.com/callback',
  scope: 'openid profile email', state, nonce,
  code_challenge, code_challenge_method: 'S256',
  prompt: 'none',
}));
```

The browser already has the session, so AnvilID redirects straight back to the redirect URI with
`code`, `state` and `iss`. With `prompt=none` it never shows a page: if the session is missing,
or consent is needed, the redirect carries `error=login_required` or `consent_required` instead.
Exchange the code at `{issuer}/token` with `fetch` (the token endpoint allows cross-origin
requests without credentials):

```js
const res = await fetch(`${issuer}/token`, {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code', code, client_id,
    redirect_uri: 'https://app.example.com/callback', code_verifier,
  }),
});
```

### When you already have an authorization request

If the user arrived from an authorization request (the built-in sign-in page URL carries it as
`…/ui/login?request=<id>`), pass it when starting the flow: `call('/login', { request })`. On
completion, `answer.result.continue_to` is an absolute URL on the AnvilID origin
(`{issuer}/authorize/continue?request=…`); navigate the top-level window there and the code
redirect follows.

## Security rules the API enforces

- Requests from origins that are not allow-listed (and not the tenant's own origin) get 403
  `forbidden_origin`, and their CORS answers carry no `Access-Control-Allow-Origin`.
- A missing or wrong `X-CSRF-Token`, or a missing flow cookie, is 403 `csrf`.
- `POST` bodies must be `application/json` (415 otherwise), so an HTML form on another site
  cannot submit to the API.
- Failed sign-ins count against the same limits as the built-in pages.

All endpoints, steps and error codes are in [Headless flow API](../HEADLESS.md); the contract is
[`docs/openapi/flows-v1.json`](../openapi/flows-v1.json).
