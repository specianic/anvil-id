# Native apps with your own login screen

A first-party mobile or desktop app can sign users in with its own screens, without opening a
browser, through the [headless flow API](../HEADLESS.md) in **native mode**. The app pushes an
authorization request with PKCE, drives the login steps with a one-time flow token, receives the
authorization code as JSON and redeems it at the token endpoint.

Native mode is AnvilID's own API. Its shape follows the IETF Internet-Draft "OAuth 2.0 for
First-Party Applications", which is a draft and not an RFC; AnvilID claims no conformance to it.

## First-party apps only

Only use native mode for an app you publish yourself, for your own users. A third-party app must
never collect a user's password: it would see credentials meant for AnvilID, and users could not
tell a genuine app from a phishing one. Third-party apps, and first-party apps that do not need
their own login screen, use the browser as RFC 8252 describes: the system browser (never an
embedded web view), a claimed `https` redirect URI, a private-use URI scheme or a loopback
redirect, and PKCE. That is a normal authorization code flow with a public client, as in the
[web application guide](oidc-app.md).

AnvilID enforces this: only a client registered by an administrator with all of the following can
start a native flow:

| Client field | Value |
| --- | --- |
| `headless_native` | `true` (admin API, console or tenant YAML; never through dynamic registration or a metadata document) |
| `consent_mode` | `skip_first_party` |
| `require_pkce` | `true` |
| `client_kind` | `application` (never `agent`) |
| `grant_types` | includes `authorization_code` |

```sh
curl -sS -X POST "https://id.example.com/api/admin/v1/tenants/default/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name": "Example mobile app",
    "client_type": "public",
    "application_type": "native",
    "redirect_uris": ["com.example.app:/callback"],
    "consent_mode": "skip_first_party",
    "require_pkce": true,
    "headless_native": true,
    "scopes": ["openid", "profile", "email"]
  }'
```

The redirect URI is still needed: the pushed request names it, and the browser fallback below
delivers the code there.

## Sign-in sequence

1. **Push the authorization request** to `{issuer}/par` ([PAR](../PAR.md)) with a PKCE challenge.
   A public client sends its `client_id` in the body:

   ```sh
   curl -sS https://id.example.com/par \
     -d response_type=code -d client_id="$CLIENT_ID" \
     -d redirect_uri=com.example.app:/callback \
     -d scope="openid profile email" -d state="$STATE" -d nonce="$NONCE" \
     -d code_challenge="$CHALLENGE" -d code_challenge_method=S256
   # 201 {"request_uri":"urn:ietf:params:oauth:request_uri:...","expires_in":60}
   ```

2. **Start the flow** with `POST {issuer}/api/flows/v1/login` and the body
   `{"client_id": "...", "request_uri": "urn:ietf:params:oauth:request_uri:..."}`. The answer is
   the first form plus `flow_token`, returned only here. The `request_uri` is used up.

3. **Submit the steps** to `POST {issuer}/api/flows/v1/login/{flow_id}` with the header
   `Authorization: AnvilFlow <flow_token>`:

   ```json
   {"method": "password", "values": {"identifier": "alice@example.com", "password": "..."}}
   ```

   Render each form the server describes (second factor, email code, ...) and send hidden fields
   such as `factor_token` back unchanged. `GET` on the same path returns the current step again.

4. **Completion** is `step: "completed"` with `result.code`, `result.iss` and `result.state`.
   Check that `iss` is your issuer and `state` is yours, then redeem the code:

   ```sh
   curl -sS https://id.example.com/token \
     -d grant_type=authorization_code -d code="$CODE" -d client_id="$CLIENT_ID" \
     -d redirect_uri=com.example.app:/callback -d code_verifier="$VERIFIER"
   ```

   The code works once and for 60 seconds. If the authorization ends with an OAuth error (for
   example `access_denied`), the answer has status 400 and `result.error` instead of a code.

## Handling the flow token

- Keep it in memory for the sign-in only (at most 15 minutes). Do not store it, put it in a URL
  or log it.
- Do not send `Origin` or `Sec-Fetch-Site` headers. Requests with browser signals are refused
  with 403 `browser_signals`, so a web page cannot use native mode. Native HTTP clients normally
  do not send them.
- A missing or malformed token is 401 `flow_token`; a wrong token is 403 `flow_token`. An expired
  flow is 404 `flow_not_found`: push a new request and start again.

## Falling back to the browser (`browser_required`)

Some steps need a browser. The answer is then `step: "browser_required"` with `url`, the
authorization URL of the same request. Open it in the **system browser** (RFC 8252, not an
embedded web view). The user finishes there and the code arrives at your redirect URI, to be
redeemed with the same `code_verifier`. This happens for:

- a CAPTCHA demand after repeated failed attempts;
- social, OIDC, SAML and enterprise single sign-on;
- registration (`prompt=create`);
- anything after sign-in that needs a page: consent, account or organization choice, step-up.

Passkeys and emailed sign-in links are not offered in native mode, because they need the AnvilID
origin in a browser. Use the browser flow for passkeys.

## Sessions

Native sign-in sends no session cookie, so it creates no single sign-on for any browser. The
server still records a session row for the sign-in, because authorization codes and token families
are anchored to one (session revocation and back-channel logout work as usual). Its cookie secret
never leaves the server.

All error codes are listed in [Headless flow API: native mode errors](../HEADLESS.md#native-mode-errors).
