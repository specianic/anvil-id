# Pushed authorization requests (PAR)

AnvilID implements pushed authorization requests as defined in RFC 9126, with the client
assertion audience rule of RFC 10070. Instead of putting its authorization parameters in the
browser's address bar, the client sends them to the PAR endpoint over an authenticated back
channel. It gets a short-lived, one-time `request_uri` back and redirects the user to
`/authorize` with only `client_id` and that `request_uri`.

Benefits: the parameters cannot be tampered with in the browser, they are not leaked through
browser history or referrers, they are validated before the user is redirected, and the client
is authenticated before any user interaction.

## Endpoint

`POST {issuer}/par`. The issuer is the tenant's issuer, for example `https://id.example.com` for
the default tenant or `https://id.example.com/t/acme` for a path tenant.

- Body: `application/x-www-form-urlencoded`. It holds the authorization request parameters you
  would otherwise put on `/authorize` (`response_type`, `redirect_uri`, `scope`, `state`,
  `nonce`, `code_challenge`, `code_challenge_method`, `prompt`, `max_age`, `claims`, `resource`,
  `organization`, ...), plus the client authentication.
- Client authentication follows the token endpoint rules exactly (one implementation is shared
  with `/token`): `client_secret_basic`, `client_secret_post`, `private_key_jwt`, or `none` for
  public clients (which must use PKCE). The method must be the client's registered method.
- Success: `201 Created`, `Cache-Control: no-store`:

  ```json
  {
    "request_uri": "urn:ietf:params:oauth:request_uri:Wm1yX2Zx...43 base64url characters",
    "expires_in": 60
  }
  ```

- Errors are JSON in the RFC 6749 §5.2 shape (`{"error": "...", "error_description": "..."}`),
  never redirects. Client authentication failures are `401 invalid_client` (with
  `WWW-Authenticate: Basic` when HTTP Basic was used). Everything else is `400`, usually
  `invalid_request`.
- The parameters are validated exactly as `/authorize` validates them. Interaction errors
  (`login_required`, `consent_required`, ...) never come from `/par`: no session is involved
  there, so `prompt=none` is decided later at `/authorize`.
- Rate limiting: the endpoint is in the same class as `/token`. It has no CORS: call it from your
  back end.

Then redirect the browser to:

```
{issuer}/authorize?client_id=<client_id>&request_uri=<request_uri>
```

### Example

```sh
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d response_type=code \
  -d redirect_uri=https://app.example.com/callback \
  -d scope="openid profile" \
  -d state="$STATE" -d nonce="$NONCE" \
  -d code_challenge="$CHALLENGE" -d code_challenge_method=S256 \
  https://id.example.com/par
```

The code is redeemed at `/token` as usual, with the PKCE `code_verifier` and the client's
authentication.

## Refused parameters

| Parameter in the pushed body | Answer |
|---|---|
| `request_uri` | `invalid_request` (a pushed request cannot reference another one) |
| `request` (request object, JAR) | `request_not_supported` |
| `id_token_hint` | `invalid_request` (the hint is not stored with pushed requests; send it on a plain `/authorize` request) |
| a `client_id` other than the authenticated client | `invalid_client` |

## The request_uri

- Format: `urn:ietf:params:oauth:request_uri:` followed by 43 base64url characters (32 random
  bytes). Only its SHA-256 hash is stored; the value itself is never stored or logged.
- Lifetime: 60 seconds (`expires_in`). Redirect the user right after pushing.
- **Strict single use.** The pushed request is consumed atomically the first time `/authorize`
  sees it; exactly one of several concurrent uses wins. A browser reload of the
  `/authorize?request_uri=...` page therefore gets an error page. RFC 9126 says the server SHOULD
  treat the `request_uri` as one-time use and MAY allow reloads; we choose not to. If the user
  needs to start again, push a new request.
- **Bound to the client.** The `client_id` on `/authorize` must be the client that pushed the
  request. A mismatch uses the request up, so a leaked `request_uri` cannot be retried.
- An unknown, expired, already used or mismatched `request_uri` shows an error page and never
  redirects, because at that point there is no trusted redirect URI.
- Expired rows are deleted by the regular cleanup job.

## At /authorize

- Only `client_id` and `request_uri` are read from the query. **Every other front-channel
  parameter is ignored**; the pushed parameters are the request (RFC 9126 §4).
- The client's current registration is checked again before the request continues (RFC 9126
  §7.4): the client must still exist, the pushed redirect URI must still be registered, the code
  grant and PKCE requirements must still hold, scopes the client may no longer use are dropped
  (`openid` must remain), resource indicators and the organization parameter must still be
  allowed. A redirect URI that is no longer registered gives an error page; other failures are
  delivered to the redirect URI.
- After that the request continues exactly like any other: login, consent, account chooser,
  organization switcher, step-up and the response mode all work unchanged.
- A `request_uri` that does not start with `urn:ietf:params:oauth:request_uri:` is a request
  object by reference. Those are not supported and keep answering `request_uri_not_supported`.

## Client assertion audience

For `private_key_jwt`, the assertion's `aud` must be the issuer, and only the issuer. RFC 10070
made the issuer the sole permitted audience for client assertions; assertions with the PAR
endpoint URL or the token endpoint URL as `aud` are refused at `/par` as at `/token`. Assertion
`jti`s are recorded in the same replay store as `/token`: an assertion used at one endpoint is
refused at the other.

## Exact redirect URI matching

The pushed `redirect_uri` must match one of the client's registered redirect URIs exactly (the
same rule as `/authorize`, including the loopback port rule for native clients). RFC 9126 §2.4
allows an authorization server to accept unregistered redirect URIs from authenticated clients;
AnvilID deliberately does not.

## Requiring PAR

- **Per client:** the client metadata `require_pushed_authorization_requests` (RFC 9126 §6).
  When it is `true`, a plain `/authorize` request (parameters on the front channel) from that
  client is refused with `invalid_request`: delivered to the redirect URI when the redirect URI
  is valid, otherwise the error page.
- **Per tenant:** the tenant setting `par.require_pushed_authorization_requests`. When it is on,
  every client of the tenant must use PAR, and discovery advertises
  `require_pushed_authorization_requests: true`.

Both default to off.

## Discovery

The OpenID Provider and authorization server metadata include:

| Field | Value |
|---|---|
| `pushed_authorization_request_endpoint` | `{issuer}/par` |
| `require_pushed_authorization_requests` | the tenant setting (default `false`) |
| `request_uri_parameter_supported` | `false` |

`request_uri_parameter_supported` stays `false`: in OpenID Connect that flag means request
objects passed by reference, which AnvilID never fetches. Pushed requests are advertised only
through the RFC 9126 fields.
