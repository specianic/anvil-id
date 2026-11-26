# Connecting a web application (OpenID Connect)

This guide connects a server-side web application to AnvilID with the OpenID Connect
authorization code flow and PKCE. Any certified OpenID Connect client library works; the
[sample relying party](https://github.com/specianic/anvil-id/blob/main/examples/node-rp/README.md)
in the repository shows a complete Node.js example.

## 1. Find the issuer

Every tenant has its own issuer:

| Tenant | Issuer |
| --- | --- |
| `default` | `https://id.example.com` |
| any other, path-based | `https://id.example.com/t/<slug>` |
| a tenant with its own host | `https://<tenant host>` |

The discovery document is at `{issuer}/.well-known/openid-configuration`. Configure your library
with the issuer and let it read the endpoints from discovery rather than hard-coding them.

## 2. Register the client

In the admin console (**Clients**, then **New client**) or through the management API, create a
confidential web client:

```sh
curl -sS -X POST "https://id.example.com/api/admin/v1/tenants/default/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name": "Example app",
    "client_type": "confidential",
    "redirect_uris": ["https://app.example.com/callback"],
    "post_logout_redirect_uris": ["https://app.example.com/signed-out"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email"]
  }'
```

The answer contains `client_id` and, once only, `client_secret`. The token endpoint
authentication method defaults to `client_secret_basic`; `client_secret_post` and
`private_key_jwt` (with an inline `jwks`) are available too. An `$ADMIN_TOKEN` comes from the
management client created at setup (client credentials grant at `/t/system/token` with scope
`admin:write`, or a narrower `admin:clients:write`).

Redirect URIs must match a registered value exactly.

## 3. Sign the user in

1. Generate `state`, `nonce` and a PKCE `code_verifier`; derive the `S256` `code_challenge`.
2. Redirect the browser to the `authorization_endpoint` with `response_type=code`, `client_id`,
   `redirect_uri`, `scope=openid profile email`, `state`, `nonce`, `code_challenge` and
   `code_challenge_method=S256`. PKCE with `S256` is the only supported method; send it for
   confidential clients too.
3. AnvilID signs the user in (password, passkey, second factor, upstream providers, whatever the
   tenant enables) and shows the consent screen if needed.
4. The browser returns to your `redirect_uri` with `code`, `state` and `iss`. Check that `state`
   is yours and that `iss` equals the issuer (RFC 9207).
5. Exchange the code at the `token_endpoint` with `grant_type=authorization_code`, `code`,
   `redirect_uri` and `code_verifier`, authenticated as the client. Codes are single use and
   short-lived.
6. Validate the ID token as OpenID Connect requires (signature from `jwks_uri`, `iss`, `aud`,
   `exp`, `nonce`). Your library does this.

Optional parameters: `prompt` (`none`, `login`, `consent`, `select_account`, and `create` when
registration is open), `max_age`, `login_hint`, `acr_values` (`urn:anvilid:acr:mfa` asks for a
second factor), `ui_locales`, `response_mode=form_post`, `resource` (RFC 8707) and
`organization` (see [Organizations](../ORGANIZATIONS.md)).

## 4. Keep the session

- **Refresh tokens rotate.** Each refresh returns a new refresh token and consumes the old one.
  Always store the newest one. Presenting a refresh token that was already used revokes the whole
  token family, because it means the token was copied.
- **Access tokens** are JWTs (RFC 9068) by default, valid for 10 minutes. A client can be set to
  opaque tokens (`token_format: opaque`); resource servers then use `/introspect`.
- **UserInfo** is at the `userinfo_endpoint`.

## 5. Sign the user out

- **RP-initiated logout:** redirect to the `end_session_endpoint` with `id_token_hint`,
  `post_logout_redirect_uri` (registered exactly) and `state`.
- **Back-channel logout:** register a `backchannel_logout_uri` on the client. AnvilID posts a
  signed `logout_token` to it when the user's session ends, so you can end your own session.

## Optional: pushed authorization requests

With [PAR](../PAR.md) your back end sends the authorization parameters to `{issuer}/par` (the
`pushed_authorization_request_endpoint`), authenticated like at the token endpoint, and redirects
the browser with only `client_id` and the returned `request_uri`:

```sh
curl -sS -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d response_type=code -d redirect_uri=https://app.example.com/callback \
  -d scope="openid profile email" -d state="$STATE" -d nonce="$NONCE" \
  -d code_challenge="$CHALLENGE" -d code_challenge_method=S256 \
  https://id.example.com/par
# {"request_uri":"urn:ietf:params:oauth:request_uri:...","expires_in":60}
```

```
https://id.example.com/authorize?client_id=<client_id>&request_uri=<request_uri>
```

The `request_uri` works once and for 60 seconds. To make PAR mandatory, set
`require_pushed_authorization_requests: true` on the client, or the tenant setting
`par.require_pushed_authorization_requests` for every client.

## Troubleshooting

- An error page instead of a redirect means AnvilID could not trust the redirect URI (unknown
  client, unregistered `redirect_uri`, or an unusable `request_uri`). Errors after that point are
  sent to the redirect URI as `error` and `error_description`.
- `invalid_grant` at the token endpoint: the code was already used or expired, or the
  `code_verifier` or `redirect_uri` does not match.
- The audit log (console **Audit log**, or `GET /api/admin/v1/tenants/{slug}/audit-events`)
  records sign-ins, consents and token failures.
