# Sample relying party (Node.js)

A minimal OpenID Connect relying party for AnvilID, built with Express 5 and
[openid-client](https://github.com/panva/openid-client) 6. It uses the authorization code flow
with PKCE (S256), `state` and `nonce`. It shows the signed-in user's `sub` and `email` from
UserInfo and can refresh its tokens. AnvilID rotates refresh tokens, and the RP always stores
the newly issued one. It also supports RP-initiated logout and back-channel logout.

The end-to-end tests in `tests/e2e` use this RP. openid-client checks the ID token, `iss`,
`nonce` and PKCE strictly, so the RP also tests AnvilID's provider behaviour.

## Requirements

- Node.js 20 or newer
- A running AnvilID (`anvilid serve`)

## Run it against `anvilid serve`

1. Start AnvilID and finish first-run setup at the printed `Setup URL`.
2. Register a confidential web client in the `default` tenant (admin UI or admin API) with:
   - redirect URI `http://localhost:3000/callback`
   - grant types `authorization_code` and `refresh_token`
   - scopes `openid profile email`
   - token endpoint auth method `client_secret_basic`
   - for logout (optional): post-logout redirect URI (`post_logout_redirect_uris`)
     `http://localhost:3000/logged-out` and back-channel logout URI (`backchannel_logout_uri`)
     `http://localhost:3000/backchannel_logout`
3. Install and start the RP:

   ```sh
   cd examples/node-rp
   npm ci
   ISSUER=http://localhost:8080 \
   CLIENT_ID=<client id> \
   CLIENT_SECRET=<client secret> \
   npm start
   ```

4. Open <http://localhost:3000>, choose **Log in**, sign in on AnvilID and you land on `/me`.
   Choose **Refresh tokens** to run a refresh-token grant.

The whole sequence (zero-config container, setup, client registration, sign-up through this RP,
UserInfo and a refresh) is automated by `scripts/qual04.sh sqlite|postgres` (`just qual04`).

## Configuration

| Variable         | Required | Default                    | Meaning                                         |
|------------------|----------|----------------------------|-------------------------------------------------|
| `ISSUER`         | yes      |                            | Issuer URL of the AnvilID tenant (`http://localhost:8080` for the `default` tenant, `http://localhost:8080/t/<slug>` for others) |
| `CLIENT_ID`      | yes      |                            | Client id                                       |
| `CLIENT_SECRET`  | yes      |                            | Client secret (sent with `client_secret_basic`) |
| `PORT`           | no       | `3000`                     | Listen port                                     |
| `BASE_URL`       | no       | `http://localhost:$PORT`   | External base URL; redirect URI is `$BASE_URL/callback` |
| `SESSION_SECRET` | no       | random at each start       | Key that signs the session cookie               |

Plain-http issuers are accepted only when the issuer host is `localhost` or `127.0.0.1`
(local development). Every other issuer must use https.

## Routes

| Route       | Purpose                                                        |
|-------------|----------------------------------------------------------------|
| `/`         | Login link, or the signed-in user                              |
| `/login`    | Starts the authorization code + PKCE flow                      |
| `/callback` | Redirect URI: exchanges the code, validates the ID token, calls UserInfo |
| `/me`       | Shows `sub`, `email` and the refresh count                     |
| `/refresh`  | Runs a refresh-token grant, stores the rotated refresh token, calls UserInfo again |
| `/logout`   | RP-initiated logout: forgets the local login and redirects to the provider's `end_session_endpoint` with `id_token_hint`, `post_logout_redirect_uri` and a fresh `state` |
| `/logged-out` | Post-logout redirect URI: checks `state` and shows "Signed out of the sample app" |
| `POST /backchannel_logout` | Back-channel logout URI: verifies the `logout_token` (see below), ends the matching local sessions, answers 200 (400 without detail on any failure) |
| `/backchannel_logout/received` | Debugging endpoint for the sample: JSON list of accepted logout tokens (`sub`, `sid`, `jti`, `received_at`), filtered by `?sub=` |
| `/healthz`  | Returns `ok`                                                   |

## Logout

Register both logout values on the client to try them:

| Client metadata          | Value for the default setup                    |
|--------------------------|------------------------------------------------|
| `post_logout_redirect_uris` | `["$BASE_URL/logged-out"]`                  |
| `backchannel_logout_uri` | `$BASE_URL/backchannel_logout`                 |

The back-channel endpoint verifies the logout token against the issuer's JWKS with `node:crypto`:
signature (RS256, PS256, ES256 or Ed25519, as advertised by the issuer; never `none` or HMAC),
`typ` `logout+jwt` if present, `iss`, `aud` containing the client id, `iat` no older than five
minutes, the back-channel logout event in `events`, no `nonce`, `sub` or `sid` present, and a
`jti` it has not seen before (replays get 400). Matching local sessions are signed out by `sid`
when the token has one, otherwise by `sub`.

`/backchannel_logout/received` exists so the end-to-end tests can see that a logout token
arrived. It is part of this example only; a production RP should not expose it.

Sessions live in memory and are lost when the process restarts. This is a sample, not a
production RP.
