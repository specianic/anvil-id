# Sample relying party (Node.js)

A minimal OpenID Connect relying party for AnvilID, built with Express 5 and
[openid-client](https://github.com/panva/openid-client) 6. It uses the authorization code flow
with PKCE (S256), `state` and `nonce`. It shows the signed-in user's `sub` and `email` from
UserInfo and can refresh its tokens. AnvilID rotates refresh tokens, and the RP always stores
the newly issued one.

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
| `/healthz`  | Returns `ok`                                                   |

Sessions live in memory and are lost when the process restarts. This is a sample, not a
production RP.
