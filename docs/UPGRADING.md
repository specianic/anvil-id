# Upgrading AnvilID

AnvilID migrates its database automatically when `anvilid serve` starts (turn this off with
`--no-migrate` and run `anvilid migrate` yourself). Migrations are forward-only. Back up the
database and the key-encryption key (KEK) before every upgrade; a downgrade means restoring that
backup.

## 0.1 to 0.2

The upgrade is automatic and keeps all data. Users, password hashes, clients, signing keys,
sessions, refresh tokens and pending authorization codes survive. The new tables (passkeys and TOTP
in `credential`, `recovery_code`, `consent_grant`, `access_token`, `audit_event`, `email_template`,
`smtp_settings`, `job_lease`) start empty. The new client and tenant columns get defaults that keep
0.1 behaviour, with one exception: consent. 0.1 had no consent screen. In 0.2 existing clients
default to `consent_mode = required`, so users see the screen once per client. To keep the 0.1
behaviour for your own applications, set `consent_mode` to `skip_first_party` through the admin API
or the console.

None of the 0.2 migrations is destructive, so no `--allow-destructive-migrations` flag is needed.
The CI upgrade tests (`crates/anvil-storage-*/tests/upgrade.rs`) build a 0.1 database, upgrade it
and run the full storage contract suite on the result.

**Stop every 0.1 node before you start a 0.2 node.** A rolling upgrade with 0.1 and 0.2 binaries
on the same database is not supported. 0.2 changes the `credential` table (new primary key and
columns). A 0.1 binary still running against the upgraded schema cannot write passwords there, so
registration, password recovery and the setup page fail on those nodes.

**SQLite:** there is no cross-process migration lock. `anvilid serve` holds an exclusive lock on
`{data_dir}/serve.lock`, so a second `serve` on the same data directory refuses to start. Do not run
`anvilid migrate` against a database that another process is using.

**Postgres:** migrations run under sqlx's advisory lock. Nodes that start at the same time wait
for each other, and each migration is applied once.

After the upgrade:

- The admin console is at `/console/`. Sign in as an administrator (a user of the `system`
  tenant, such as the first administrator created by the setup page).
- Rate limiting is on by default. Behind a reverse proxy, set `trusted_proxies` to the proxy
  addresses. Without it every request seems to come from the proxy and all users share one quota.
  `anvilid config show` lists the new keys (`trusted_proxies`, `trusted_proxy_header`,
  `rate_limit_*`, `key_rotation_days`, `audit_retention_days`).
- Signing keys now rotate automatically every 90 days. The current key stays published until
  tokens signed with it have expired. `anvilid keys rotate --immediate` rotates at once.
- Audit events go to the database and to stdout as one JSON object per line.

## 0.2 to 0.3

**Back up first.** Stop AnvilID, then copy the database (for SQLite, the whole data directory) and
the KEK. The KEK now also seals upstream connection secrets; without it they cannot be opened.

### Migrations

The upgrade is automatic and keeps all data. There are two migrations per backend, each applied in
a single transaction:

- **SQLite:** `0005_release_0_3`. It rebuilds the `flow`, `self_service_token` and `email_template`
  tables to widen their `kind` checks (new values `logout`, `email_change`, `login_code`,
  `email_changed`). Each rebuild creates the new table, copies every row, drops the old table and
  recreates its indexes. No other table references these three, so nothing cascades. The rebuilds
  are reviewed as non-destructive, and a failure rolls the whole migration back.
  Then `0006_release_0_3_logout_issuer`, which only adds a column (below).
- **Postgres:** `0004_release_0_3`. It swaps the same three CHECK constraints in place and only
  adds columns, tables and constraints. Then `0005_release_0_3_logout_issuer`, which only adds a
  column.

None of these migrations is destructive, so no `--allow-destructive-migrations` flag is needed. They add
the tables `connection`, `identity_link`, `rp_session`, `logout_delivery`, `branding` and
`branding_logo` (Postgres also `branding_draft`), the client columns `post_logout_redirect_uris`,
`backchannel_logout_uri`, `backchannel_logout_session_required`, `allowed_resources` and
`mfa_policy`, and a `resource` column on authorization codes, token families and opaque access
tokens, and the nullable `issuer` column on `rp_session` and `logout_delivery` (the issuer each
application signed in through, used as the back-channel logout token's `iss`). The CI upgrade tests build a 0.2 database, upgrade it, compare every row and run the full
storage contract suite on the result.

Stop every 0.2 node before you start a 0.3 node. Running 0.2 and 0.3 binaries against the same
database is not tested.

### Defaults after the upgrade

Existing tenants and clients behave as in 0.2 until you change something:

| Setting | Default | Effect |
|---|---|---|
| MFA policy (tenant `mfa_policy`) | `optional` | As in 0.2: users who enrolled TOTP are asked for it; nobody is forced to enrol. Clients have no policy of their own (`mfa_policy` unset) |
| Email code and magic link (`email_otp`, `magic_link`) | off | Not offered. They can be turned on only when SMTP is configured |
| Auto-link (`auto_link`) | on | Matters only once you add upstream connections: a trusted, verified upstream email that matches a verified local account links automatically. Turn it off to always ask the user to confirm |
| Upstream registration (`upstream_registration`) | unset | Follows the tenant's registration mode |
| Default language (`default_locale`) | `en` | |
| Consent | unchanged | Saved consent grants stay valid |
| Client logout and resources | empty | No post-logout redirect URIs, no back-channel URI, no allowed resources |

No upstream connections exist after the upgrade, so the sign-in page looks as before.

### New configuration keys

- `outbound_allow_cidrs` (`ANVILID_OUTBOUND_ALLOW_CIDRS`): destinations the outbound HTTP client
  may reach although they are in a private or reserved range. Default: loopback in development
  mode, none otherwise.
- `outbound_ca_file` (`ANVILID_OUTBOUND_CA_FILE`): extra PEM root certificates for outbound TLS,
  for example a private CA.

All outbound HTTP now goes through one guarded client: upstream identity providers, back-channel
logout, CAPTCHA verification and the breached-password check. It uses https only, refuses private,
loopback, link-local and other reserved addresses, and never follows redirects. **If your
`breach_check_url` points at a server on a private network**, or your applications' back-channel
logout endpoints are internal, add their addresses to `outbound_allow_cidrs`, and their CA to
`outbound_ca_file` if it is not publicly trusted. Plain http is accepted only in development mode.

### Behaviour changes

- **Discovery** now advertises `end_session_endpoint`, `backchannel_logout_supported`,
  `backchannel_logout_session_supported`, `ui_locales_supported`, per-tenant
  `prompt_values_supported` (`create` only when registration is open) and
  `acr_values_supported` (`urn:anvilid:acr:pwd`, `urn:anvilid:acr:mfa`). Client libraries that read
  discovery may start offering logout.
- **Logout:** `/logout` implements RP-initiated logout. Sending `post_logout_redirect_uri` requires
  that the exact URI is registered on the client (`post_logout_redirect_uris`); otherwise the user
  sees an error page. Without a valid `id_token_hint` for the current session the user is asked to
  confirm.
- **`acr_values` and `prompt`:** `acr_values=urn:anvilid:acr:mfa` now asks a single-factor session
  for a second factor (0.2 accepted and ignored it). An essential `acr` that cannot be met returns
  `unmet_authentication_requirements`. `prompt=select_account` shows an account chooser and
  `prompt=create` opens registration.
- **Resource indicators:** `resource` is accepted (and may repeat) at `/authorize` and `/token`.
  A value not in the client's `allowed_resources` is `invalid_target`. Access tokens issued for a
  resource carry that resource as `aud` instead of the client id.
- **UserInfo audience:** UserInfo accepts an access token only when its `aud` contains the calling
  client's id or `{issuer}/userinfo`. Tokens from 0.2, and tokens for clients that request no
  resource, have the client id as `aud` and are unaffected. A token requested only for another
  resource is now `invalid_token` at UserInfo.
- **Languages:** pages follow `ui_locales` and the browser's `Accept-Language` when a catalog for
  that language exists, and fall back to the tenant's `default_locale`, then English. Emails are
  not translated yet.
- **Switching users:** when a second user signs in on a browser that holds another user's session,
  the first session is signed out together with its tokens.
- **`login_hint`** that is an email address now prefills the sign-in form.
- **Everyone signs in again after the upgrade.** Session, flow and upstream cookie names now end
  in a suffix derived from the whole tenant id (the first 16 hex characters of its SHA-256) instead
  of the first 12 hex characters of the tenant UUID. The old suffix was only the tenant's creation
  millisecond, so two tenants created in the same millisecond shared cookie names. Old cookies are
  not read any more: existing browser sessions end, and sign-ins in progress during the upgrade
  start over. Refresh tokens already issued to applications keep working. Old cookies expire with
  the browser session and are harmless.
- **Email code and magic link are independent settings:** `email_otp` offers the 6-digit code and
  `magic_link` the sign-in link; turning on either one offers email sign-in, and the `login_code`
  email carries only the enabled methods. Custom `login_code` templates must guard `code` and
  `link` with `{% if code is defined %}` / `{% if link is defined %}`; an unguarded use is refused
  when the template is saved.
- **Upstream accounts follow `require_verified_email`:** an account created at first upstream
  sign-in from an untrusted or unverified email gets a verification email. When the tenant
  requires a verified email, that account (and any linked account whose email is not verified)
  cannot sign in until the address is verified. A trusted provider asserting a verified email signs
  in at once.
- **Admin API:** new `connections` and `branding` resources use the existing
  `admin:settings:{read|write}` scopes (plus `admin:write` for the `system` tenant). Tokens that
  already hold `admin:settings:write` can manage them.

### What to configure next

- Register `post_logout_redirect_uris` on clients that use RP-initiated logout, and a
  `backchannel_logout_uri` on clients that want back-channel logout.
- Add upstream connections (console: **Connections**). Register the redirect URI shown on the
  connection page at the provider, then set the secret. Secrets are write-only.
- Choose the MFA policy and email sign-in options (console: **Login settings**) and, per client,
  an MFA policy override and `allowed_resources`.
- Brand the login pages (console: **Branding**), per tenant or per client.
- Back-channel logout runs on every node; no extra process or setting is needed.
