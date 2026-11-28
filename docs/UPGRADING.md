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

## 0.3 to 0.4

**Back up first.** Stop AnvilID, then copy the database (for SQLite, the whole data directory)
and the KEK. The KEK now also seals webhook secrets. From 0.4 on, `anvilid backup create` makes
online SQLite backups ([OPERATIONS.md](OPERATIONS.md#backup-and-restore-sqlite)).

**Stop every 0.3 node before you start a 0.4 node.** Running 0.3 and 0.4 binaries against the same
database is not tested.

### Migrations

The upgrade is automatic and keeps all data. There is one migration per backend, applied in a
single transaction:

- **SQLite:** `0007_release_0_4`.
- **Postgres:** `0006_release_0_4`.

Both only add tables, columns and indexes (new columns get constant defaults), plus one backfill
(below). Neither is destructive, so no `--allow-destructive-migrations` flag is needed. They add
the tables `role`, `role_assignment`, `attribute_definition`, `webhook_endpoint`,
`webhook_delivery` and `initial_access_token`; the column `attributes` on `user` (a JSON object,
default empty); the client columns `registration_source` (default `static`),
`metadata_expires_at` and `registration_access_token_hash`; and `resources` on `consent_grant`
(default empty). The CI upgrade tests build a 0.3 database, upgrade it, compare every row, check
the backfill and run the full storage contract suite on the result (SQLite also checks that a
restart does not run the backfill twice).

**Administrator backfill.** If the `system` tenant exists, the migration creates its
`administrator` role with the permission `admin:write` and assigns it to **every existing user of
the `system` tenant**. New installations get the same role from the setup page.

### Behaviour changes

- **Console access follows roles.** In 0.3 every user of the `system` tenant got the admin scopes
  the console asked for. In 0.4 the console token's admin scopes are bounded by the user's roles in
  the `system` tenant: `admin:write` covers everything, `admin:read` every read scope, and
  `admin:{resource}:write` also its read scope. Thanks to the backfill, existing system users keep
  full access. **System users you create after the upgrade sign in to the console without any admin
  access** until you assign them a role (console: **Roles**, or
  `PUT /api/admin/v1/tenants/system/users/{user_id}/roles/administrator`). Management clients using
  `client_credentials` are not affected. The last active holder of `admin:write` cannot be removed:
  unassigning, deleting or disabling them, deleting their role or dropping `admin:write` from it is
  refused with `409`. If you lock yourself out anyway, use `anvilid admin recover`
  ([OPERATIONS.md](OPERATIONS.md#admin-access-recovery)).
- **Role and permission claims.** The default claim mapping of every tenant puts a `roles` claim
  in access tokens, ID tokens and UserInfo when the `roles` scope is granted, and a `permissions`
  claim in JWT access tokens (not gated by a scope). Users without roles get neither claim, so
  nothing changes until you create roles. Resource servers that reject unknown claims should allow
  them, or change the mapping (tenant setting `claims`; `null` disables a claim). Opaque access
  tokens and the introspection response carry no role, permission or attribute claims in 0.4.
- **Consent covers resources.** A remembered consent now skips the screen only when it covers
  every requested scope **and** every requested `resource` (RFC 8707). Grants stored by 0.3 have no
  resources, so users of clients that send `resource` see the consent screen once more after the
  upgrade (and `prompt=none` returns `consent_required` until they have). Clients that send no
  `resource` are unaffected.
- **Sessions survive the upgrade.** Cookie names do not change in 0.4, so users stay signed in.
- **Oversized request bodies** now always get `413` (pages, protocol endpoints and the admin API),
  whether the size is declared or streamed. Some routes answered `400` in 0.3.
- **Health aliases.** `/healthz` (liveness) and `/readyz` (readiness) are added next to
  `/health/live` and `/health/ready`. During a drain readiness answers `503 draining`. The probes
  no longer go through tenant resolution or rate limiting.
- **Tenant hosts.** A host that matches no tenant is remembered as a miss for 5 seconds per node,
  so a newly configured custom host can take up to 5 seconds to resolve on each node.
- **MFA `required`.** The enrolment step offers a passkey next to an authenticator app.
- **Logs.** Each request writes one access line (target `anvil_web::access`) with the route
  template, tenant, status, latency and request id. Client IP addresses are no longer logged by the
  rate limiter. Parsers of the 0.3 request log lines need updating.
- **Admin scopes on ordinary clients are refused.** Static clients outside the `system` tenant can
  no longer be created with, or updated to, an `admin` or `admin:*` scope (`422` on `scopes`, also
  in config plan/apply). Such scopes never granted admin access: the admin API accepts only
  tokens of the `system` tenant. Existing clients keep them until their scopes are next changed,
  so other fields stay editable; remove them with
  `PATCH /api/admin/v1/tenants/{slug}/clients/{client_id}` and a `scopes` list without them. A
  config document exported from such a tenant lists the scope and is refused until you remove it.
- **Config documents over HTTP** may be up to 1 MiB (plan and apply only); every other route keeps
  the 64 KiB body limit.
- **Discovery** is unchanged by default. Path tenants are also served at the OpenID Connect
  path-insertion URL `/.well-known/openid-configuration/t/{slug}`. `registration_endpoint` and
  `client_id_metadata_document_supported` appear only for tenants that enable dynamic registration
  or client metadata documents.
- **Admin API:** new resources `roles`, `attributes`, `webhooks`, `initial-access-tokens` and
  `config` (export, plan, apply); the tenant view gains `issuer` and `discovery_url`; the client view
  gains `registration_source` and `metadata_expires_at`; tenant settings gain `claims`, `dcr` and
  `cimd`. Deleting, disabling or unassigning the last administrator answers `409`.

### New configuration keys and defaults

Everything new is off until you configure it:

| Key | Default | Effect of the default |
|---|---|---|
| `redis_url` | unset | Rate limits are per node, as in 0.3 |
| `rate_limit_redis_failure` | `closed` | Only matters with `redis_url`: while Redis is unreachable, `auth`-class requests (sign-in, registration, recovery and setup form posts, `/register`) get `429` with `Retry-After`; other classes fall back to per-node limits. `local` uses per-node limits for every class instead |
| `metrics_listen`, `metrics_on_main_port` | unset, `false` | No `/metrics` |
| `otel_endpoint`, `otel_service_name` | unset, `anvilid` | No trace export |
| `shutdown_drain` | `0s` | The node stops right after SIGTERM, as in 0.3. Set it (for example `10s`) behind a load balancer |
| `database_max_connections` | `10` | Postgres pool size per node, as in 0.3 |

New tenant settings default to off as well: dynamic client registration (`dcr.policy`) and client
metadata documents (`cimd.policy`) are `disabled` in every tenant, and always in `system`.
[OPERATIONS.md](OPERATIONS.md#configuration-keys-added-in-04) describes every key, and
[OPERATIONS.md](OPERATIONS.md#client-registration-policies) the registration policies.

### Limitations in 0.4

- **`jwks_uri` is not accepted for dynamically registered or CIMD clients.** `private_key_jwt`
  clients of either kind must send inline `jwks`.
- **KEK rotation is not supported.**
- The webhook payload names the tenant by id (`data.tenant`), not by slug.

### Deployment

- A Helm chart is included (`deploy/helm/anvilid`). `database.type` selects `sqlite` (one replica)
  or `postgres` (several replicas). The chart refuses more than one replica, or an HPA, without
  `redis.url` / `redis.existingSecretKey`, unless you set `redis.acknowledgePerNodeLimits=true` and
  accept per-pod rate limits. It also refuses SQLite with more than one replica, and a termination
  grace period not longer than the drain.
- Compose examples for Postgres and an OpenTelemetry/Prometheus overlay are in `deploy/compose/`;
  see [deploy/README.md](https://github.com/specianic/anvil-id/blob/main/deploy/README.md).
- The container image has a `HEALTHCHECK` that runs `anvilid healthcheck`.

### What to configure next

- Assign roles to your console administrators and define roles for your applications
  (console: **Roles**). Add custom user attributes (console: **Attributes**) and choose which ones
  users may edit on their account page.
- Subscribe your services to user and session events: [WEBHOOKS.md](WEBHOOKS.md).
- Behind a load balancer: set `shutdown_drain`, use `/health/ready`, and for several nodes on
  Postgres set `redis_url` ([OPERATIONS.md](OPERATIONS.md#high-availability-on-postgres)).
- Turn on metrics and traces ([OPERATIONS.md](OPERATIONS.md#metrics)).
- Keep tenant configuration in version control with `anvilid tenant export` ([CONFIG-YAML.md](CONFIG-YAML.md)).
- For MCP servers and agents, enable dynamic registration or client metadata documents for the
  tenant ([MCP.md](MCP.md)).

## 0.4 to 1.0

**Back up first.** Stop AnvilID, then copy the database (for SQLite, the whole data directory, or
`anvilid backup create`) and the KEK. The SQLite upgrade rebuilds five tables (below); a backup is
the only way back if anything goes wrong, and a downgrade to 0.4 means restoring it.

**Stop every 0.4 node before you start a 1.0 node.** Running 0.4 and 1.0 binaries against the
same database is not supported: 0.4 does not know the new columns and constraints.

### Migrations

The upgrade is automatic and keeps all data. None of the migrations is destructive, so no
`--allow-destructive-migrations` flag is needed.

- **SQLite:** three migrations.
  - `0008_release_1_0` (one transaction, additive): the tables `organization`, `org_membership`,
    `org_invitation` and `org_domain`; `org_id` on `authorization_code` and `token_family`;
    `organization` on `client` (default `off`).
  - `0009_release_1_0_rebuild` rebuilds `connection`, `role`, `role_assignment`, `replay_guard` and
    `email_template` to add organization columns, foreign keys and new kinds (`saml` connections,
    `saml_assertion_id` replay entries, the `org_invitation` email template). SQLite cannot alter
    these constraints in place, and `identity_link` and `role_assignment` reference the rebuilt
    tables, so this migration runs **outside** sqlx's per-migration transaction: it turns foreign
    keys off, rebuilds the five tables in its own transaction (each: create the new table, copy
    every column of every row, drop the old one, rename, recreate every index), checks
    `pragma_foreign_key_check` before `COMMIT` (any violation rolls everything back), then turns
    foreign keys on again. Re-running it after a crash between its commit and sqlx's bookkeeping
    is safe. This is why a backup matters most for SQLite.
  - `0010_release_1_0_par_import` (one transaction, additive): the tables
    `pushed_authorization_request` and `password_hash_profile`, and the client columns
    `require_pushed_authorization_requests` (default false), `client_kind` (default `application`)
    and `headless_native` (default false).
- **Postgres:** two migrations, each one transaction, in place.
  - `0007_release_1_0`: the same four organization tables, new columns, swapped CHECK constraints
    for the new kinds, the role-assignment primary key replaced by two partial unique indexes, and
    composite foreign keys. Rows are not copied.
  - `0008_release_1_0_par_import` (additive): the same two tables and three client columns as
    SQLite `0010`.

The CI upgrade tests build a populated 0.4 database on each backend (tenants, users, roles and
assignments, connections of several kinds with identity links, replay entries, email templates,
a client, a token family and a code), upgrade it, compare every row and run the full storage
contract suite on the result. Every 0.4 row becomes tenant-level: `org_id` is null and every
client's `organization` policy is `off`. Every client keeps its behaviour: PAR is not required,
the client is an `application` and not a native headless client. The two new tables start empty.

### Tenants without organizations behave as in 0.4

Nothing changes for a tenant until you create an organization, set a client's `organization`
policy, or verify and route a domain:

- The sign-in page stays the combined form. It turns into the email-first page only for tenants
  with a verified domain routed to an enabled organization connection.
- Clients default to `organization: off`, so no token carries organization claims.
- Organization connections never appear on the tenant's sign-in page.

Changes that do apply to every tenant:

- **Opaque tokens:** introspection and UserInfo now return the role, permission and attribute
  claims that a JWT access token would carry (0.4 returned none for opaque tokens).
- **Reserved claim names:** `org_id`, `org_slug`, `org_roles` and `org_permissions` are reserved.
  A custom attribute claim or a renamed role/permission claim with one of these names is refused
  when saved and is never emitted.
- **Discovery:** `claims_supported` lists the four organization claims.
- **`org:admin` is a reserved scope:** it can never be registered through dynamic registration or
  a client metadata document, cannot be listed in `dcr.allowed_scopes`, and cannot be held by
  `system` tenant clients.
- **Second-factor passkeys:** at the second-factor step the browser's passkey picker now offers
  only the signing-in user's passkeys.
- **Admin API:** new `organizations` resource with the scopes `admin:organizations:read|write`;
  signing keys (`GET /tenants/{slug}/keys`, `POST /tenants/{slug}/keys/rotate`, scope
  `admin:settings:*`); the email template kind `org_invitation` (nine kinds); the client field
  `organization`; tenant settings `claims.org_roles` / `claims.org_permissions`; the tenant view
  field `features.saml`; the connection view fields `organization` and, for SAML, `sp`. The
  tenant's `GET …/connections` list now includes organization connections (with `organization`
  set); changing one there answers `409`, so automation that edits every listed connection should
  skip them.
- **Tenant YAML** documents never contain organizations or anything they own, and `--prune` never
  deletes them ([CONFIG-YAML.md](CONFIG-YAML.md#organizations-are-not-part-of-the-document)).
- **Console links from before 0.4** (`/console/users`, `/console/clients/…` and the other paths
  without `/t/{tenant}`) no longer redirect to the `default` tenant; they show the console's
  not-found page. Update bookmarks to `/console/t/{tenant}/…`.

### New in the final 1.0

These arrived after 1.0.0-beta.1. All of them are off or unused until you turn them on, so an
upgraded installation behaves as before.

- **Pushed authorization requests (RFC 9126).** Each tenant has a `/par` endpoint, advertised in
  discovery as `pushed_authorization_request_endpoint`. PAR can be required per client
  (`require_pushed_authorization_requests`) or for the whole tenant (tenant setting
  `par.require_pushed_authorization_requests`); both default to off ([PAR.md](PAR.md)).
- **Headless flow API** (`/api/flows/v1`): your own single-page app or first-party native app
  drives login, registration, recovery and verification with JSON. Browser mode admits only the
  tenant's own origin and the origins in the tenant setting `headless.allowed_origins` (empty by
  default). Native mode is limited to clients with `headless_native` set (default false)
  ([HEADLESS.md](HEADLESS.md)).
- **User import and export.** `anvilid users import` / `anvilid users export` and the management
  API routes `POST …/users/import`, `GET …/users/export`, `GET …/users/{user_id}/export` (with
  `?profile=gdpr` for a GDPR bundle). Imported password hashes (bcrypt, Argon2, scrypt, Firebase
  scrypt, PBKDF2 variants and salted SHA-2) are verified at first sign-in and replaced with
  Argon2id. Firebase parameters live in per-tenant password hash
  profiles (`…/password-hash-profiles`, scopes `admin:settings:read|write`)
  ([IMPORT-EXPORT.md](IMPORT-EXPORT.md)).
- **New admin scope `admin:users:export`.** Export needs `admin:users:export` or `admin:write`.
  Full administrators already hold `admin:write`, so they can export without any change.
  `admin:users:read` and `admin:users:write` do **not** grant export, and `admin:users:export`
  grants nothing else. Give automation that must export users the new scope explicitly.
  Import needs `admin:users:write`.
- **Agent marker.** The client field `client_kind` is `application` (default) or `agent`. An agent
  is an AI agent acting for the user: the consent page says so and agent clients never skip
  consent ([CONFIG-YAML.md](CONFIG-YAML.md)).
- **Admin API and tenant YAML:** the client fields `require_pushed_authorization_requests`,
  `client_kind` and `headless_native`, and the tenant settings `par` and `headless`. They are
  additive and optional; documents and requests without them keep working.

No new operator configuration keys were added after 1.0.0-beta.1.

### New configuration keys

| Key | Default | Effect of the default |
|---|---|---|
| `saml_experimental` (`ANVILID_SAML_EXPERIMENTAL`, `--saml-experimental`) | `false` | SAML 2.0 connections cannot be created or used ([SAML.md](SAML.md)) |
| `domain_verification_resolvers` (`ANVILID_DOMAIN_VERIFICATION_RESOLVERS`, `--domain-verification-resolvers`) | empty | Domain TXT lookups use the system resolver configuration |

[OPERATIONS.md](OPERATIONS.md#configuration-keys-added-in-10) describes both, the DNS lookup and
the daily domain re-check job, which every node schedules (one node runs it at a time).

### New token claims

With an active organization, tokens carry `org_id`, `org_slug`, `org_roles` and `org_permissions`
([ORGANIZATIONS.md](ORGANIZATIONS.md#organizations-in-tokens)). Resource servers that reject
unknown claims should allow them before you turn on organizations for their clients.

### Limitations in 1.0

- SAML 2.0 is experimental and off by default; IdP-initiated SSO, encrypted assertions and Single
  Logout are not supported. Whether SAML leaves experimental status in 1.0 is an open owner
  decision, taken after the external security review and the real-IdP interop checklist
  ([SAML.md](SAML.md)). Until then, treat it as experimental.
- Tenant-restricted system administrators (system roles limited to some tenants) are deferred to
  a later 1.x release. They need a second administrator principal shape that every tenant-level
  and installation-level route would have to check. That is security-sensitive surface which
  should not be added right before the external security review. Organization administrators
  already cover delegated administration per organization ([ORGANIZATIONS.md](ORGANIZATIONS.md)).
  Adding the feature later is additive and does not change existing roles.
- KEK rotation is still not supported, and `jwks_uri` is still refused for dynamic and CIMD
  clients.
- The other open items are listed in [ORGANIZATIONS.md](ORGANIZATIONS.md#limitations-in-10).

### What to configure next

- Create organizations and set the `organization` policy of the clients that serve business
  customers ([ORGANIZATIONS.md](ORGANIZATIONS.md)).
- Organization connections create accounts just in time for addresses on the organization's
  verified domains even when the tenant's registration is closed. Other addresses, and
  tenant-level connections, follow `upstream_registration`
  ([ORGANIZATIONS.md](ORGANIZATIONS.md#enterprise-oidc-connections)).
- Behind a firewall that blocks outbound DNS, set `domain_verification_resolvers`.
- Subscribe to the `organization.*` webhook events ([WEBHOOKS.md](WEBHOOKS.md)).
- Require PAR for clients that handle sensitive authorization requests ([PAR.md](PAR.md)).
- Migrating from another identity system: import users with their password hashes
  ([IMPORT-EXPORT.md](IMPORT-EXPORT.md)).

## 1.0.0-beta.1 to 1.0

This section is for installations that ran a 1.0.0-beta.1 build. Coming from 0.4, follow
[0.4 to 1.0](#04-to-10) instead; it includes everything here.

**Back up first**, as for every upgrade, and stop every beta.1 node before you start a 1.0 node.

### Migrations

The upgrade is automatic, additive and keeps all data. No `--allow-destructive-migrations` flag is
needed, and no table is rebuilt.

- **SQLite:** `0010_release_1_0_par_import` (one transaction). `0008` and `0009` already ran on
  beta.1 and are unchanged.
- **Postgres:** `0008_release_1_0_par_import` (one transaction). `0007` already ran on beta.1 and
  is unchanged.

Both add the tables `pushed_authorization_request` and `password_hash_profile` and the client
columns `require_pushed_authorization_requests`, `client_kind` and `headless_native`, with
defaults that keep every existing client's behaviour. The CI upgrade tests build a populated
beta.1 database on each backend, upgrade it, compare every table, check the defaults of the new
columns, restart twice to prove the upgrade is idempotent and run the full storage contract suite
on the result.

### What changes

Everything in [New in the final 1.0](#new-in-the-final-10). In short:

- PAR, the headless flow API, user import and export, password hash profiles and the agent marker
  are new and off or unused until configured.
- The admin scope `admin:users:export` is new. Full administrators (`admin:write`) can export
  without changes; other tokens need the new scope.
- The management API and the headless flow API are now covered by the compatibility policy
  ([COMPATIBILITY.md](COMPATIBILITY.md)): from 1.0 on, changes within 1.x are additive only.

The [Limitations in 1.0](#limitations-in-10) apply.

## 1.0.0-rc.3 to 1.0.0-rc.4

This section is for installations that ran 1.0.0-rc.3. rc.4 is an operability and user-experience
release: the sign-in, account and console screens were reworked, and the management API gained a
few additive fields and one operation. **Back up first**, as for every upgrade, and stop every
rc.3 node before you start an rc.4 node.

### Migrations

The upgrade is automatic, additive and keeps all data. No `--allow-destructive-migrations` flag is
needed, and no table is rebuilt.

- **SQLite:** `0011_release_1_0_rc4` (one transaction).
- **Postgres:** `0009_release_1_0_rc4` (one transaction, metadata only, no table rewrite).

Both add two nullable columns to `client`: `client_uri` (the application's home page) and
`initiate_login_uri` (a URL that starts a sign-in at the application). Every existing client reads
`NULL`, which keeps rc.3 behaviour. The CI upgrade tests build a populated rc.3 database on each
backend (static, public, DCR and CIMD clients), upgrade it, compare every rc.3 value, restart to
prove the upgrade is idempotent and run the full storage contract suite on the result.

On start-up the built-in console client (`anvil-console`) gains the scopes `profile` and `email`
(the drift check writes one `client_updated` audit event with `fields: ["scopes"]`; later starts
change nothing).

### Management API

All changes are additive under the compatibility policy ([COMPATIBILITY.md](COMPATIBILITY.md)):

- Clients have the optional fields `client_uri` and `initiate_login_uri`. They must be absolute
  `https` URLs with a host, no user info, no fragment and at most 2048 bytes (`http` only for
  loopback hosts); a refusal is a 422 naming the field. Dynamic client registration stores and
  returns both; a Client ID Metadata Document may carry them. Only static (administrator-registered)
  clients ever get a "Back to {app}" link on the sign-in, error, signed-out and account pages.
- New operation `POST /api/admin/v1/tenants/{slug}/users/{user_id}/recovery`
  (`sendUserRecovery`, scope `admin:users:write`): sends the user the normal password-reset email.
  The response never contains the token; blocked users are refused. Audit action
  `user_recovery_sent`.
- `GET /api/admin/v1/system/info` adds `smtp_configured` (whether the installation-wide SMTP is configured).
- Deleting the built-in console client of a tenant now answers 409.
- **Enabling an incomplete upstream connection now answers 422** with the missing field
  (`config.client_id`, `config.issuer`, `secret`, ...). Such a connection never worked at sign-in.
  Every OAuth 2.0 / OIDC kind (the social presets, generic OIDC and generic OAuth2) needs a client
  secret before it can be enabled; SAML needs none. For generic OIDC the issuer must also pass
  discovery through the SSRF-guarded outbound client. Creating a connection with `enabled: true`
  and an incomplete configuration is refused the same way and stores nothing. The API default of
  `enabled` is unchanged (`true`); send `enabled: false` to save a draft. The same rule applies to
  organization connections and to tenant YAML.
- rc.3 connections that are enabled but incomplete stay stored and enabled, but are **hidden from
  sign-in** (no button, not offered on the link confirmation page or the account's "add a link"
  list) until they are completed. The console lists them with an "Incomplete" badge.
- The redirect URI refusal messages are clearer (for example a missing scheme is named). The
  decisions are unchanged.

The OpenAPI breaking-change check (`crates/anvil-web/tests/api_compat.rs`) now treats the required
path parameters and body of a **new** operation as additive; a new required input on an existing
operation is still reported as breaking.

### Tenant YAML

New optional keys, all absent by default (an absent key changes nothing):

- `clients[].client_uri` and `clients[].initiate_login_uri` (same rule as the API).
- `branding.logo`: inline image data, the SHA-256 of the stored logo, `null` to remove it, or (CLI
  only) `{file: path}`, which the CLI inlines. An absent `logo` keeps the stored logo.
- `organizations[]`: organizations with their roles, connections (write-only secrets, like tenant
  connections), domains, default roles and branding. Domain verification can never be declared;
  a new domain is claimed pending and only routes after DNS verification. The system tenant refuses
  `organizations`. Without the key, `--prune` never touches organization objects.

See [CONFIG-YAML.md](CONFIG-YAML.md).

### Behaviour changes in the browser UI

- **Post/redirect/get.** A refused form `POST` on a sign-in, registration, recovery or verification
  page now answers **303** to the same page with `?flow=`, and the `GET` answers 400 with the
  messages (carried in a sealed one-shot cookie, never containing the password or a code). Custom
  themes or scripts that read the body of a refused `POST` (a 400 in rc.3) must follow the
  redirect. Rate-limit locks (429) and CAPTCHA demands are still direct answers.
- **Detours keep the application.** Create account, forgot password, start over and "use another
  way" links carry the authorization request (`request=`), and emailed recovery and verification
  links started from an application continue to it. An unknown, expired or foreign `request=` shows
  the "sign-in link has expired" page instead of an empty form.
- **Emailed links fail early.** A used or expired reset or verification link fails when it is
  opened (before any input), without consuming anything. A reset link offers "Send a new link".
- **Recovery codes after MFA enrolment during sign-in** are shown on their own page, bound to the
  browser, and must be confirmed before the sign-in continues.
- **Account pages** show who is signed in and a sign-out button. Signing out from there is two
  steps: the button, then "Sign out" on the confirmation page. Destructive account actions (remove a
  passkey or TOTP, new recovery codes, remove an app's access, disconnect a linked account, sign out
  other devices) ask for confirmation on a server-rendered page, also without JavaScript.
- **Session times** on the account pages are shown in UTC with an explicit label; the account pages
  run no script, so local-time rendering is not available.
- **Logout:** without an active session the end-session endpoint no longer asks for confirmation.
  "Stay signed in" returns to the static client's home when there is one. The contract sentences
  and URL layout of the logout pages are unchanged.
- **Error pages** show a friendly explanation and a way forward. The technical detail line appears
  only in development mode. The `error-message` sentences are unchanged.
- **Setup:** reopening a setup link after setup answers 200 "Setup is already complete" with a
  link to the console (it was a 403). Before setup an unknown token is still refused.
- **Root page:** `/` and `/ui` show sign-in, the account and (system tenant) the console.
- **Look:** the default theme uses the new palette and self-hosts its fonts (`font-src 'self'`).
  Stored themes keep their colours; see [the theme README](../themes/default/README.md) for the
  selector contract, the new CSS variables and the new templates. Themes that override templates
  should compare them with the new defaults.

### Postgres in containers

The rc.4 test suites open many concurrent connections. Postgres in Docker defaults to a 64 MB
`/dev/shm`, which can make parallel queries fail with `could not resize shared memory segment`
(SQLSTATE 53100) under load. Give the container more shared memory (`--shm-size=256m`, or
`shm_size` in Compose) if you see it.

### Known limitations in rc.4

- There is no end-user "send a new verification email" action. An invalid or used verification
  link fails on open and offers "Go to sign in". Adding it needs a new rate-limited,
  enumeration-safe route.

### Deferred to after rc.4

These four Low findings of the rc.4 review are deliberately not fixed in rc.4:

- **U-L9**: registration reveals that an account with the address exists. Fixing it needs a new
  "someone tried to register with your address" email kind and template, part of the
  tenant-overridable email contract.
- **C-L4**: the console has no email template preview, test send or language choice. It needs a
  server-side preview render.
- **C-L6**: the "Setup URL" line on stdout is mixed with the JSON audit output. The log format is an
  operator contract; the root page and `/console/` before setup name `anvilid admin setup-url`
  instead.
- **C-L7 grace period**: rotating a client secret has no grace period, because that needs
  dual-secret support on the server. The console warns that the old secret stops working
  immediately.
