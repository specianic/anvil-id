# Declarative tenant configuration (YAML)

A tenant's configuration can be exported as one document, kept in version control, reviewed as a
plan, and applied again, to the same installation or to a new one. Re-applying a document that is
already in force changes nothing.

- CLI: `anvilid tenant export|plan|apply` (YAML, secret references resolved locally).
- Admin API: `GET /api/admin/v1/tenants/{slug}/config`, `POST …/config/plan`,
  `POST …/config/apply` (JSON, inline secrets only).
- JSON Schema: [`docs/schemas/tenant-config-v1.json`](schemas/tenant-config-v1.json) (draft
  2020-12). Editors with YAML language support can use it for completion and checks.

## What the document contains

| Section | Key | Notes |
|---|---|---|
| `tenant` | `slug` | Display name, custom host and settings (registration, MFA, signing algorithms, sign-in by email, upstream linking, default language, DCR and CIMD policy, role and permission claim mapping; since 1.0 also the organization claim mapping `claims.org_roles` / `claims.org_permissions`). |
| `clients` | `client_id` | Static clients only. Since 1.0 with the `organization` policy (`off`, `optional`, `required`). |
| `connections` | `slug` | Tenant-level upstream identity providers (social presets, OIDC, OAuth 2.0). Organization connections are not included (below). |
| `branding` | `client_id` (absent = tenant-wide) | Theme tokens and custom CSS. |
| `roles` | `name` | Name, description, permissions. |
| `attributes` | `name` | Custom user attribute definitions (JSON Schema, claim rule). |
| `email_templates` | `kind` | Customized templates only. |
| `smtp` | (one) | Tenant SMTP settings; absent = the installation SMTP. |
| `webhooks` | `name` | URL, subscribed events, enabled flag. |

Objects are identified by these natural keys only. Database ids never appear in a document, so a
document exported from one installation applies to another.

The document does **not** contain:

- users, role assignments, sessions, tokens, consents or the audit log (runtime data);
- dynamic clients (RFC 7591) and Client ID Metadata Document clients (registered at runtime);
- in the system tenant, the console client `anvil-console` (the installation keeps it in line
  with `public_url` at every start);
- CAPTCHA settings (their secret cannot be exported; configure CAPTCHA through the admin API or
  the console, and leave `captcha` out of the document);
- logos (version 1 carries theme tokens and custom CSS; upload logos through the admin API);
- organizations and everything they own (1.0, see below).

### Organizations are not part of the document

Added in 1.0. Organizations are customer data that organization admins change at runtime, so the
tenant document neither contains nor manages them. Export, plan, apply and `--prune` never see
or touch:

- organizations, their memberships, invitations, verified domains and routing settings;
- organization connections (OIDC and SAML) and their identity links;
- organization roles and the role assignments made within an organization;
- organization branding.

In particular, `--prune` never deletes an organization connection or an organization role, even
one whose name equals a tenant role being pruned (roles are matched by name among tenant roles
only). A document connection whose `slug` is already used by an organization connection is
refused before anything is written (`connections[i].slug`: the slug is used by an organization
connection), because organization and tenant connections share one slug namespace.

The client `organization` field is part of the document and round-trips like every other client
option:

```yaml excerpt
clients:
  - client_id: billing-web
    # ...
    organization: optional   # off (default) | optional | required
```

In the system tenant `organization` must be `off`, and no client may list the `org:admin` scope;
`dcr.allowed_scopes` can never contain `org:admin` in any tenant.

## Example

```yaml
# AnvilID tenant configuration (kind TenantConfig, version 1) of tenant `acme`.
version: 1
kind: TenantConfig
tenant:
  slug: acme
  display_name: Acme
  host: null
  settings:
    registration: invite_only
    mfa_policy: required
    signing_algs: [RS256, ES256]
    default_locale: en
    dcr:
      policy: disabled
    cimd:
      policy: disabled
clients:
  - client_id: billing-web
    name: Billing
    client_type: confidential
    application_type: web
    auth_method: client_secret_basic
    secret: {env: BILLING_CLIENT_SECRET}
    redirect_uris: [https://billing.example.com/callback]
    grant_types: [authorization_code, refresh_token]
    scopes: [openid, profile, email, roles]
connections:
  - slug: google
    display_name: Google
    config:
      type: social
      provider: google
      client_id: 1234.apps.googleusercontent.com
    secret: {file: secrets/google-client-secret}
    trust_email_verified: true
branding:
  - tokens:
      colors: {primary: "#0b5fff"}
      radius_px: 6
roles:
  - name: editor
    description: Edits documents
    permissions: [docs:read, docs:write]
attributes:
  - name: department
    schema: {type: string, enum: [sales, engineering]}
    user_editable: true
    claim: {claim: department, tokens: [access_token], scope: profile}
smtp:
  host: smtp.example.com
  port: 587
  username: anvilid
  password: {env: SMTP_PASSWORD}
  from: id@example.com
  tls: starttls
webhooks:
  - name: crm
    url: https://crm.example.com/hooks/anvilid
    events: [user.created, user.deleted]
```

Fields left out take their defaults (for example `require_pkce: true`, `token_format: jwt`,
`consent_mode: required`, `enabled: true`). Unknown keys at the top level and in the sections
(`tenant`, `clients[]`, `connections[]`, ...) are an error; inside `tenant.settings` and a
connection's `config`, unknown keys are ignored, like the admin API does.

## Secrets

Secret fields are `clients[].secret`, `connections[].secret`, `webhooks[].secret` and
`smtp.password`. An export never contains a secret, a secret hash or sealed bytes; it writes
`{configured: true}` (a secret is stored) or `{configured: false}`.

| Form | Meaning |
|---|---|
| `{configured: true}` | Keep the stored secret. |
| `{configured: false}` | Clear it (connections; SMTP only together with removing `username`). Clients using `client_secret_basic`/`client_secret_post` and webhooks always have a secret. |
| `{value: "…"}` | Set it. Equal to the stored secret = no change (compared in constant time; client secrets by hash). |
| `{env: NAME}` | CLI only: the value of environment variable `NAME` on the machine running the CLI. |
| `{file: path}` | CLI only: the file's contents without one trailing newline; relative paths are relative to the document's directory. |
| omitted | Keep the stored secret. |

References are resolved by `anvilid` before the document reaches the configuration service. The
admin API never reads the server's environment or files: a reference sent to the API is refused
with a 422 naming the field.

When a secret is needed but none is stored and none is given:

- a new client using a secret-based method, or a new webhook, gets a **generated** secret. The CLI
  prints it once (`Generated secret of client billing-web (shown once, store it now): …`); the API
  returns it once in `generated_secrets`. It is never shown again.
- a connection or SMTP password cannot be generated (they come from the upstream provider or the
  mail server): the document is refused until it carries the value or a reference.

Provided client secrets must be 32 to 512 characters without whitespace (they are stored as a
plain SHA-256 hash, so they must be as unguessable as generated ones). Webhook secrets use the
`whsec_` form (`whsec_` + base64 of 24 to 64 random bytes).

## CLI

The commands run on the host, next to a running server, with the server's configuration (data
directory, `database_url`, KEK). They call the same configuration service as the admin API and are
audited with the system actor.

```sh
# Export (stdout or a file). The file starts with a comment header.
anvilid tenant export acme -o acme.yaml

# Validate and show the plan; changes nothing.
anvilid tenant plan -f acme.yaml

# Show the plan, then apply after confirmation (or with --yes).
anvilid tenant apply -f acme.yaml
anvilid tenant apply -f acme.yaml --yes
anvilid tenant apply -f acme.yaml --yes --prune
```

- `apply` without `--yes` asks for confirmation and refuses when stdin is not an interactive
  terminal (scripts and CI must pass `--yes`). `-f -` reads the document from stdin and then
  needs `--yes`.
- A document for a tenant that does not exist creates it.

## Plans

A plan lists, by natural key, what would be created (`+`), updated (`~`, one line per changed
field) and deleted (`-`):

```text
+ role editor
~ client billing-web
    redirect_uris: ["https://billing.example.com/cb"] -> ["https://billing.example.com/callback"]
~ webhook crm
    secret: (secret changed)
- role viewer (prune only)
1 to create, 2 to update, 1 to delete with prune.
```

Secret changes are reported without values. An applied document plans as `No changes.`

### Pruning

Objects that exist but are missing from the document are listed as deletes and only removed with
`--prune` (API: `?prune=true`). Without it they stay, so a partial document never removes
anything. Deleting a client also revokes its tokens; deleting branding also drops the scope's logo
reference; deleting a role removes its assignments.

## Validation and the system tenant

The whole document is checked before anything is written, with the same rules the admin API
applies to single changes (redirect URIs, scopes, PKCE, JWKS, connection settings, theme contrast
and CSS, attribute schemas and claim collisions, template compilation, webhook destinations,
...), plus checks against the stored state (a client's type, application type and auth method,
and a connection's kind, are fixed after creation). Every problem is reported with its path, for
example `clients[2].redirect_uris[0]: redirect URI must use https`, and nothing is changed.

In the system tenant:

- DCR and CIMD must stay `disabled`; any other value is an error;
- `anvil-console` cannot be part of the document;
- roles are admin API scopes: a document that would leave no active user holding `admin:write`
  (by editing or pruning `administrator` or another role) is refused as a whole with
  `LastAdministrator` (API: 409), and nothing is changed. Role changes beyond the caller's own
  admin scopes are refused too. The API requires `admin:write` for plan and apply on every tenant.

Connections of the Microsoft preset that set `trust_email_verified: true` accept the risk that
Microsoft accounts can carry unverified addresses ("nOAuth"); the document states that choice
explicitly, and the audit event records it.

## Idempotency, ordering and partial failures

Apply writes through the same services as the admin API, in dependency order: tenant settings,
roles, attributes, connections, clients, branding, email templates and SMTP (then the settings
that need SMTP, such as sign-in by email), webhooks. Each write is audited by its service as
usual, and a final `tenant_config_applied` event records the counts of creates, updates and
deletes (no names, no values). Before writing, the document is normalized the way the services
store it (trimmed names, de-duplicated and sorted lists), so a re-applied document plans empty
and writes nothing.

The writes are not one database transaction. If a write fails after validation (a storage error,
or a concurrent change such as a name taken in the meantime), the changes already made stay, the
error is reported and `tenant_config_applied` is not recorded. Applying the same document again
plans against the new state and completes the remaining changes.

## Limits

- Plan and apply over HTTP (`POST /api/admin/v1/tenants/{slug}/config/plan` and `.../apply`)
  accept documents up to 1 MiB and answer `413` above that; every other admin API route keeps the
  64 KiB limit. The CLI reads the file directly and has no HTTP limit.
- Plan and apply check the DCR and CIMD settings with the same rules as the tenant API: allow-list
  hosts are host names or IP literals, at most 100 per list and no duplicates; at most 100 allowed
  scopes and resources; no `admin` / `admin:*` scope; `dcr.max_clients` at most 1000000; CIMD
  cache bounds between 60 and 604800 seconds with `min_cache_secs <= max_cache_secs`; CIMD
  `allow_listed` needs a host. The published schema encodes the per-field bounds.
- Clients outside the `system` tenant cannot list `admin` or `admin:*` scopes; `system` tenant
  clients cannot list `org:admin` and must keep `organization: off` (1.0).
