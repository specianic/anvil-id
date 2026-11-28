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
| `tenant` | `slug` | Display name, custom host and settings (registration, MFA, signing algorithms, sign-in by email, upstream linking, default language, DCR and CIMD policy, role and permission claim mapping; since 1.0 also the organization claim mapping `claims.org_roles` / `claims.org_permissions`, the PAR policy `par` and the headless origin allow-list `headless`). |
| `clients` | `client_id` | Static clients only. Since 1.0 with the `organization` policy (`off`, `optional`, `required`), `require_pushed_authorization_requests`, `client_kind` and `headless_native`; since rc.4 with the home URLs `client_uri` and `initiate_login_uri`. |
| `connections` | `slug` | Tenant-level upstream identity providers (social presets, OIDC, OAuth 2.0). Organization connections are listed under their organization (below). |
| `branding` | `client_id` (absent = tenant-wide) | Theme tokens, custom CSS and (rc.4) the logo. |
| `roles` | `name` | Name, description, permissions. |
| `attributes` | `name` | Custom user attribute definitions (JSON Schema, claim rule). |
| `email_templates` | `kind` | Customized templates only. |
| `smtp` | (one) | Tenant SMTP settings; absent = the installation SMTP. |
| `webhooks` | `name` | URL, subscribed events, enabled flag. |
| `organizations` | `slug` | rc.4, optional: organizations with their roles, connections, domain claims, default roles and branding (below). |

Objects are identified by these natural keys only. Database ids never appear in a document, so a
document exported from one installation applies to another.

The document does **not** contain:

- users, role assignments, sessions, tokens, consents or the audit log (runtime data);
- dynamic clients (RFC 7591) and Client ID Metadata Document clients (registered at runtime);
- in the system tenant, the console client `anvil-console` (the installation keeps it in line
  with `public_url` at every start);
- CAPTCHA settings (their secret cannot be exported; configure CAPTCHA through the admin API or
  the console, and leave `captcha` out of the document);
- organization members, invitations, identity links, the role assignments made within an
  organization, and domain verification (status, DNS token, timestamps).

The keys added in rc.4 (`logo`, `client_uri`, `initiate_login_uri`, `organizations`) are optional
keys of version 1 ([COMPATIBILITY.md](COMPATIBILITY.md)): unknown keys are still refused, and there
is no new document version. A document written before rc.4 keeps its meaning, also with `--prune`:
an absent `logo` keeps the stored logo, and an absent `organizations` key touches no organization.

### Logos (rc.4)

`branding[].logo` and `organizations[].branding.logo` take one of these forms:

| Form | Meaning |
|---|---|
| omitted | Keep the stored logo (documents written before rc.4). |
| `null` | Remove the logo. |
| `{data: <base64>}` | Set the logo from the image (standard base64; line breaks are ignored). The upload rules apply: PNG, JPEG or WebP, at most 256 KiB; SVG is refused. |
| `{sha256: <hex>, content_type: image/png}` | A logo already stored in this tenant, by content hash. This is what an export writes. A hash the target tenant does not have is refused (`branding[0].logo: unknown logo hash`), so a document for another installation must carry the image. |
| `{file: path}` | CLI only: the image file (relative to the document's directory) is inlined as `{data}`. The admin API refuses it with a 422 naming the field. |

```yaml excerpt
branding:
  - tokens:
      colors: {primary: "#0b5fff"}
    logo: {file: brand/logo.png}
```

Plans compare logos by SHA-256 (inline images are hashed first), so re-applying the same image is
no change. Over HTTP a document is limited to 1 MiB, and each inline logo takes up to about
350 KB of base64: a document with several inline logos may need the CLI, which applies the
document without HTTP.

### Client home URLs (rc.4)

```yaml excerpt
clients:
  - client_id: billing-web
    # ...
    client_uri: https://billing.example.com/
    initiate_login_uri: https://billing.example.com/login
```

Both are optional and omitted from an export while unset. The rule is the one of the admin API: an
absolute `https` URL (`http` only for `localhost` and loopback addresses), without user information
or fragment, at most 2048 characters. A refusal names the field, for example
`clients[0].client_uri: must be an absolute https URL`. Like every other client field, a home URL
set in the console and missing from the document is removed by the next apply.

### Organizations (rc.4)

1.0 kept organizations out of the document. Since rc.4 the optional `organizations` section manages
them, keyed by `slug`:

```yaml excerpt
organizations:
  - slug: globex
    display_name: Globex
    mfa_policy: required          # null = no organization requirement
    metadata: {crm_id: "42"}      # free-form JSON object
    settings:
      default_roles: [member]     # by name: a role of this organization, otherwise a tenant role
    roles:
      - name: member
        permissions: [docs:read]
    connections:
      - slug: globex-sso
        display_name: Globex SSO
        enabled: false
        config:
          type: oidc
          issuer: https://idp.globex.example.com
          client_id: anvilid
        secret: {env: GLOBEX_OIDC_SECRET}
    domains:
      - domain: globex.example.com
        connection: globex-sso    # routing target, a connection of this organization
        routing: true
        allow_local_password: true
    branding:
      tokens: {radius_px: 4}
      logo: {file: brand/globex.png}
```

Rules:

- **Absent means unmanaged.** Without the `organizations` key, export, plan, apply and `--prune`
  leave every organization and everything it owns alone. The tenant sections never contain
  organization objects: `--prune` of the tenant's `roles` or `connections` never deletes an
  organization role or connection, even one whose name equals a tenant role being pruned.
- **Organizations are never deleted by a document** in rc.4. An organization missing from the
  list (or an empty list) is kept; delete organizations through the admin API or the console
  (that removes their members and links too).
- **Inside a listed organization**, roles, connections, domain claims and branding that its entry
  no longer lists are deletes, performed only with `--prune` (`- organization role
  globex/member (prune only)`). Plan keys are `{org}/{name}`.
- **Runtime data is never part of the document**: members, invitations, identity links and the
  roles assigned within the organization. The export writes none of them and applying never
  changes them.
- **A document never marks a domain verified.** A new domain claim is pending, with a fresh DNS
  token that the console or the admin API shows. `routing: true` and `allow_local_password:
  false` take effect only once the domain was verified through DNS: until then the claim keeps its
  stored routing settings (a new claim: routing off, passwords allowed) and the plan shows no
  change for them. Apply the document again after verification to turn routing on. A document
  with any verification key (`verified`, `status`, `token`, `verified_at`, ...) is refused.
- **Connections** are OIDC, or SAML while the operator flag `saml_experimental` is on (creating or
  changing a SAML connection with the flag off is refused; a SAML connection has no secret).
  Their secrets are write-only like every other secret (`{configured: true}` in an export).
  Enabling one follows the same rule as everywhere: it must be complete, and a generic OIDC
  issuer must pass discovery.
- **One slug namespace**: tenant and organization connections share slugs. A slug used twice in
  the document, or by a stored connection of the tenant or of another organization, is refused
  by path (`organizations[0].connections[0].slug`), as is a tenant connection reusing an
  organization connection's slug (`connections[i].slug`).
- **Not for the system tenant**: a system tenant document with `organizations` (even an empty
  list) is refused.

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

### Pushed authorization requests, agents and headless (1.0)

These fields are omitted from an export while they have their default, so documents written
before 1.0 export and apply unchanged.

Tenant settings:

```yaml excerpt
tenant:
  settings:
    par:
      require_pushed_authorization_requests: true   # default false
    headless:
      allowed_origins: [https://app.example.com]    # default []
```

- `par.require_pushed_authorization_requests`: every client of the tenant must use a pushed
  authorization request (RFC 9126 section 5). With `false` each client decides for itself.
- `headless.allowed_origins`: the origins of single-page apps that may call the headless flow API
  in browser mode with credentials (see `docs/HEADLESS.md`). Each entry is an exact origin
  `https://host[:port]`, lowercase, without path, query, fragment, userinfo or wildcard; at most
  50. `http://localhost` and `http://127.0.0.1` are accepted only when the server runs in
  development mode. The app must be **same-site** with the issuer (for example
  `app.example.com` with `id.example.com`): browsers block the cross-site cookies the flow needs.
  A bad entry is reported by path, for example
  `tenant.settings.headless.allowed_origins[0]: origin must not contain a wildcard`.

Client fields:

```yaml excerpt
clients:
  - client_id: mobile-app
    # ...
    consent_mode: skip_first_party
    require_pushed_authorization_requests: true   # default false
    client_kind: application                      # application (default) | agent
    headless_native: true                         # default false
```

- `require_pushed_authorization_requests`: the client may only start authorization with a pushed
  request (RFC 9126 section 6 client metadata).
- `client_kind: agent` marks an AI agent acting for the user; the consent page says so. An agent
  must keep `consent_mode: required`.
- `headless_native: true` lets the client use the native headless flow API. It needs
  `consent_mode: skip_first_party` (first-party apps only), `require_pkce: true` and
  `client_kind: application`.

The same rules apply to every write path (admin API, this document, dynamic registration, Client
ID Metadata Documents), and a refusal names the field, for example `clients[0].consent_mode:
agent clients never skip consent`. Dynamic registration (RFC 7591) accepts
`require_pushed_authorization_requests` as client metadata. It never sets `client_kind` or
`headless_native`: those keys are ignored like any unknown metadata, and a dynamic or metadata
document client can never be `headless_native`. An administrator can mark any client, dynamic
ones included, as an agent through the admin API. There is no automatic `agent` default for
dynamic or metadata document clients in 1.0; the consent page always shows how such a client was
registered.

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

Secret fields are `clients[].secret`, `connections[].secret`,
`organizations[].connections[].secret`, `webhooks[].secret` and `smtp.password`. An export never contains a secret, a secret hash or sealed bytes; it writes
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
reference; deleting a role removes its assignments. Organizations are never pruned; see
[Organizations](#organizations-rc4) for what prune does inside a listed organization.

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
roles, attributes, connections, organizations (each with its roles, connections, domain claims,
default roles and branding), clients, branding, email templates and SMTP (then the settings
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
  64 KiB limit. The CLI reads the file directly and has no HTTP limit (use it for documents with
  several inline logos).
- Logos: at most 256 KiB each (about 350 KB as base64), PNG, JPEG or WebP.
- Plan and apply check the DCR and CIMD settings with the same rules as the tenant API: allow-list
  hosts are host names or IP literals, at most 100 per list and no duplicates; at most 100 allowed
  scopes and resources; no `admin` / `admin:*` scope; `dcr.max_clients` at most 1000000; CIMD
  cache bounds between 60 and 604800 seconds with `min_cache_secs <= max_cache_secs`; CIMD
  `allow_listed` needs a host. The published schema encodes the per-field bounds.
- Clients outside the `system` tenant cannot list `admin` or `admin:*` scopes; `system` tenant
  clients cannot list `org:admin` and must keep `organization: off` (1.0).
- `headless.allowed_origins` holds at most 50 origins (1.0).
