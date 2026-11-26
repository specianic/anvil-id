# Operating AnvilID

This guide covers running AnvilID: the operator commands of the `anvilid` binary (backups and
restores, key rotation, recovering administrator access, health checks), and, added in 0.4,
running several nodes on Postgres, shared rate limiting with Redis, metrics, traces and logs, the
outbound request policy, and the tenant registration policies. Every command reads the same
configuration as `anvilid serve` (config file, `ANVILID_*` environment variables, flags), so run
it with the environment of the server it operates on. `anvilid config show` prints the effective
value and source of every key.

Contents: [What to back up](#what-to-back-up) ·
[Backup and restore (SQLite)](#backup-and-restore-sqlite) · [Postgres](#postgres) ·
[Key rotation](#key-rotation) · [Admin access recovery](#admin-access-recovery) ·
[Container health checks](#container-health-checks) ·
[Configuration keys added in 0.4](#configuration-keys-added-in-04) ·
[Health, readiness and drain](#health-readiness-and-drain) ·
[High availability on Postgres](#high-availability-on-postgres) ·
[Shared rate limiting with Redis](#shared-rate-limiting-with-redis) · [Metrics](#metrics) ·
[Traces (OpenTelemetry)](#traces-opentelemetry) · [Logs](#logs) ·
[Outbound requests](#outbound-requests) · [Tenant hosts](#tenant-hosts) ·
[Client registration policies](#client-registration-policies) ·
[Deploying with Helm or Compose](#deploying-with-helm-or-compose) ·
[Declarative tenant configuration](#declarative-tenant-configuration)

## What to back up

An installation has two parts, and a backup needs both:

1. **The database**: SQLite file (default `./anvilid-data/anvilid.db`) or the Postgres database.
2. **The key-encryption key (KEK)**: `ANVILID_KEK`, or the KEK file (default
   `./anvilid-data/kek`). Signing keys, upstream connection secrets, webhook secrets and queued
   email payloads are sealed with it. A database backup without its KEK cannot be used.

The KEK is never written into a backup. Store it separately (a secrets manager or an offline
copy), and keep it as long as you keep backups made while it was in use.

## Backup and restore (SQLite)

### Online backup

```sh
anvilid backup create --output /srv/backups/anvilid-$(date +%Y%m%d%H%M).db
```

- Runs next to a running server; no downtime and no lock on the server.
- The copy is made with SQLite's `VACUUM INTO` in one read transaction, so it is a consistent
  point-in-time snapshot even while the server writes.
- The copy is written to a temporary file in the destination directory, checked with
  `PRAGMA integrity_check`, synced to disk and then renamed to the final name. A failed backup
  leaves no partial file. The command never overwrites an existing file.
- The backup file is created with mode `0600`: it contains password hashes and sealed secrets.
- The command prints the migration version and tenant count of the copy, and a reminder that
  the KEK is not included.

Schedule it with cron or a systemd timer and ship the files off the host. Restore a backup on a
scratch host from time to time to prove that your backups and your KEK copy work.

### Restore

```sh
# 1. stop the server
# 2. make sure the KEK of the backed-up installation is in place (ANVILID_KEK or the KEK file)
anvilid backup restore --input /srv/backups/anvilid-202611260300.db --yes
# 3. start the server
```

The restore is offline and refuses to run when it would do damage:

- **A server is running**: restore takes `serve.lock` in the data directory, so it refuses
  while `anvilid serve` runs on that data directory, and no server can start during the restore.
- **The file is corrupt** (truncated, not a SQLite file, failing the integrity check, or not an
  AnvilID database).
- **The backup is newer than the binary**: a backup whose newest migration is unknown to this
  binary is refused. Upgrade `anvilid` first. An older backup is accepted; `anvilid serve`
  applies the newer migrations when it starts (see [UPGRADING.md](UPGRADING.md)).
- **No KEK, or the wrong KEK**: the restore checks that the configured KEK decrypts the backup's
  signing keys. If it does not, nothing is changed.
- **An existing database without `--yes`.**

When every check passes, the backup is copied to a temporary file next to the database, synced,
the old database's `-wal` and `-shm` files are removed, and the copy is renamed over the
database. The old database is not kept: take a backup of it first if you may need it.

## Postgres

`anvilid backup create` and `anvilid backup restore` support SQLite only. On Postgres they exit
with an error that points here. Use the Postgres tooling, which handles large databases, several
nodes and point-in-time recovery:

- **Logical dumps** with `pg_dump` and `pg_restore`, for example
  `pg_dump --format=custom --file=anvilid.dump "$DATABASE_URL"` and
  `pg_restore --clean --if-exists --dbname="$DATABASE_URL" anvilid.dump`. A dump is consistent
  even while AnvilID nodes write. Stop all nodes before a restore.
- **Physical base backups with WAL archiving** (`pg_basebackup` plus `archive_command`, or a
  backup tool built on them, or your provider's snapshots) for point-in-time recovery.
- **The KEK**: every node shares one KEK (`ANVILID_KEK`). Back it up with the same care as the
  database; a Postgres dump without it cannot be used.
- **Configuration**: the per-tenant YAML export (added in 0.4) is a readable copy of each
  tenant's configuration that can be re-applied to a fresh instance. It does not contain users,
  sessions or secrets, so it complements a database backup and does not replace it.

Restore into a database of the same or an older AnvilID version than the binary you start; the
binary applies newer migrations on start.

## Key rotation

Signing keys are rotated automatically every `key_rotation_days`. To rotate on demand:

```sh
# prepublish a next key; the scheduled rotation activates it once caches have seen it
anvilid keys rotate --tenant default --alg RS256
# key compromise: replace the active key now; tokens signed by the old key stop verifying
anvilid keys rotate --tenant default --alg RS256 --immediate
```

Both forms run next to a running server and are audited as `key_rotation_requested`.

**KEK rotation is not supported in 0.4.** Rotating the KEK means re-sealing every encrypted
column and invalidating codes derived from it; it is planned for a later release. Until then,
keep the KEK secret and treat a leaked KEK together with a leaked database as a full compromise.

## Admin access recovery

When nobody can sign in to the console any more (forgotten password, lost second factor, or the
last administrator lost the `administrator` role), recover access from a shell on the host. There
is no network endpoint for this; the command needs the server's database configuration (and, for
SQLite, access to the data directory). It runs next to a running server.

### Recover an existing administrator account

```sh
anvilid admin recover --email admin@example.com
# lost second factor as well:
anvilid admin recover --email admin@example.com --reset-mfa
```

- Works for accounts of the `system` tenant only. An unknown address, or an account of another
  tenant, is refused and nothing changes. A blocked account is refused too (see below).
- Prints a one-time **recovery URL**, valid for one hour, that opens the system tenant's
  password reset page. Nothing is emailed: hand the URL to the account owner over a trusted
  channel. Setting the new password signs the account out of every session.
- Assigns the `administrator` role to the account if it does not hold it.
- `--reset-mfa` also removes the account's TOTP authenticator (with its recovery codes) and its
  passkeys, each audited as `totp_removed` / `passkey_removed` with the system actor. Without
  it, second factors are left as they are.
- Audited as `admin_recovery_issued` in the system tenant, with the system actor. The URL is never
  logged or audited.

### Create a new administrator after a lockout

```sh
anvilid admin recover
```

Without `--email` the command prints a one-time **setup URL** (one hour) that creates a new
system administrator, like the URL printed at first start. It does this only when no active
system-tenant user holds `admin:write`. If an administrator exists, the command refuses and asks
for `--email`, so it cannot be used to add administrators quietly. Also audited as
`admin_recovery_issued`.

## Container health checks

`anvilid healthcheck` probes the readiness endpoint of the server on the same host, for images
that have no shell or curl (the release image is distroless):

```yaml
# docker compose
healthcheck:
  test: ["CMD", "/usr/local/bin/anvilid", "healthcheck"]
  interval: 10s
  timeout: 5s
  retries: 3
```

- Sends `GET /health/ready` over plain HTTP/1.1 to `127.0.0.1` on the port of `listen` (a
  wildcard `listen` address is probed on loopback). Exit code 0 means ready, 1 means not ready or
  unreachable (for example while the server drains after SIGTERM), 2 means a usage error.
- `--url http://127.0.0.1:8080/readyz` picks another loopback URL. Only `127.0.0.1`, `[::1]` and
  `localhost` are accepted, over plain `http`; any other target is refused before a connection is
  made.
- When the main listener uses TLS, the healthcheck cannot probe it; use an orchestrator HTTPS
  probe instead.

## Configuration keys added in 0.4

| Key | Environment | Flag | Default | Meaning |
|---|---|---|---|---|
| `redis_url` | `ANVILID_REDIS_URL` | none (secret: environment or config file only) | unset | Shared rate-limit backend, `redis://` or `rediss://` (TLS). Unset = every node limits on its own. See [Shared rate limiting with Redis](#shared-rate-limiting-with-redis) |
| `rate_limit_redis_failure` | `ANVILID_RATE_LIMIT_REDIS_FAILURE` | `--rate-limit-redis-failure` | `closed` | What happens while Redis is unreachable: `closed` or `local` |
| `metrics_listen` | `ANVILID_METRICS_LISTEN` | `--metrics-listen` | unset | Socket address of a separate plain-HTTP listener that serves only `/metrics`. Must differ from `listen` |
| `metrics_on_main_port` | `ANVILID_METRICS_ON_MAIN_PORT` | `--metrics-on-main-port` | `false` | Serve `/metrics` on the main listener instead (logs a warning: it is then reachable by anyone who reaches the server) |
| `otel_endpoint` | `ANVILID_OTEL_ENDPOINT` | `--otel-endpoint` | unset | OTLP/HTTP base URL for traces. Unset = no trace export |
| `otel_service_name` | `ANVILID_OTEL_SERVICE_NAME` | `--otel-service-name` | `anvilid` | `service.name` of exported spans (1-255 printable characters) |
| `shutdown_drain` | `ANVILID_SHUTDOWN_DRAIN` | `--shutdown-drain` | `0s` | How long readiness reports 503 before a graceful stop: `10s`, `500ms`, `1m` or plain seconds; at most 1 h |
| `database_max_connections` | `ANVILID_DATABASE_MAX_CONNECTIONS` | `--database-max-connections` | `10` | Postgres connection pool size per node (1-1000). SQLite ignores it |

Invalid values stop startup with an error that names the key and never echoes the value.
`config show` redacts the password of `redis_url` and any credentials in `otel_endpoint`.

Metrics and trace export are off by default. Tenant settings added in 0.4 (registration policies,
claim mapping) are managed through the admin API, the console or the declarative configuration,
not through configuration keys.

## Health, readiness and drain

| Endpoint | Alias | Answers |
|---|---|---|
| `/health/live` | `/healthz` | `200` while the process serves requests |
| `/health/ready` | `/readyz` | `200` when the database answers; `503 unavailable` when it does not; `503 draining` during shutdown |

The probes are installation-wide: they bypass tenant resolution and rate limiting, so an unknown
`Host` header or a busy client cannot make a node look unhealthy.

**Drain.** On SIGTERM or Ctrl-C a node switches readiness to `503 draining` at once, keeps
serving every other request for `shutdown_drain`, then stops accepting connections, finishes the
requests in flight and stops its background workers. Set `shutdown_drain` to at least your load
balancer's health-check interval times its failure threshold, so the balancer stops routing new
requests to the node before it closes its listener, and give the orchestrator a grace period
longer than the drain (the Helm chart refuses `terminationGracePeriodSeconds` not greater than the
drain). After the listener stops, background jobs get up to 20 s (webhook timeout 15 s + 5 s) to
finish, so size the orchestrator grace period as drain + 20 s + margin (the Helm default of 40 s
with a 10 s drain already does). With the default `0s` the node stops right away.

## High availability on Postgres

Several `anvilid serve` nodes can share one Postgres database. SQLite is single-node: the data
directory lock (`serve.lock`) refuses a second server.

- **Nodes are stateless.** Sessions, flows, codes, tokens, consent and every queue live in the
  database. Any node can serve any request, so no sticky sessions are needed.
- **Every node needs the same KEK** (`ANVILID_KEK`) and the same `public_url`. AnvilID never
  generates a KEK for Postgres; a node without one refuses to start.
- **First start.** Nodes started together on an empty database come up together: one installs,
  the others accept its result, and exactly one setup URL is printed. Migrations run under an
  advisory lock, each applied once.
- **Load balancer.** Route to nodes whose `/health/ready` answers `200`; use `/health/live` for
  restarts. Use the drain above for rolling restarts and upgrades.
- **Do not let the load balancer or proxy retry non-idempotent requests** (any `POST`: `/token`,
  `/register`, sign-in forms, the admin API). Authorization codes and refresh tokens are single
  use. A retried code exchange looks like a replay, which is refused and revokes the token family
  the code started; a retried refresh does the same to the refresh chain. Retrying `GET` and
  `HEAD` requests on connection errors is safe.
- **Pool size.** Each node opens up to `database_max_connections` connections (default 10). Keep
  nodes × pool size, plus anything else using the database, below the server's
  `max_connections`.
- **Background work.** Expired-row cleanup, key rotation and audit retention run on one node at
  a time (database leases). Back-channel logout and webhook delivery run on every node and claim
  rows with `FOR UPDATE SKIP LOCKED`, so each delivery attempt is made by one node. A node that
  stops mid-delivery leaves the row to be claimed again after its lease (webhooks: 45 s), so
  deliveries are at least once.
- **Rate limits.** Without Redis each node keeps its own budgets, so the effective limit is the
  configured one times the number of nodes. Use Redis to share them (next section).
- **Tenant hosts** are cached as misses for 5 seconds per node (see [Tenant hosts](#tenant-hosts)).

The load and three-node restart harness that exercises this setup is in `tests/load/`
(`tests/load/README.md`); the Compose stack it uses is `deploy/compose/ha/`.

## Shared rate limiting with Redis

With `redis_url` set, every node uses one shared set of rate-limit and brute-force budgets in
Redis (each check is one Lua script, so the server must support `EVALSHA`/`EVAL`). Without it,
each node limits on its own.

- **Startup** fails with an error naming `redis_url` when Redis cannot be reached (500 ms
  timeouts). The URL is never printed: it may carry a password. Use `rediss://` for TLS.
- **Key names** are `anvil:rl:{class}:{64 hex}`. The hex part is an HMAC-SHA-256 under a key
  derived from the KEK, so Redis never sees client IP addresses, client ids or sign-in
  identifiers. Nodes sharing a Redis must share the KEK (they must anyway).
- **Time** comes from each node's clock (passed into the scripts); keep node clocks in sync with
  NTP.

**Failure modes.** After a Redis error a circuit breaker opens for 5 seconds; then one probe
request tries Redis again, and the breaker closes when it succeeds. While the breaker is open:

| Route class | `rate_limit_redis_failure = closed` (default) | `local` |
|---|---|---|
| `auth` (sign-in, registration, recovery and setup form posts, `/register`, the brute-force gate) | **refused**: `429` with `Retry-After` set to the rest of the 5 s cool-down | limited by the node's own in-process limiter |
| `token`, `admin`, `default`, brute-force backoff counting | limited by the node's own in-process limiter | the same |

So with the default, a Redis outage stops new sign-ins (they cannot be protected against
password guessing across nodes) while token refreshes, the admin API and page views keep working
with per-node limits. Choose `local` if availability of sign-in matters more to you than
cross-node brute-force limits during an outage.

Every fallback increments `anvil_ratelimit_backend_errors_total{operation,reason}` (`reason` is
`error` or `breaker_open`), and the node logs one warning when Redis becomes unreachable and one
line when it is reachable again. The URL is never logged.

## Metrics

Prometheus metrics are off until you choose where to serve them:

- `metrics_listen = "0.0.0.0:9464"` (recommended): a separate plain-HTTP listener that answers only
  `GET /metrics`. Expose it on an internal network only.
- `metrics_on_main_port = true`: `/metrics` on the main listener. It is not rate limited and has
  no authentication, so block it at your proxy if the main port is public.

With neither set, `/metrics` answers 404 and no metrics are collected.

| Metric | Type | Labels |
|---|---|---|
| `anvil_http_requests_total` | counter | `route_class`, `status_class` |
| `anvil_http_request_duration_seconds` | histogram (1 ms to 5 s buckets) | `route_class` |
| `anvil_ratelimit_rejections_total` | counter | `route_class` |
| `anvil_auth_attempts_total` | counter | `outcome` (`success`, `failure`) |
| `anvil_tokens_issued_total` | counter | `grant` |
| `anvil_refresh_reuse_total` | counter | none |
| `anvil_jobs_runs_total` | counter | `job`, `outcome` (`ran`, `lease_held`, `lease_error`) |
| `anvil_webhook_deliveries_total` | counter | `outcome` (`delivered`, `retry`, `failed`, `disabled`) |
| `anvil_ratelimit_backend_errors_total` | counter | `operation`, `reason` |

`route_class` is one of `auth`, `token`, `admin`, `default`, `health`, `metrics`, `console`,
`assets`; `status_class` is `1xx` to `5xx` (or `other`). Labels are bounded on purpose: no
tenant slugs, client ids, paths with ids, email addresses or IP addresses appear in metrics. The
names and their owners are defined in one place, `anvil_web::observability`.

## Traces (OpenTelemetry)

Trace export is compiled into every build and switched on at runtime by `otel_endpoint`:

- `otel_endpoint` is a **base URL**, like `OTEL_EXPORTER_OTLP_ENDPOINT`: `/v1/traces` is appended
  unless the path already ends with it. `http://otel-collector:4318` sends to
  `http://otel-collector:4318/v1/traces`. The protocol is OTLP/HTTP with protobuf, batched.
- Put exporter **credentials in `OTEL_EXPORTER_OTLP_HEADERS`** (or
  `OTEL_EXPORTER_OTLP_TRACES_HEADERS`), for example `authorization=Bearer%20…`, not in URL
  userinfo.
- Spans carry `service.name` (`otel_service_name`) and `service.version`. Each request is one
  `http.request` span with `method`, `route` (the route template, for example `/authorize`, never
  the query string), `tenant` (slug), `status`, `latency_ms` and `request_id`. Audit events are
  never exported as span events.
- Pending spans are flushed when the node stops.
- **Incoming `traceparent`** headers are honoured only when the TCP peer is in
  `trusted_proxies`; from anyone else they are ignored and a new trace starts. Put your proxy or
  gateway in `trusted_proxies` if it starts traces.
- The exporter uses its own HTTP client, not the guarded outbound client (see
  [Outbound requests](#outbound-requests)): the collector is operator infrastructure, often on a
  private address.

`deploy/compose/observability/` is a Compose overlay with an OpenTelemetry Collector and
Prometheus wired to a node.

## Logs

- Operational logs go to stderr. `log_format = json` (the default outside development mode)
  writes one JSON object per line; `pretty` is for terminals. `RUST_LOG` sets the levels.
- Every request writes one access line (target `anvil_web::access`) with `method`, `route`
  (template), `tenant`, `status`, `latency_ms` and `request_id`. `request_id` is a generated UUID
  or a client-sent `x-request-id` of at most 64 characters from `[A-Za-z0-9._-]`.
- Client IP addresses, email addresses, query strings and secrets are not written to operational
  logs, metrics or traces.
- The audit log is separate: stored in the database and mirrored to **stdout** as one JSON object
  per line, independent of `RUST_LOG`.

## Outbound requests

AnvilID makes outbound HTTP requests to upstream identity providers, back-channel logout
endpoints, CAPTCHA providers and the breached-password service, and since 0.4 to **webhook
endpoints** and **client metadata documents** (CIMD). All of them go through one guarded client:
https only (plain http only in development mode), no private, loopback, link-local or other
reserved addresses (checked for every resolved address), no redirects, no proxy environment
variables, bounded timeouts and bodies. Allow internal destinations with `outbound_allow_cidrs`
and add a private CA with `outbound_ca_file`.

Operator infrastructure that you configure yourself is **not** subject to that policy and may be
on private addresses: the OTLP collector (`otel_endpoint`), Redis (`redis_url`), Postgres, SMTP,
and the loopback probe of `anvilid healthcheck`.

## Tenant hosts

A request whose `Host` matches no tenant's custom host is routed by path (`/t/{slug}/…`, otherwise
the `default` tenant). To keep unknown hosts from costing a database lookup each, a node
remembers a miss for **5 seconds** (at most 10,000 hosts). Consequence: after you give a tenant a
custom host, each node may keep serving that host as the default tenant for up to 5 seconds.
Found tenants are never cached, so deleting a tenant, a client or a signing key takes effect on
the next request.

## Client registration policies

Each tenant has two self-service client policies, both **disabled by default** and always
disabled for the `system` tenant. They are tenant settings (`dcr`, `cimd`) in the admin API, the
console's tenant settings and the declarative configuration. [MCP.md](MCP.md) shows
the integrator side for MCP clients.

**Dynamic client registration** (RFC 7591/7592, setting `dcr`):

| Field | Default | Meaning |
|---|---|---|
| `policy` | `disabled` | `disabled`: `/register` answers 404 and discovery has no `registration_endpoint`. `allow_listed`: registration needs an initial access token. `open`: anyone may register |
| `allowed_redirect_hosts` | empty | Redirect URI hosts accepted under `allow_listed` (host names or IP literals, no scheme, port, path or wildcard; at most 100). Empty = any host the redirect rules allow |
| `allowed_scopes` | empty | Scopes a registered client may request. Empty = `openid profile email address phone`. `admin:*` scopes are never registrable |
| `allowed_resources` | empty | RFC 8707 resource indicators registered clients (and CIMD clients) may be granted |
| `allow_client_credentials` | `false` | Whether registered confidential clients may use `client_credentials` |
| `max_clients` | `1000` | Most dynamically registered clients the tenant may hold (at most 1,000,000) |

- **Initial access tokens** are issued in the console or with
  `POST /api/admin/v1/tenants/{slug}/initial-access-tokens` (scope `admin:clients:write`); the
  value is shown once and stored as a SHA-256 hash. Lifetime: default 24 hours, 1 minute to 365
  days. Uses: 1 to 100,000, or unlimited. A registration refused for its metadata does not use up
  the token. Without a valid token the answer is `401 invalid_token`.
- Registered clients get `consent_mode = required` and PKCE required. The informational URIs
  (`logo_uri`, `client_uri`, `policy_uri`, `tos_uri`) are validated but neither stored nor
  returned. `software_statement` is refused. The RFC 7592 read, replace and delete endpoints
  (`/register/{client_id}`) need the registration access token returned at registration, and
  answer 404 once the policy is disabled again.
- `max_clients` is a soft cap: it is checked before the insert, so concurrent registrations can
  exceed it by the number of requests in flight.
- `/register` and `/register/*` (any method) are in the `auth` rate class.

**Client ID Metadata Documents** (setting `cimd`): a client id that is an `https` URL is resolved
by fetching the JSON document at that URL.

| Field | Default | Meaning |
|---|---|---|
| `policy` | `disabled` | `disabled`: URL client ids are unknown clients, and clients materialised earlier stop working at once. `allow_listed`: only document hosts in `allowed_hosts` (at least one required). `open`: any host |
| `allowed_hosts` | empty | Host names or IP literals (same syntax rules as above) |
| `min_cache_secs`, `max_cache_secs` | `300`, `86400` | Bounds for how long a fetched document is used (the document's `Cache-Control: max-age` clamped to them; 60 to 604,800 seconds, min ≤ max) |

- Documents are fetched through the guarded outbound client: at most 5 KiB, status 200, no
  redirects, at most 16 concurrent fetches per node, and a per-host budget shared by the whole
  installation (the `auth` quota, `rate_limit_auth_per_minute`, keyed by document host whichever
  tenant asks).
- Valid documents are stored as client rows with `registration_source = cimd`; there is no
  separate cache table. A failed fetch is never cached. When a refresh fails transiently (network,
  timeout, 429, 5xx) a row that expired less than `max_cache_secs` ago is served stale; otherwise
  the request fails with `503 temporarily_unavailable`.
- CIMD clients get their allowed resources from the tenant's `dcr.allowed_resources`.

**Limitation in 0.4:** neither dynamic nor CIMD clients may use `jwks_uri`. `private_key_jwt`
clients must send their keys inline as `jwks`. A registration request with `jwks_uri` is refused
with `invalid_client_metadata`, and a metadata document with `jwks_uri` is treated as invalid
(the client id is refused).

## Deploying with Helm or Compose

- [`deploy/README.md`](../deploy/README.md): overview, zero-config container, Docker Compose with
  Postgres, the observability overlay.
- [`deploy/helm/anvilid/README.md`](../deploy/helm/anvilid/README.md): the Helm chart.
  `database.type` is `sqlite` (one replica, persistent volume) or `postgres` (several replicas,
  database URL and KEK from an existing Secret). The chart refuses to render unsafe combinations:
  SQLite with more than one replica or an HPA, several replicas without `redis.url` (unless
  `redis.acknowledgePerNodeLimits=true`), and a termination grace period not longer than the
  drain.

## Declarative tenant configuration

`anvilid tenant export|plan|apply` and the matching admin API routes keep a tenant's
configuration (settings, static clients, connections, branding, roles, attributes, email
templates, SMTP, webhooks) in a versioned YAML document: [CONFIG-YAML.md](CONFIG-YAML.md).

## Limitations in 0.4

- **KEK rotation is not supported** (see [Key rotation](#key-rotation)).
- `jwks_uri` is not accepted for dynamic or CIMD clients (inline `jwks` only).
- Without Redis, rate limits are per node.
