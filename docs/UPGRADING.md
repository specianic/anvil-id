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
