# Operating AnvilID

This guide covers the operator commands of the `anvilid` binary: backups and restores, key
rotation, and recovering administrator access. Every command reads the same configuration as
`anvilid serve` (config file, `ANVILID_*` environment variables, flags), so run it with the
environment of the server it operates on.

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
