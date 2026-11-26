# Importing and exporting users

AnvilID imports users, including their existing password hashes, so people can sign in with
their old passwords after a migration. On the first successful sign-in the password is
transparently re-hashed with the current Argon2id parameters.

There is one import implementation. The `anvilid users import` command and the management API
both call it, and both produce the same per-record report. Users can also be exported: one user,
all users of a tenant, or a user's GDPR data-subject bundle (see [Export](#export)).

## Import

### Running an import from the command line

```sh
anvilid users import users.ndjson --tenant default --source legacy-app
```

| Flag | Meaning |
| --- | --- |
| `<FILE>` | NDJSON file, one user per line (`-` reads stdin) |
| `--tenant <SLUG>` | Tenant to import into (default `default`) |
| `--dry-run` | Validate every record and print the report, write nothing |
| `--update` | Overwrite existing users whose data differs (see [Outcomes](#outcomes)) |
| `--source <LABEL>` | Label of the source system, recorded in the audit log (1-64 characters) |

The command opens the database with the server's configuration (the same flags and environment
as `anvilid serve`), so it can run next to a running server. It reads the file line by line and
imports it in batches of 1,000 records, so files of any size use bounded memory. Blank lines are
skipped; line numbers in the report are those of the file.

The summary on stdout lists the number of batches, the counts per outcome, the number of weak
hashes accepted, every rejected line number with its reason code, and every conflicting line
number. It never prints hashes, salts or record contents. The audit stream (JSON lines) is
written to stdout as well.

**Exit status:** `0` when no record was rejected (conflicts alone do not fail the command);
non-zero when at least one record was rejected or on any error (unknown tenant, unreadable file,
database not installed). Records accepted before a rejection are imported, so after fixing the
listed lines you can run the same file again: already imported users report `unchanged`.

### Importing through the management API

```sh
curl -sS -X POST "https://id.example.com/api/admin/v1/tenants/default/users/import?source=legacy-app" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @batch.ndjson
```

`POST /api/admin/v1/tenants/{slug}/users/import` takes the same NDJSON records as the command in
the request body and returns the [report](#report) as JSON.

| Query parameter | Meaning |
| --- | --- |
| `dry_run=true` | Validate and report, write nothing (see [Dry run](#dry-run)) |
| `update=true` | Like `--update` |
| `source=<LABEL>` | Like `--source` (1-64 characters) |

Any other query parameter is refused with a 422 problem.

- **Scope:** `admin:users:write` (or `admin:write`).
- **Content type:** `application/x-ndjson` is required; anything else is a 400 problem.
- **Size:** at most 1,000 records (non-blank lines) and 1 MiB per request. A larger request is
  refused with a 413 problem and nothing is imported. The 1 MiB limit applies to this one route
  only; every other route keeps the default 64 KiB. Split larger files into batches, or use the
  command, which batches for you.
- A line that is not valid UTF-8 or not a valid record is reported as `rejected` /
  `invalid_record` with its line number. The report never repeats the line.

### Record format

Each line is one JSON object. Unknown keys are refused (`invalid_record`).

```json
{"email": "ada@example.com", "email_verified": true, "id": "0192f0c1-1111-7aaa-8bbb-0123456789ab", "claims": {"name": "Ada Lovelace", "locale": "en"}, "attributes": {"department": "R&D"}, "password": {"scheme": "bcrypt", "hash": "$2b$12$..."}}
```

| Key | Required | Meaning |
| --- | --- | --- |
| `email` | yes | Normalised like admin user creation (trimmed, lowercased, `local@domain`) |
| `email_verified` | no | Default `false` |
| `claims` | no | OpenID Connect standard claims (`name`, `given_name`, `family_name`, `locale`, `phone_number`, `address`, ...) |
| `attributes` | no | Custom attribute values, validated against the tenant's attribute definitions exactly like an administrator's write (required attributes must be present) |
| `id` | no | UUID to use as the user id; see [Keeping user ids](#keeping-user-ids) |
| `password` | no | The imported password hash, see [Password schemes](#password-schemes). Without it the user is created without a password |

The same email twice in one batch is refused for the second occurrence (`invalid_record`), so a
dry run and a real run always agree. A record line may be at most 64 KiB.

### Keeping user ids

A record's `id` that is a valid UUID not yet used by any user becomes the user's id, so the
`sub` claim stays the same after a migration from another AnvilID installation. An id that is
already used by another user is rejected with `id_conflict`, and so is a record whose email
belongs to an existing user with a different id. Any other id format (numbers, prefixed strings)
is rejected with `invalid_record`: keep such source ids in a custom attribute (for example
`legacy_id`) instead.

### Password schemes

The `password` object is tagged by `scheme`. Byte fields (shown as *bytes*) are written as
`{"hex": "..."}` (either case) or `{"base64": "..."}` (standard alphabet, padded or unpadded).
Every hash is converted once, at import, into AnvilID's stored encoding; sign-in never parses a
vendor format.

| `scheme` | Fields | Notes |
| --- | --- | --- |
| `bcrypt` | `hash`: modular crypt string `$2a$`, `$2b$` or `$2y$` | Cost 4 to 16, weak below 10. `$2x$` is refused (`refused_variant`) |
| `argon2` | `hash`: PHC string (`argon2i`, `argon2d`, `argon2id`; `v=16` or `v=19`) | Within the memory, time and parallelism caps |
| `scrypt` | `salt` *bytes*, `hash` *bytes*, `log_n` (log2 N), `r`, `p` | Non-empty salt, hash at least 16 bytes |
| `firebase_scrypt` | `salt` *bytes* (the user's salt), `hash` *bytes* (the user's password hash), `profile` (UUID of a tenant hash profile) | See [Firebase scrypt](#firebase-scrypt) |
| `pbkdf2` | `prf` (`sha1`, `sha256`, `sha512`), `iterations`, `salt` *bytes*, `hash` *bytes* | At least 1,000 iterations (weak below 100,000), salt at least 8 bytes, hash at least 16 bytes |
| `django_pbkdf2` | `hash`: `pbkdf2_sha256$<iterations>$<salt>$<base64 hash>` (or `pbkdf2_sha1`) | The salt string's UTF-8 bytes are the salt; same floors as `pbkdf2` |
| `passlib_pbkdf2` | `hash`: `$pbkdf2-sha256$<iterations>$<ab64 salt>$<ab64 hash>` (also `$pbkdf2$` for SHA-1 and `$pbkdf2-sha512$`) | ab64 is base64 with `.` instead of `+` and no padding; same floors as `pbkdf2` |
| `salted_sha2` | `alg` (`sha256`, `sha512`), `position` (`prefix` = SHA(salt ‖ password), `suffix` = SHA(password ‖ salt)), `salt` *bytes* (at least 8 bytes), `hash` *bytes* (the digest length) | Always weak. MD5 and SHA-1 digests and unsalted digests are refused (`weak_parameters`) |

Any other scheme (for example `md5`, `sha1`, SHA-crypt or LDAP `{SSHA}`) is refused with
`unknown_scheme`.

Examples:

```json
{"scheme": "scrypt", "log_n": 15, "r": 8, "p": 1, "salt": {"base64": "c2FsdHNhbHQ="}, "hash": {"hex": "..."}}
{"scheme": "pbkdf2", "prf": "sha256", "iterations": 600000, "salt": {"hex": "..."}, "hash": {"base64": "..."}}
{"scheme": "django_pbkdf2", "hash": "pbkdf2_sha256$870000$..."}
{"scheme": "salted_sha2", "alg": "sha256", "position": "suffix", "salt": {"hex": "..."}, "hash": {"hex": "..."}}
```

#### Caps and floors

Caps bound the memory and CPU one verification can cost. They are enforced at import (the record
is rejected with `over_cap`) and again at every verification (the check fails closed):

- scrypt and Firebase scrypt: `128 × N × r × p` at most 64 MiB;
- Argon2: memory at most 262,144 KiB, time cost at most 10, parallelism at most 8;
- PBKDF2: iterations × output blocks at most 5,000,000;
- bcrypt: cost at most 16;
- salts at most 256 bytes, hashes at most 128 bytes, encoded strings at most 1,024 characters.

Floors refuse trivially weak data at import (`weak_parameters`): bcrypt cost below 4, PBKDF2
below 1,000 iterations or with a salt shorter than 8 bytes, salted SHA-2 without a salt of at
least 8 bytes, MD5 and SHA-1 digests, and scrypt, Firebase scrypt or PBKDF2 hashes shorter than
16 bytes.

#### Weak hashes

A hash that passes the floors but is below today's recommendations (bcrypt cost below 10, PBKDF2
below 100,000 iterations, every salted SHA-2 hash) is imported and marked `"weak": true` in the
report; the batch audit event counts them. The flag is informational: every imported hash is
replaced with Argon2id at the user's first successful sign-in anyway. Consider asking users who
have not signed in for a while to reset their passwords.

#### bcrypt and long passwords

bcrypt uses only the first 72 bytes of a password. Imported bcrypt hashes are verified the same
way, so a longer password still matches the hash its source system produced, as it did there.
After the first sign-in the full password is hashed with Argon2id.

### Firebase scrypt

Firebase Authentication uses a modified scrypt with project-wide parameters. These live in a
tenant **hash profile**, which an administrator creates through the management API with the
values of the Firebase project's password hash parameters:

| Profile field | Firebase parameter |
| --- | --- |
| signer key | `base64_signer_key` |
| salt separator | `base64_salt_separator` |
| rounds | `rounds` |
| memory cost | `mem_cost` |

Hash profiles are managed through the management API:

| Request | Scope | Meaning |
| --- | --- | --- |
| `GET /api/admin/v1/tenants/{slug}/password-hash-profiles` | `admin:settings:read` | List the profiles (public parameters only) |
| `POST /api/admin/v1/tenants/{slug}/password-hash-profiles` | `admin:settings:write` | Create a profile; returns it with its `id` |
| `DELETE /api/admin/v1/tenants/{slug}/password-hash-profiles/{id}` | `admin:settings:write` | Delete a profile (409 while imported hashes reference it) |

`admin:read` and `admin:write` work as well.

```json
{"name": "firebase-prod", "kind": "firebase_scrypt", "signer_key": "<base64_signer_key>", "salt_separator": "<base64_salt_separator>", "rounds": 8, "mem_cost": 14}
```

`signer_key` and `salt_separator` are standard base64, exactly as Firebase shows them. The
response contains `id`, `name`, `kind`, `salt_separator`, `rounds`, `mem_cost` and `created_at`,
but never the signer key. The key is write-only: it is not in any response, and the OpenAPI
document marks it `writeOnly`.

The verification follows the published algorithm (github.com/firebase/scrypt): scrypt over the
password with the user's salt followed by the salt separator, `N = 2^mem_cost`, `r = rounds`,
`p = 1`, 64 output bytes; the first 32 bytes key AES-256-CTR (zero IV) over the signer key, and
the result is compared with the stored hash in constant time. The profile parameters are checked
against the scrypt memory cap when the profile is created.

Each user record then names the profile:

```json
{"email": "ada@example.com", "password": {"scheme": "firebase_scrypt", "profile": "<profile id>", "salt": {"base64": "<salt>"}, "hash": {"base64": "<passwordHash>"}}}
```

A record that names a profile the tenant does not have is rejected with `unknown_profile`.

The signer key is a secret. It is stored only encrypted with the key-encryption key, bound to the
tenant and profile, and no API, report or export returns it. A profile cannot be deleted while
stored passwords still reference it (refused as a conflict); after every imported user has signed in
once (and been re-hashed) it can be removed. If a profile disappears anyway, sign-in for the
users referencing it fails closed and looks like a wrong password.

### Outcomes

Users are matched by tenant and normalised email. Each record gets one outcome:

| Outcome | Meaning |
| --- | --- |
| `created` | A new user was created (with its password in the same transaction) |
| `unchanged` | The user exists with exactly this content |
| `conflict` | The user exists with different content; nothing was changed |
| `updated` | With `--update` (API: `update`), the existing user was changed to match the record |
| `rejected` | The record was refused; `reason` says why |

Content is compared through a hash of the record without the password (email, `email_verified`,
claims, attributes and, when given, the id) plus a hash of the converted password hash, computed
in memory on both sides and never stored. A record without `password` leaves the stored password
out of the comparison and untouched. So importing the same file twice yields only `unchanged`.

After a user's first sign-in the stored password is an Argon2id hash, so a record with a
`password` for that user reports `conflict` again. `--update` would then reset the user's
password to the imported hash: only use it when that is what you want.

`--update` changes `email_verified`, the claims and the custom attributes, and the password when
the record carries one. It never changes the email, the username, the status or the id.

#### Reason codes

| Code | Meaning |
| --- | --- |
| `invalid_email` | `email` missing or not `local@domain` |
| `invalid_record` | Not JSON, unknown keys, wrong types, a malformed password object, attributes that do not validate, a non-UUID `id`, a line over 64 KiB, or the same email twice in one batch |
| `unknown_scheme` | `password.scheme` is not one of the schemes above |
| `weak_parameters` | Below the import floors |
| `over_cap` | Above the memory/CPU caps |
| `refused_variant` | A known but refused variant (bcrypt `$2x$`) |
| `unknown_profile` | `firebase_scrypt` names a hash profile the tenant does not have |
| `id_conflict` | The `id` is used by another user, or the email belongs to a user with another id |

### Report

Every import call returns this JSON report (the CLI prints a summary of it):

```json
{
  "dry_run": false,
  "counts": {"created": 2, "unchanged": 0, "conflict": 0, "updated": 0, "rejected": 1, "weak": 1},
  "records": [
    {"line": 1, "outcome": "created", "user_id": "0192f0c1-...", "weak": true},
    {"line": 2, "outcome": "created", "user_id": "0192f0c1-...", "weak": false},
    {"line": 3, "outcome": "rejected", "reason": "unknown_scheme", "weak": false}
  ]
}
```

`user_id` is the created, updated or matching user (for a dry-run `created`, the kept id if the
record named one). One call imports at most 1,000 records; a larger batch is refused as a whole
and nothing is imported.

### Dry run

A dry run validates every record (including the Firebase profile lookup and the comparison with
existing users) and returns the same report a real run would, without writing any user,
credential or attribute. It records only its own `users_imported` audit event with
`dry_run: true`.

### Audit

- One `users_imported` event per batch: the counts per outcome, the weak count, the source label
  and the dry-run flag.
- `user_created` (reason `imported`) for every created user, and `user_updated` (the changed field
  names, reason `imported`) for every updated user.
- `password_profile_created` and `password_profile_deleted` for hash profiles (name and kind).

No hash, salt, signer key or password field ever appears in audit details, logs, errors or the
report.

### First sign-in and re-hashing

When an imported user signs in, AnvilID verifies the password against the imported hash, using
the tenant hash profile for Firebase scrypt. On success it immediately replaces the stored hash
with an Argon2id hash of the same password. The replacement is a compare-and-swap on the old
value: if the password was changed in the meantime (for example a reset completed at the same
moment), the newer password is kept and the re-hash is dropped. A wrong password changes
nothing.

All schemes run in the same bounded hashing pool as Argon2, so imported hashes cannot exhaust
the server's CPU or memory beyond the configured concurrency.

### Timing

Sign-in for an unknown email always runs the Argon2 dummy hash, so unknown and known accounts are
not distinguishable by scheme. A known account with an imported hash can take a different time
than one with an Argon2id hash (for example scrypt with a large `N`), which reveals that the
account was imported. Both cases are existing accounts, so this does not reveal whether an
address is registered; the difference disappears as users sign in and are re-hashed.

## Export

Users can be exported in three ways. Each one has its own fixed list of fields (an allow-list).
A field added to the user model is not exported until it is added to the export on purpose.
Secrets are never exported: no TOTP seed, recovery code, passkey key material, sealed blob,
token hash, client secret or signer key. Password hashes are left out too, except for the one
command-line option described in [Password hashes](#password-hashes). Timestamps are RFC 3339 in
UTC with milliseconds (`2026-11-25T12:00:00.000Z`).

| Mode | Command line | Management API |
| --- | --- | --- |
| One user (JSON) | `anvilid users export --user <UUID>` | `GET /api/admin/v1/tenants/{slug}/users/{user_id}/export` |
| GDPR bundle (JSON) | `anvilid users export --user <UUID> --gdpr` | `GET /api/admin/v1/tenants/{slug}/users/{user_id}/export?profile=gdpr` |
| All users (NDJSON) | `anvilid users export` | `GET /api/admin/v1/tenants/{slug}/users/export` |

### Exporting from the command line

```sh
anvilid users export --tenant default --out users.ndjson
anvilid users export --tenant default --user 0192f0c1-1111-7aaa-8bbb-0123456789ab --gdpr --out ada.json
```

| Flag | Meaning |
| --- | --- |
| `--tenant <SLUG>` | Tenant to export (default `default`) |
| `--user <UUID>` | Export one user as a JSON document instead of every user |
| `--gdpr` | With `--user`: the GDPR data-subject bundle |
| `--include-password-hashes` | Bulk export only: add each user's stored password hash (see [Password hashes](#password-hashes)) |
| `--out <PATH>` | Write to a file created with mode 0600 (an existing file is truncated and tightened to 0600) instead of stdout |

Without `--out`, the output goes to stdout and the command prints no log or audit lines there, so
the output stays valid JSON or NDJSON. The audit event is still stored in the database.

### Exporting through the management API

- **Scope:** `admin:users:export`, or the `admin:write` umbrella. `admin:read`,
  `admin:users:read` and `admin:users:write` do not grant it, and get 403. Reading users one
  page at a time and pulling every user out in one call are separate grants.
- Responses carry `Cache-Control: no-store`.
- The only query parameter is `profile=gdpr` on the single-user route. Any other parameter is
  refused with a 422 problem, including every spelling of a password-hash option.
- A user of another tenant, or an unknown user, is a 404.
- The bulk route streams `application/x-ndjson`, one user per line in user id order. It reads the
  users 100 at a time, so the server never holds the whole tenant in memory. If reading fails
  after the response has started, the last line is `{"error":"export_failed"}` and the stream
  ends. Treat an output with that line as incomplete.

### User record

The single-user export and each line of the bulk export are a user record:

| Field | Content |
| --- | --- |
| `id`, `email`, `email_verified`, `username`, `status` | The user |
| `claims` | The OpenID Connect standard claims, field by field (`address` as an object) |
| `attributes` | Custom attribute values |
| `created_at`, `updated_at`, `last_login_at` | Timestamps |
| `roles` | Tenant roles (`id`, `name`) |
| `organizations` | Memberships: `org_id`, `slug`, `display_name`, `roles` |
| `identity_links` | Linked upstream accounts: `connection_id`, `connection` (slug or `null`), `subject` |
| `credentials` | Metadata only: `id`, `kind`, `label`, `created_at`, `last_used_at` |
| `password_hash` | Only in a command-line bulk export with `--include-password-hashes`, for users who have a password. Otherwise the field is absent |

### GDPR data-subject bundle

The bundle is a machine-readable copy of every category of personal data AnvilID stores about
one user, for access and portability requests:

| Key | Content |
| --- | --- |
| `export_format_version` | `1` |
| `generated_at` | When the bundle was produced |
| `subject` | `id`, `email`, `email_verified`, `username`, `status`, `claims`, `created_at`, `updated_at`, `last_login_at` |
| `attributes` | Custom attribute values |
| `credentials` | `items` (metadata as above), `password_set`, `totp_enrolled`, `recovery_codes_remaining` (a count) |
| `sessions` | Active sessions: `id`, `created_at`, `last_seen_at`, `auth_time`, `expires_at`, `authentication_methods`, `ip`, `user_agent` |
| `consents` | `client_id`, `scopes`, `resources`, `created_at`, `updated_at`, `revoked_at` |
| `token_families` | Refresh token families in every state: `id`, `client_id`, `scope`, `resources`, `created_at`, `expires_at`, `revoked_at`, `revoked_reason` (never token values or hashes) |
| `identity_links` | `connection_id`, `connection`, `subject`, `email_at_link`, `metadata`, `created_at`, `last_used_at` |
| `roles`, `organizations` | As in the user record |
| `audit_events` | Events where the user is the actor or the target: `id`, `at`, `action`, `outcome`, `actor`, `actor_client_id`, `target`, `ip`, `user_agent`, `details` |
| `pending_self_service_tokens` | Pending email verification, password reset and similar links, as `kind` and `expires_at` only |
| `operator_statement` | Always `null`. See below |

The bundle names other people only by role. In `audit_events`, `actor` is `subject`,
`administrator`, `another_user`, `system` or `client`. A client keeps its client id, because it
is an application and not a person. A target that is another user of the tenant becomes
`another_user`. IP address and user agent appear only on the subject's own events. Detail
values whose key mentions a user, an email or an actor are replaced with `redacted`, unless the
value is the subject's own id.

Webhook deliveries are not included: they are copies of the audit events that are already in
the bundle.

The bundle has no field for a password hash at all, and neither the command line nor the API
can add one.

#### Operator statement

A data-subject response also needs information that only the operator knows: the purposes of
processing, the recipients and the retention periods. AnvilID cannot know these, so
`operator_statement` is always `null`. Before handing the bundle over, fill in the slot as
`{"purposes": "...", "recipients": "...", "retention": "..."}`, or send that information
alongside the bundle.

### Password hashes

Password hashes leave AnvilID only through the command line:

```sh
anvilid users export --tenant default --include-password-hashes --out users-with-hashes.ndjson
```

- The option works only for the bulk export. The command refuses it together with `--user` or
  `--gdpr`.
- The command prints a warning on stderr. The output holds secrets: store it like a backup (the
  `--out` file is created with mode 0600) and delete it once the migration is done.
- The export is audited with `include_password_hashes: true`.

No HTTP route can export password hashes. The management API has no such option: the bulk
route uses an export without hashes, and unknown query parameters are refused. The single-user
export and the GDPR bundle never carry a hash.

### Export audit

Every export records one `user_exported` audit event with `mode` (`single`, `gdpr` or `bulk`),
`count` and `include_password_hashes`. Single and GDPR exports have the user as the target. A
bulk export over the API that ends early, because of a read error or because the client
disconnected, is recorded with outcome `failure` and the number of users sent so far. A refused
request (wrong scope, unknown user, invalid parameter) is not an export and records nothing.
