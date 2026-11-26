# Migrating users to AnvilID

AnvilID imports users together with their existing password hashes, so people keep signing in
with their old passwords. This page is the overview; the full reference (every field, scheme,
limit and reason code) is [Importing and exporting users](../IMPORT-EXPORT.md).

Guides for specific sources:

- [From Firebase Authentication](firebase.md)
- [From another AnvilID installation](anvilid.md)
- Any other system: convert its export to the record format below. The
  [password schemes](../IMPORT-EXPORT.md#password-schemes) cover bcrypt, Argon2, scrypt,
  PBKDF2 (raw, Django and passlib formats) and salted SHA-256/SHA-512.

Guides are only published for sources whose current export documentation has been checked; each
vendor guide names the documentation it was checked against and the date.

## How a migration works

1. **Prepare the tenant.** Create the tenant, its custom attribute definitions (if you import
   attributes) and, for Firebase, a [hash profile](../IMPORT-EXPORT.md#firebase-scrypt).
2. **Convert the export** of the old system into NDJSON: one JSON object per line.
3. **Dry run** the file and read the report.
4. **Import.** Run the same file again without `--dry-run`. Repeating an import is safe.
5. **Point your applications at AnvilID** (see the [integration guides](../guides/oidc-app.md)).
   Users sign in with their old passwords; each password is re-hashed with Argon2id at the first
   successful sign-in.

## The record format

```json
{"email": "ada@example.com", "email_verified": true, "id": "0192f0c1-1111-7aaa-8bbb-0123456789ab", "claims": {"name": "Ada Lovelace"}, "attributes": {"department": "R&D"}, "password": {"scheme": "bcrypt", "hash": "$2b$12$..."}}
```

Only `email` is required. `claims` holds OpenID Connect standard claims, `attributes` the
tenant's custom attributes, and `password` the imported hash. Unknown keys are refused, so a
typo cannot silently drop data. A user without `password` is created without one and can set a
password through account recovery (which needs SMTP).

The record has no fields for roles, organization memberships, linked upstream accounts, TOTP or
passkeys. Assign roles and memberships after the import; users enrol a second factor and
passkeys again.

## Keeping user ids (`sub`)

If the old system's user ids are UUIDs, put them in `id`: the user keeps that id, so the `sub`
claim your applications store does not change. Other id formats are refused with
`invalid_record`; keep such ids in a custom attribute (for example `legacy_id`) and map them in
your application. See [Keeping user ids](../IMPORT-EXPORT.md#keeping-user-ids).

## Running an import

```sh
anvilid users import users.ndjson --tenant default --source legacy-app --dry-run
anvilid users import users.ndjson --tenant default --source legacy-app
```

The command uses the server's configuration (run it with the same flags or environment as
`anvilid serve`) and can run next to a running server. It imports in batches of 1,000 records,
so files of any size work. The management API offers the same import for batches of up to 1,000
records: `POST /api/admin/v1/tenants/{slug}/users/import` with `Content-Type:
application/x-ndjson` and scope `admin:users:write`.

### Dry run and report

A dry run checks every record, including the comparison with existing users and the Firebase
profile lookup, and writes nothing. The real run returns the same report: one outcome per line
number (`created`, `unchanged`, `conflict`, `updated`, `rejected` with a reason code) plus
counts. Reports, logs and audit events never contain hashes, salts or the record contents.

### Running it again

Users are matched by tenant and email. Importing the same file again reports `unchanged` for
every user already imported, so you can fix rejected lines and re-run the whole file. A user that
exists with different data is a `conflict` and is left alone, unless you pass `--update`.

### Weak and over-cap hashes

- **Caps** limit the memory and CPU one verification may cost (for example scrypt at most
  64 MiB, bcrypt cost at most 16). A hash above a cap is rejected with `over_cap`.
- **Floors** refuse trivially weak data with `weak_parameters` (for example PBKDF2 below 1,000
  iterations, salts shorter than 8 bytes, MD5 and SHA-1 digests, unsalted digests).
- Hashes that pass the floors but are below today's recommendations (bcrypt cost below 10,
  PBKDF2 below 100,000 iterations, every salted SHA-2 hash) are imported and counted as `weak`
  in the report. They are replaced with Argon2id at first sign-in like every other imported
  hash; consider asking users who have not signed in for a while to reset their password.
- Schemes AnvilID does not verify (`unknown_scheme`) cannot be imported with a password. Import
  those users without `password`; they set a new one through account recovery.

The exact limits are in [Caps and floors](../IMPORT-EXPORT.md#caps-and-floors).

## First sign-in

At a user's first successful sign-in, AnvilID verifies the password against the imported hash and
immediately replaces it with an Argon2id hash. A wrong password changes nothing. Users who never sign in keep their imported hash, so a
Firebase hash profile stays in use until every user that references it has signed in once (a
referenced profile cannot be deleted).

## Leaving AnvilID

Your users are not locked in. `anvilid users export` writes every user of a tenant as NDJSON;
the admin API offers single, bulk and GDPR data-subject exports (scope `admin:users:export`).
Password hashes are exported only by the command line, on request, and audited:

```sh
anvilid users export --tenant default --include-password-hashes --out users-with-hashes.ndjson
```

The file holds secrets: it is created with mode 0600; delete it once the migration is done. The
stored formats are Argon2id PHC strings for users who signed in since the import, and otherwise
the imported hash in AnvilID's own encoding. [From another AnvilID installation](anvilid.md)
shows how to turn this export into import records. See [Export](../IMPORT-EXPORT.md#export) for
every field.

## Adding a guide for another source

A guide for a specific vendor is added only after checking that vendor's current, public export
documentation. It states which export fields map to which record fields and hash scheme, and ends
with a "Checked against" footer listing the documentation URLs and the date they were read.
