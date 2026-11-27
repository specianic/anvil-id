# Migrating from Clerk

Clerk's Dashboard exports a CSV of an application's users that includes each user's password
digest and the name of the hasher that produced it. AnvilID verifies the digests of several of
those hashers (bcrypt, Argon2 and PBKDF2 variants), so those users keep their passwords: each one
is re-hashed with Argon2id at the user's first sign-in. Users with a digest from any other hasher
are imported without a password.

You need admin access to the Clerk workspace, Python 3, and access to the `anvilid` command (or an
AnvilID management token with `admin:users:write`).

## 1. Export the users

Clerk's documentation describes the export: workspace admins (and anyone in a personal
workspace) open the instance's **Settings**, select **Export users** in the **User exports**
section, and **Download** the new entry in the export history.

Only the Dashboard export contains password digests. The `clerk migrate export clerk` command and
the Backend API cannot include them; users exported that way can only be imported without a
password.

The file holds password digests and TOTP secrets: treat it as a secret and delete it after the
migration.

## 2. The export format

Clerk's documentation does not list the CSV columns. The names below are the ones Clerk's own
migration CLI reads from a Dashboard export; check them against the header of your file:

| Column | Content |
| --- | --- |
| `id` | Clerk user id (`user_...`) |
| `primary_email_address` | primary email |
| `verified_email_addresses`, `unverified_email_addresses` | lists of addresses |
| `first_name`, `last_name`, `username` | profile |
| `password_digest`, `password_hasher` | the digest and the hasher name |

- Clerk's CLI reads a list column either as a JSON array or as values separated by `,` or `|`, and
  treats the primary email as verified unless it is listed in `unverified_email_addresses`. The
  script below does the same.
- The Dashboard prefixes a TAB to any value that starts with `=`, `+`, `-` or `@` so spreadsheets
  do not run it as a formula. The script removes that prefix.
- Clerk documents the digest format of each hasher for its user import. Its CLI imports the
  Dashboard export's `password_digest` and `password_hasher` unchanged, so the script expects the
  digests in those documented formats.

| `password_hasher` | Digest format (Clerk documentation) | AnvilID record |
| --- | --- | --- |
| `bcrypt` | `$<version>$<cost>$<salt and hash>` | `bcrypt` |
| `argon2i`, `argon2id` | PHC string `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>` | `argon2` |
| `pbkdf2_sha256_django` | `pbkdf2_sha256$<iterations>$<salt>$<base64 hash>` | `django_pbkdf2` |
| `pbkdf2_sha256` | `pbkdf2_sha256$<iterations>$<base64 salt>$<base64 hash>` | `pbkdf2`, `prf: "sha256"` |
| `pbkdf2_sha512` | `pbkdf2_sha512$<iterations>$<salt string>$<hex hash>` | `pbkdf2`, `prf: "sha512"`, the salt string's UTF-8 bytes as salt |
| `pbkdf2_sha512_hex` | `pbkdf2_sha512_hex$<iterations>$<hex salt>$<hex hash>` | `pbkdf2`, `prf: "sha512"` |
| any other hasher | | no password |

The other hashers Clerk accepts are not converted: `md5`, `md5_salted`, `sha256`, `md5_phpass`,
`phpass` and `ldap_ssha` are digests AnvilID refuses (MD5, SHA-1 or unsalted); `bcrypt_peppered`
and `bcrypt_sha256_django` alter the password before bcrypt, and `awscognito` is a reference to a
Cognito user pool rather than a hash. `sha512_symfony` (iterated SHA-512) has no matching AnvilID
scheme. `sha256_salted` (the documentation does not say where the salt goes), `pbkdf2_sha1` (the
salt may be hex or raw), `scrypt_werkzeug` (the parameter format is not spelled out) and
`scrypt_firebase` (each digest carries the Firebase project's signer key and parameters) are left
out of the script; if many of your users have one of these, convert them by hand to the matching
[password scheme](../IMPORT-EXPORT.md#password-schemes). For `scrypt_firebase`, create a hash
profile from the parameters in the digest as described in
[From Firebase Authentication](firebase.md).

## 3. Convert the export

Save this script as `clerk-to-anvilid.py`:

```python
"""Clerk Dashboard user export (CSV) -> AnvilID import records (NDJSON on stdout).

Usage: python3 clerk-to-anvilid.py users.csv > users.ndjson
"""
import base64
import csv
import json
import re
import sys

FORMULA = re.compile(r"^\t(?=[=+\-@\t\r\n＝＋－＠])")


def cell(row, name):
    # The Dashboard prefixes a TAB to values that start with = + - @ (spreadsheet safety).
    return FORMULA.sub("", (row.get(name) or "").strip("\r\n")).strip()


def addresses(row, name):
    value = cell(row, name)
    if value.startswith("["):
        return [str(v).strip() for v in json.loads(value) if str(v).strip()]
    return [v.strip() for v in re.split(r"[,|]", value) if v.strip()]


def password(hasher, digest):
    if not digest:
        return None
    if hasher == "bcrypt" and re.match(r"^\$2[aby]\$", digest):
        return {"scheme": "bcrypt", "hash": digest}
    if hasher in ("argon2i", "argon2id"):
        return {"scheme": "argon2", "hash": digest}
    if hasher == "pbkdf2_sha256_django":
        return {"scheme": "django_pbkdf2", "hash": digest}
    parts = digest.split("$")
    if hasher == "pbkdf2_sha256" and len(parts) == 4:
        # pbkdf2_sha256$<iterations>$<base64 salt>$<base64 hash>
        return {"scheme": "pbkdf2", "prf": "sha256", "iterations": int(parts[1]),
                "salt": {"base64": parts[2]}, "hash": {"base64": parts[3]}}
    if hasher == "pbkdf2_sha512" and len(parts) == 4:
        # pbkdf2_sha512$<iterations>$<salt string>$<hex hash>; the salt string is used as is
        return {"scheme": "pbkdf2", "prf": "sha512", "iterations": int(parts[1]),
                "salt": {"base64": base64.b64encode(parts[2].encode()).decode()},
                "hash": {"hex": parts[3]}}
    if hasher == "pbkdf2_sha512_hex" and len(parts) == 4:
        # pbkdf2_sha512_hex$<iterations>$<hex salt>$<hex hash>
        return {"scheme": "pbkdf2", "prf": "sha512", "iterations": int(parts[1]),
                "salt": {"hex": parts[2]}, "hash": {"hex": parts[3]}}
    return None  # every other hasher: imported without a password


with open(sys.argv[1], newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        email = cell(row, "primary_email_address")
        if not email:
            continue  # phone-only or username-only users
        record = {"email": email,
                  "email_verified": email not in addresses(row, "unverified_email_addresses")}
        claims = {k: v for k, v in (("given_name", cell(row, "first_name")),
                                    ("family_name", cell(row, "last_name")),
                                    ("preferred_username", cell(row, "username"))) if v}
        name = " ".join(v for v in (claims.get("given_name"), claims.get("family_name")) if v)
        if name:
            claims["name"] = name
        if claims:
            record["claims"] = claims
        pw = password(cell(row, "password_hasher"), cell(row, "password_digest"))
        if pw:
            record["password"] = pw
        print(json.dumps(record, ensure_ascii=False))
```

and run it:

```sh
python3 clerk-to-anvilid.py users.csv > users.ndjson
```

| Clerk column | AnvilID record |
| --- | --- |
| `primary_email_address` | `email`; users without one (phone-only, username-only) are skipped |
| `unverified_email_addresses` | `email_verified` is `false` when the primary email is listed there |
| `first_name`, `last_name`, `username` | `claims.given_name`, `claims.family_name`, `claims.name`, `claims.preferred_username` |
| `password_digest`, `password_hasher` | `password`, see the table in step 2 |

- Clerk user ids (`user_...`) are not UUIDs, so they cannot become the AnvilID user id (`sub`).
  If your applications store them, define a custom attribute (for example `clerk_id`) in the
  tenant first and add `record["attributes"] = {"clerk_id": cell(row, "id")}` to the script,
  then map the old ids in your applications.
- AnvilID users have one email address. Additional verified addresses, phone numbers, TOTP
  secrets, metadata, organizations, social accounts and passkeys are not converted; assign
  memberships after the import, and users enrol a second factor and passkeys again.

## 4. Import

```sh
anvilid users import users.ndjson --tenant default --source clerk --dry-run
anvilid users import users.ndjson --tenant default --source clerk
```

Check the dry-run report first: every line should be `created` (or `unchanged` when you re-run).
A `malformed` line has a digest that does not have the format its hasher name promises; remove its
`password` key to import that user without a password. bcrypt hashes with a cost below 10 and
PBKDF2 hashes below 100,000 iterations are counted as `weak`; hashes above the caps are rejected
with `over_cap`.

## 5. After the import

- Users sign in with their Clerk passwords. At the first successful sign-in the hash is replaced
  with Argon2id.
- Sign in with a test account right after the import to confirm the conversion.

## Verification of this guide

The script was run on a synthetic CSV with the column names above: users with locally generated
`bcrypt`, `argon2id`, `pbkdf2_sha256` (600,000 iterations), `pbkdf2_sha512` and
`pbkdf2_sha512_hex` (210,000 iterations) digests in the documented formats, an `md5` digest, a
TAB-prefixed username, an unverified primary email, a comma-separated address list and a
phone-only user. On an AnvilID 1.0 build the bcrypt, Argon2id and PBKDF2 users signed in with
their original passwords and a wrong password was refused; the `md5` user was imported without a password and the phone-only user
was skipped. No real Clerk export was used, so the exact digest strings of a real export were not
seen.

---

Checked against (read on 2026-11-27):

- Clerk documentation, "Export your users from Clerk":
  <https://clerk.com/docs/guides/development/migrating/export-from-clerk>: Dashboard export
  steps and who can run it, only the Dashboard export contains password digests and TOTP
  secrets, CLI and Backend API exports cannot.
- Clerk documentation, "Migrate between Clerk instances":
  <https://clerk.com/docs/guides/development/migrating/clerk-to-clerk>: the Dashboard export
  includes each user's password digest, password hasher and TOTP secret; verified and unverified
  emails and phones are exported separately.
- Clerk documentation, `createUser()`:
  <https://clerk.com/docs/references/backend/user/create-user>: the list of password hashers and
  the digest format of each.
- Clerk CLI source code (`clerk/cli`, main branch), for the CSV details the documentation does not
  list:
  - <https://github.com/clerk/cli/blob/main/packages/cli-core/src/commands/migrate/sources/clerk.ts>:
    the Dashboard CSV column names, the TAB prefix on formula-like values.
  - <https://github.com/clerk/cli/blob/main/packages/cli-core/src/commands/migrate/lib/transform.ts>:
    list columns as JSON arrays or `,`/`|`-separated values; an unverified primary address is
    listed under the unverified column.
