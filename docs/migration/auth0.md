# Migrating from Auth0

Auth0 does not hand out password hashes through its dashboard, Management API or bulk user
export. Its documentation describes a separate route: a password hash export requested from Auth0
support. With that file, users keep their passwords in AnvilID; the sample in Auth0's
documentation is a bcrypt string, which AnvilID verifies with the `bcrypt` scheme. Each password is
re-hashed with Argon2id at the user's first sign-in.

You need tenant administrator access to the Auth0 tenant, a PGP key pair, `jq`, and access to the
`anvilid` command (or an AnvilID management token with `admin:users:write`).

If you cannot get the hash export, you can still import the users from the bulk export alone
(step 2) without passwords: they set a new password through account recovery, or sign in with an
upstream provider you configure in AnvilID.

## 1. Request the password hash export

Auth0's documentation describes the process:

- A tenant administrator opens a support case asking for a password hash export, naming the
  tenant and attaching their PGP public key in ASCII-armored form (the key needs a 4096-bit RSA
  encryption subkey).
- Auth0 reviews eligibility ("not all requests qualify") and asks for a written authorization, a
  confirmation from another tenant administrator, and a signed acknowledgment form from an
  executive-level representative.
- The file is PGP-encrypted before it leaves Auth0. The download link expires after 3 days and
  works only for the administrator who opened the case.

Decrypt the download with your private key:

```sh
gpg --output auth0-hashes.ndjson --decrypt <downloaded file>.pgp
```

Auth0's support article on this export describes the decrypted file as NDJSON, one user per line:

```json
{"_id": "5dea9f9c82dd7c0e76e4ec93", "connection": "Username-Password-Authentication", "email": "user@example.com", "email_verified": false, "identifiers": [{"type": "email", "value": "user@example.com", "verified": false}], "passwordHash": "$2b$10$...", "tenant": "example-tenant-name", "version": "1.1"}
```

- `email` and `email_verified` may be missing for some users; the same values are in the
  `identifiers` array.
- `alt_id` is present for users that came from a custom database that provides the user id. The
  Auth0 user id is `auth0|` followed by `alt_id`, or by `_id` when there is no `alt_id`.
- The file has no profile or metadata fields. Those come from the bulk export.
- The article does not name the hashing algorithm. Its sample value has the bcrypt format
  (`$2b$10$...`). Any value that is not a bcrypt string is left out by the filter below, so that
  user is imported without a password.

Treat the decrypted file as a secret and delete it after the migration.

## 2. Export the user profiles

Create a bulk user export job with the Management API (`POST /api/v2/jobs/users-exports`) or the
dashboard. Ask for JSON and the fields you want to keep:

```json
{"format": "json", "fields": [{"name": "user_id"}, {"name": "email"}, {"name": "email_verified"},
  {"name": "name"}, {"name": "given_name"}, {"name": "family_name"}]}
```

Poll `GET /api/v2/jobs/{id}` until the job is done and download the file from its `location` URL
(the link is valid for 60 seconds; the job and its data are deleted after 24 hours). The file is
NDJSON. Auth0 documents that bulk exports are not available on the Free plan. Save the file as
`auth0-profiles.ndjson`, decompressing it first if needed.

## 3. Convert the export

Save this filter as `auth0-to-anvilid.jq`:

```jq
# Auth0 password hash export (NDJSON) + bulk user export (NDJSON) -> AnvilID import records.
# Run with: jq -n -c --slurpfile profiles <bulk export> -f auth0-to-anvilid.jq <hash export>
def bcrypt_mcf: type == "string" and test("^\\$2[aby]\\$");
($profiles | map({key: .user_id, value: .}) | from_entries) as $by_id
| inputs
| (first(.identifiers[]? | select(.type == "email")) // {}) as $ident
| (.email // $ident.value // "") as $email
| select($email != "")
| ($by_id["auth0|" + (.alt_id // ._id)] // {}) as $p
| {email: $email,
   email_verified: (if has("email_verified") then .email_verified else ($ident.verified // false) end)}
  + ({name: $p.name, given_name: $p.given_name, family_name: $p.family_name}
     | with_entries(select(.value != null and .value != ""))
     | if . == {} then {} else {claims: .} end)
  + (if .passwordHash | bcrypt_mcf then {password: {scheme: "bcrypt", hash: .passwordHash}} else {} end)
```

and run it:

```sh
jq -n -c --slurpfile profiles auth0-profiles.ndjson -f auth0-to-anvilid.jq auth0-hashes.ndjson > users.ndjson
```

| Auth0 field | AnvilID record |
| --- | --- |
| `email` (or the `identifiers` entry of type `email`) | `email`; users without an email are skipped |
| `email_verified` (or `identifiers[].verified`) | `email_verified` |
| `passwordHash` (bcrypt string) | `password` with scheme `bcrypt` |
| bulk export `name`, `given_name`, `family_name` | `claims` |

- The hash export and the bulk export are joined on the Auth0 user id (`auth0|` + `alt_id` or
  `_id`).
- Auth0 user ids (`auth0|...`) are not UUIDs, so they cannot become the AnvilID user id (`sub`).
  If your applications store them, define a custom attribute (for example `auth0_user_id`) in the
  tenant first and add `attributes: {auth0_user_id: ("auth0|" + (.alt_id // ._id))}` to each
  record, then map the old ids in your applications.
- The hash export only covers database users. Users of social or enterprise connections are in
  the bulk export only; import them without `password` and configure the matching upstream
  provider in AnvilID.
- `user_metadata`, `app_metadata`, roles and MFA enrolments are not converted. Map metadata to
  custom attributes yourself if you need it; users enrol a second factor again.

## 4. Import

```sh
anvilid users import users.ndjson --tenant default --source auth0 --dry-run
anvilid users import users.ndjson --tenant default --source auth0
```

Check the dry-run report first: every line should be `created` (or `unchanged` when you re-run).
bcrypt hashes with a cost below 10 are imported and counted as `weak`; costs above 16 are
rejected with `over_cap`; `$2x$` hashes are rejected with `refused_variant`.

## 5. After the import

- Users sign in with their Auth0 passwords. At the first successful sign-in the hash is replaced
  with Argon2id.
- Sign in with a test account right after the import to confirm the conversion.
- Delete `auth0-hashes.ndjson`, the encrypted download and `users.ndjson` once the import is done.

## Verification of this guide

The filter was run on synthetic files shaped like the samples in Auth0's documentation (one user
with a root `email`, one with only an `identifiers` entry and an `alt_id`), with bcrypt `$2b$10$`
hashes generated locally. The output was imported into an AnvilID 1.0 build: both users signed in
with their original passwords, a wrong password was refused, and the users signed in again after
the re-hash. No real Auth0 export was used.

---

Checked against (read on 2026-11-27):

- Auth0 documentation, "Export Password Hashes and MFA Secrets":
  <https://auth0.com/docs/manage-users/user-migration/export-password-hashes-and-mfa-secrets>:
  support case, tenant administrator, PGP key requirements, authorization and acknowledgment,
  3-day download link, `gpg --decrypt`. The page does not describe the file format or algorithm.
- Auth0 support article, "Migrate Users Using the Password Hashes Export in Auth0":
  <https://support.auth0.com/center/s/article/How-to-Use-the-Password-Hashes-Export-from-Auth0>
  (marked updated Oct 1, 2026): NDJSON format, sample record and fields (`_id`, `alt_id`,
  `connection`, `email`, `email_verified`, `identifiers`, `passwordHash`), no metadata in the
  export, user id `auth0|` + `alt_id` or `_id`.
- Auth0 documentation, "Bulk User Exports":
  <https://auth0.com/docs/manage-users/user-migration/bulk-user-exports>: export job, `fields`,
  NDJSON format, `location` download link valid for 60 seconds, 24-hour job lifetime, not on the
  Free plan.
- Auth0 documentation, "Data Export and Transfer Policy":
  <https://auth0.com/docs/troubleshoot/customer-support/operational-policies/data-export-and-transfer-policy>:
  export tools and the Management API do not return password hashes of Auth0-hosted database
  users; they can be requested through a support ticket.
- Auth0 documentation, "User Profile Structure":
  <https://auth0.com/docs/manage-users/user-accounts/user-profiles/user-profile-structure>: the
  attribute names `user_id`, `email`, `email_verified`, `name`, `given_name`, `family_name`.
