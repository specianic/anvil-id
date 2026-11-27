# Migrating from Supabase Auth

Supabase Auth stores users in the `auth.users` table of the project's Postgres database, with the
password hash in the `encrypted_password` column. Supabase documents that it hashes passwords with
bcrypt and that it can also read imported Argon2 hashes. AnvilID verifies both (the `bcrypt` and
`argon2` schemes), so users keep their passwords: each one is re-hashed with Argon2id at the
user's first sign-in. Supabase user ids are UUIDs, so they are kept and the `sub` claim your
applications store does not change.

You need the project's database connection string and password, `psql`, `jq`, and access to the
`anvilid` command (or an AnvilID management token with `admin:users:write`).

## 1. Connect to the database

Supabase's documentation says the Auth schema is not exposed through the auto-generated API, so
read it with a direct database connection. In the Supabase dashboard, click **Connect** at the top
of the project page, copy a connection string (the direct connection, or the session pooler from
an IPv4-only network) and put your database password into it.

## 2. Export the users

Run this query and write one JSON object per line:

```sh
psql "<connection string>" -At -c "
  select json_build_object(
    'id', id, 'email', email, 'email_confirmed_at', email_confirmed_at,
    'encrypted_password', encrypted_password, 'raw_user_meta_data', raw_user_meta_data)
  from auth.users
  where email is not null" > supabase-users.ndjson
```

`-A -t` prints the bare rows without headers or alignment, so each line is one JSON object. The
file holds password hashes: treat it as a secret and delete it after the migration.

| Column | Meaning (Supabase documentation) |
| --- | --- |
| `id` | the user id (`uuid`) |
| `email` | the user's email |
| `email_confirmed_at` | `null` when the email is not confirmed |
| `encrypted_password` | the password hash (despite the name, a hash, not encrypted) |
| `raw_user_meta_data` | the user metadata your application set |

## 3. Convert the export

Save this filter as `supabase-to-anvilid.jq`:

```jq
# Rows of auth.users (one JSON object per line) -> AnvilID import records (NDJSON with jq -c).
def hash: .encrypted_password // "";
select((.email // "") != "")
| {id: .id, email: .email, email_verified: (.email_confirmed_at != null)}
  + (if hash | test("^\\$2[aby]\\$") then {password: {scheme: "bcrypt", hash: hash}}
     elif hash | test("^\\$argon2(id|i|d)\\$") then {password: {scheme: "argon2", hash: hash}}
     else {} end)
```

and run it:

```sh
jq -c -f supabase-to-anvilid.jq supabase-users.ndjson > users.ndjson
```

| `auth.users` column | AnvilID record |
| --- | --- |
| `id` | `id` (the user keeps the id) |
| `email` | `email`; users without an email (phone-only or anonymous) are not exported |
| `email_confirmed_at` | `email_verified` (`true` when set) |
| `encrypted_password` | `password` with scheme `bcrypt` (`$2a$`, `$2b$`, `$2y$`) or `argon2` (`$argon2id$`, `$argon2i$`, `$argon2d$`) |

- Supabase's documentation names bcrypt and Argon2 but does not specify the exact string format
  of the column. The filter recognises bcrypt modular crypt strings and Argon2 PHC strings; any
  other value, and an empty value (a user without a password), is imported without a password. Those users set a password through account
  recovery or sign in with an upstream provider you configure in AnvilID.
- `raw_user_meta_data` is free-form data your application wrote, so the filter does not convert
  it. To keep a display name, add for example
  `+ (if (.raw_user_meta_data.name // "") != "" then {claims: {name: .raw_user_meta_data.name}} else {} end)`
  using the key your application uses; other values go into custom attributes, which must be
  defined in the tenant first.
- Other columns (phone, app metadata, timestamps) are not converted. Linked OAuth identities,
  MFA factors and sessions are not migrated; users enrol a second factor again. Users you have
  banned or deleted in Supabase are not marked as such by the import: the record has no field for
  it, so leave them out of the query if they should not get an account.

## 4. Import

```sh
anvilid users import users.ndjson --tenant default --source supabase --dry-run
anvilid users import users.ndjson --tenant default --source supabase
```

Check the dry-run report first: every line should be `created` (or `unchanged` when you re-run).
A line rejected with `id_conflict` has an id that another user in the tenant already has. bcrypt
hashes with a cost below 10 are counted as `weak`; Argon2 hashes above the memory, time or
parallelism caps are rejected with `over_cap`.

## 5. After the import

- Users sign in with their Supabase passwords. At the first successful sign-in the hash is
  replaced with Argon2id.
- Your application's own tables that reference `auth.users.id` keep working with the AnvilID
  `sub`, because the ids are unchanged.
- Sign in with a test account right after the import to confirm the conversion.

## Verification of this guide

The filter was run on synthetic rows shaped like the query output: a confirmed user with a
locally generated `$2a$10$` bcrypt hash, an unconfirmed user with an empty `encrypted_password`,
and a user with an Argon2id PHC string. On an AnvilID 1.0 build the bcrypt and Argon2id users
signed in with their original passwords and kept their ids. The `psql` export step was not run
against a Supabase project, and no real user data was used.

---

Checked against (read on 2026-11-27):

- Supabase documentation, "Password security":
  <https://supabase.com/docs/guides/auth/password-security>: bcrypt with a random salt per hash,
  hash stored in `auth.users.encrypted_password`, the column name is a misnomer.
- Supabase documentation, "Migrate from Auth0 to Supabase Auth":
  <https://supabase.com/docs/guides/platform/migrating-to-supabase/auth0>: Supabase supports
  bcrypt and Argon2 password hashes; new password users always get a bcrypt hash.
- Supabase documentation, "Managing user data":
  <https://supabase.com/docs/guides/auth/managing-user-data>: `auth.users` id is a `uuid`, user
  metadata in `raw_user_meta_data`, the Auth schema is not exposed in the auto-generated API.
- Supabase documentation, "Users": <https://supabase.com/docs/guides/auth/users>:
  `email_confirmed_at` is null when the email is not confirmed.
- Supabase documentation, "Connect to your database":
  <https://supabase.com/docs/guides/database/connecting-to-postgres>: the **Connect** button,
  direct connection and session pooler, connecting with `psql`.
- Supabase documentation, "Migrating Auth users between projects":
  <https://supabase.com/docs/guides/troubleshooting/migrating-auth-users-between-projects>: the
  auth schema, including users and their hashed passwords, can be exported with standard
  Postgres tools.
