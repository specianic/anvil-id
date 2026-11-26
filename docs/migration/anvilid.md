# Migrating from another AnvilID installation

This guide moves the users of one tenant to another AnvilID installation (or another tenant),
with their password hashes and their user ids, so the `sub` claim your applications store stays
the same.

To move a **whole installation** (same database, new host), use a backup and restore instead
([Operating AnvilID](../OPERATIONS.md#backup-and-restore-sqlite)): it keeps everything,
including sessions, clients, keys and second factors. This guide is for moving users between
installations that otherwise stay separate.

You need shell access to the source installation (the password-hash export is command-line only),
`jq`, and the import command or management API on the target.

## 1. Move the tenant configuration first

Custom attribute definitions must exist on the target before users with attribute values are
imported. Copy the tenant configuration with the declarative YAML workflow
([Declarative tenant configuration](../CONFIG-YAML.md)):

```sh
# on the source
anvilid tenant export acme -o acme.yaml
# on the target: review the plan, then apply
anvilid tenant plan -f acme.yaml
anvilid tenant apply -f acme.yaml
```

An export never contains a secret. Fill in the secret references (`{env: NAME}` or
`{file: path}`) the document needs before applying it on the target; see
[Declarative tenant configuration](../CONFIG-YAML.md) for what is covered (organizations, for
example, are not part of the document).

If the source has Firebase hash profiles, create a profile with the same Firebase parameters on
the target (the signer key is never exported, so take it from the original Firebase project) and
note both profile ids. `GET /api/admin/v1/tenants/{slug}/password-hash-profiles` lists the ids on
each side.

## 2. Export the users with their hashes

On the source:

```sh
anvilid users export --tenant acme --include-password-hashes --out acme-users.ndjson
```

The command prints a warning, records a `user_exported` audit event with
`include_password_hashes: true` and creates the file with mode 0600. It holds every user's
password hash: copy it to the target over a secure channel and delete it afterwards.

`password_hash` in each line is AnvilID's stored form: an Argon2id PHC string for users who set or
used their password on the source, otherwise the hash imported there (bcrypt, or AnvilID's
`$anvil-…$` encoding for scrypt, Firebase scrypt, PBKDF2 and salted SHA-2).

## 3. Convert the export into import records

The export has more fields than the import accepts (roles, organizations, credentials, ...), and
the import takes the hash as a `password` object. Save this filter as `anvilid-to-anvilid.jq`:

```jq
# AnvilID `users export --include-password-hashes` -> AnvilID import records (NDJSON with jq -c).
# --argjson profiles '{"<source profile id>": "<target profile id>", ...}' (use '{}' without Firebase hashes)
def params: split(",") | map(split("=") | {(.[0]): (.[1] | tonumber? // .)}) | add;
def password:
  if startswith("$argon2") then {scheme: "argon2", hash: .}
  elif test("^\\$2[aby]\\$") then {scheme: "bcrypt", hash: .}
  else split("$") as $f | ($f[2] | params) as $p
  | if $f[1] == "anvil-scrypt" then
      {scheme: "scrypt", log_n: $p.ln, r: $p.r, p: $p.p, salt: {base64: $f[3]}, hash: {base64: $f[4]}}
    elif $f[1] == "anvil-pbkdf2" then
      {scheme: "pbkdf2", prf: $p.alg, iterations: $p.i, salt: {base64: $f[3]}, hash: {base64: $f[4]}}
    elif $f[1] == "anvil-sha2" then
      {scheme: "salted_sha2", alg: $p.alg, position: $p.pos, salt: {base64: $f[3]}, hash: {base64: $f[4]}}
    elif $f[1] == "anvil-firebase-scrypt" then
      {scheme: "firebase_scrypt",
       profile: ($profiles[$p.profile] // error("no target profile for \($p.profile)")),
       salt: {base64: $f[3]}, hash: {base64: $f[4]}}
    else error("unknown stored hash format") end
  end;
{id, email, email_verified,
 claims: ((.claims // {}) | with_entries(select(.value != null))),
 attributes: (.attributes // {})}
+ (if .password_hash then {password: (.password_hash | password)} else {} end)
```

Run it, with the profile id mapping from step 1 (or `'{}'`):

```sh
jq -c --argjson profiles '{}' -f anvilid-to-anvilid.jq acme-users.ndjson > acme-import.ndjson
```

Each record keeps `id`, `email`, `email_verified`, the standard claims and the custom attributes,
and gets the password hash in the matching scheme. The filter stops with an error on a Firebase
hash whose profile has no target id, instead of producing a record that would be rejected.

Before importing, decide about **blocked users**: the import has no status field, so every
imported user is active. To leave blocked users behind, add `select(.status == "active") |` at
the start of the last expression, or block them on the target after the import.

## 4. Import on the target

```sh
anvilid users import acme-import.ndjson --tenant acme --source anvilid-source --dry-run
anvilid users import acme-import.ndjson --tenant acme --source anvilid-source
```

- Every user keeps its id, so `sub` is unchanged (the target refuses an id that another user
  already has, with `id_conflict`).
- Users sign in with their existing passwords. Hashes that were not Argon2id yet are re-hashed at
  the first sign-in, as on the source.
- Running the import again reports `unchanged`.

## What does not move

The import record carries users, their claims, attributes and password hash. These stay behind
and are set up again on the target:

| Data | On the target |
| --- | --- |
| Usernames | not imported; users sign in with their email |
| Roles and organization memberships | assign again (the export lists them per user) |
| Linked upstream accounts | linked again at the user's next upstream sign-in, depending on the tenant's linking settings |
| TOTP, recovery codes, passkeys | users enrol again |
| Sessions, consents, refresh tokens | users sign in again; consent is asked again where needed |

## Verification of this guide

The export, this filter and the import were run between two AnvilID 1.0 instances with users
holding Argon2id, bcrypt, scrypt, Firebase scrypt, PBKDF2 and salted SHA-2 hashes: every user
signed in on the target with the original password, the user ids were identical on both sides and
a second import reported only `unchanged`.
