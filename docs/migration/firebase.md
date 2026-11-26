# Migrating from Firebase Authentication

Firebase Authentication hashes passwords with its own modified scrypt and project-wide
parameters. AnvilID verifies these hashes with the published algorithm (the `firebase_scrypt`
scheme), so users keep their passwords: each one is re-hashed with Argon2id at the user's first
sign-in.

You need the Firebase CLI with access to the project, `jq`, and an AnvilID management token with
`admin:settings:write` and `admin:users:write` (or `admin:write`).

## 1. Get the project's password hash parameters

Firebase's documentation describes where to find them: in the Firebase console, open
**Authentication**, then **Users**, and open the menu (three dots) above the list of users. The
dialog shows a block like this:

```
hash_config {
  algorithm: SCRYPT,
  base64_signer_key: <...sensitive...>,
  base64_salt_separator: <...sensitive...>,
  rounds: 8,
  mem_cost: 14,
}
```

The signer key and the salt separator are sensitive: anyone with them and the exported hashes can
attack the passwords offline. Do not paste them into tickets or chat.

## 2. Export the users

```sh
firebase auth:export users.json --format=json --project <your-project-id>
```

Firebase's documentation notes that:

- the export contains password hashes only for accounts hashed with Firebase's scrypt. Accounts
  whose passwords are still in another format (for example imported into Firebase and never
  signed in since) are exported with empty `passwordHash` and `salt`;
- the password hash and salt fields require the Editor or Owner role on the project.

Treat `users.json` as a secret and delete it after the migration.

## 3. Create a hash profile in AnvilID

The project parameters go into a tenant **hash profile** (console: **Password hash profiles**, or
the management API):

```sh
curl -sS -X POST "https://id.example.com/api/admin/v1/tenants/default/password-hash-profiles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "firebase-prod", "kind": "firebase_scrypt",
       "signer_key": "<base64_signer_key>", "salt_separator": "<base64_salt_separator>",
       "rounds": 8, "mem_cost": 14}'
```

Copy `base64_signer_key` and `base64_salt_separator` exactly as Firebase shows them, and `rounds`
and `mem_cost` from the same dialog. The answer contains the profile `id`. The signer key is
write-only: AnvilID stores it encrypted with its key-encryption key and never returns it.

| Firebase parameter | Profile field |
| --- | --- |
| `base64_signer_key` | `signer_key` |
| `base64_salt_separator` | `salt_separator` |
| `rounds` | `rounds` |
| `mem_cost` | `mem_cost` |

## 4. Convert the export

Save this filter as `firebase-to-anvilid.jq`:

```jq
# Firebase `auth:export --format=json` -> AnvilID import records (NDJSON with jq -c).
# --arg profile <id of the AnvilID hash profile holding the project's hash parameters>
def std64: gsub("-"; "+") | gsub("_"; "/");
.users[]
| select((.email // "") != "")
| {email: .email, email_verified: (.emailVerified // false)}
  + (if (.displayName // "") != "" then {claims: {name: .displayName}} else {} end)
  + (if (.passwordHash // "") != "" and (.salt // "") != "" then
       {password: {scheme: "firebase_scrypt", profile: $profile,
                   salt: {base64: (.salt | std64)}, hash: {base64: (.passwordHash | std64)}}}
     else {} end)
```

and run it with the profile id from step 3:

```sh
jq -c --arg profile "<profile id>" -f firebase-to-anvilid.jq users.json > users.ndjson
```

What the filter does:

| Firebase field | AnvilID record |
| --- | --- |
| `email` | `email`; accounts without an email (phone-only or anonymous) are skipped |
| `emailVerified` | `email_verified` |
| `displayName` | `claims.name` |
| `passwordHash`, `salt` | `password` with scheme `firebase_scrypt`, the profile id, and both values as base64 |

- Both base64 alphabets are accepted: the filter turns URL-safe characters (`-`, `_`) into the
  standard ones (`+`, `/`) before the import.
- Accounts with an empty `passwordHash` are imported without a password. Those users set a
  password through account recovery, or sign in with an upstream provider you configure in
  AnvilID.
- Firebase user ids (`localId`) are not UUIDs, so they cannot become the AnvilID user id (`sub`).
  If your applications store them, define a custom attribute (for example `firebase_uid`) in the
  tenant first and add `attributes: {firebase_uid: .localId}` to each record, then map the old ids
  in your applications.
- Other fields of the export (photo URL, phone number, provider data, timestamps) are not
  converted. Add them to `claims` yourself if you need them (for example `picture`,
  `phone_number`).

## 5. Import

```sh
anvilid users import users.ndjson --tenant default --source firebase --dry-run
anvilid users import users.ndjson --tenant default --source firebase
```

Check the dry-run report first: every line should be `created` (or `unchanged` when you re-run).
A line rejected with `unknown_profile` names a profile id the tenant does not have. The parameters
of the profile are checked against the scrypt memory cap (64 MiB) when the profile is created;
Firebase's default `rounds: 8`, `mem_cost: 14` need 16 MiB.

## 6. After the import

- Users sign in with their Firebase passwords. At the first successful sign-in the hash is
  replaced with Argon2id.
- A wrong signer key or salt separator does not show up at import time (the import cannot know
  the passwords). Sign in with a test account right after the import to confirm the profile.
- The profile can be deleted once no stored password references it any more (AnvilID refuses to
  delete a profile in use).

## Verification of this guide

The conversion filter and the import were run against an AnvilID 1.0 build with the sample
account and project parameters published in the firebase/scrypt README (`user1password`): the
imported user signed in with the original password, also with the hash and salt rewritten in the
URL-safe alphabet.

---

Checked against (read on 2026-11-26):

- Firebase documentation, "auth:import and auth:export":
  <https://firebase.google.com/docs/cli/auth> (page marked "Last updated 2026-11-19 UTC"): password
  hash parameters dialog, `auth:export` command and JSON file format, scrypt-only hash export,
  Editor/Owner role for hash fields.
- firebase/scrypt, README: <https://github.com/firebase/scrypt>: where to find the password hash
  parameters, the meaning of signer key, salt separator, rounds and mem_cost, and the published
  sample values.
