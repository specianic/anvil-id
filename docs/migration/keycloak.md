# Migrating from Keycloak

Keycloak stores password hashes with Argon2 (its default for non-FIPS deployments) or PBKDF2
(SHA-512, SHA-256 or SHA-1). A realm export made with `kc.sh export` contains the users, their
ids and their password credentials. AnvilID verifies Argon2 hashes with the `argon2` scheme and
PBKDF2 hashes with the `pbkdf2` scheme, so users keep their passwords: each one is re-hashed with
Argon2id at the user's first sign-in. Keycloak user ids that are UUIDs are kept, so the `sub` claim
your applications store does not change.

You need shell access to the Keycloak installation, `jq`, and access to the `anvilid` command (or
an AnvilID management token with `admin:users:write`).

## 1. Export the realm

Keycloak's documentation describes the `export` command. The Keycloak server must not be running
while it runs, and all nodes of a cluster should be stopped:

```sh
bin/kc.sh export --dir ./keycloak-export --realm my-realm --users same_file
```

`--users` takes `different_files` (the default, 50 users per file), `same_file`, `realm_file` or
`skip`. The filter below reads the `users` array of each file you pass it and ignores files
without one.

The export from the admin console (**Realm settings**, **Partial export**) does not contain users
and masks secrets, so it cannot be used for a migration. Keycloak's export code writes each user's
stored credentials (except for service-account users), which is what carries the password
hashes. Treat the export as a secret and delete it after the migration.

## 2. The credential format

Each user in the export has a `credentials` array. A password credential has `type: "password"`
and two JSON documents stored as strings. Keycloak's documentation does not describe them; their
fields are defined in Keycloak's source code (see the footer):

```json
{"type": "password",
 "secretData": "{\"value\":\"<base64 hash>\",\"salt\":\"<base64 salt>\",\"additionalParameters\":{}}",
 "credentialData": "{\"hashIterations\":5,\"algorithm\":\"argon2\",\"additionalParameters\":{\"hashLength\":[\"32\"],\"memory\":[\"7168\"],\"type\":[\"id\"],\"version\":[\"1.3\"],\"parallelism\":[\"1\"]}}"}
```

| Keycloak `algorithm` | Parameters | AnvilID record |
| --- | --- | --- |
| `argon2` | `hashIterations`, and `type` (`id`, `i`, `d`), `version` (`1.3`, `1.0`), `memory` (KiB), `parallelism` in `additionalParameters` | `argon2` with a PHC string built from these values |
| `pbkdf2-sha512` | `hashIterations` | `pbkdf2`, `prf: "sha512"` |
| `pbkdf2-sha256` | `hashIterations` | `pbkdf2`, `prf: "sha256"` |
| `pbkdf2` (PBKDF2 with SHA-1, deprecated in Keycloak) | `hashIterations` | `pbkdf2`, `prf: "sha1"` |

In both `secretData` fields the hash and the salt are standard base64. Keycloak's documented
defaults are Argon2id version 1.3 with 5 iterations, 7,168 KiB of memory, parallelism 1 and a
32-byte hash; and 210,000 iterations for `pbkdf2-sha512`, 600,000 for `pbkdf2-sha256` and
1,300,000 for `pbkdf2`. Changing the algorithm in Keycloak does not change stored hashes until the
user signs in, so one export can contain several algorithms.

## 3. Convert the export

Save this filter as `keycloak-to-anvilid.jq`:

```jq
# Keycloak realm export (kc.sh export) -> AnvilID import records (NDJSON with jq -c).
def nopad: sub("=+$"; "");
def uuid: type == "string" and test("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$");
def password_of($c):
  ($c.secretData | fromjson) as $s
  | ($c.credentialData | fromjson) as $d
  | ($d.additionalParameters // {}) as $a
  | if $d.algorithm == "argon2" then
      {scheme: "argon2",
       hash: "$argon2\($a.type[0])$v=\(if $a.version[0] == "1.0" then 16 else 19 end)$m=\($a.memory[0]),t=\($d.hashIterations),p=\($a.parallelism[0])$\($s.salt | nopad)$\($s.value | nopad)"}
    elif ($d.algorithm | IN("pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512")) then
      {scheme: "pbkdf2",
       prf: ({"pbkdf2": "sha1", "pbkdf2-sha256": "sha256", "pbkdf2-sha512": "sha512"}[$d.algorithm]),
       iterations: $d.hashIterations, salt: {base64: $s.salt}, hash: {base64: $s.value}}
    else null end;
.users[]?
| select((.email // "") != "" and .enabled != false)
| first(.credentials[]? | select(.type == "password")) as $c
| {email: .email, email_verified: (.emailVerified // false)}
  + (if .id | uuid then {id: .id} else {} end)
  + ({given_name: .firstName, family_name: .lastName, preferred_username: .username,
      name: ([.firstName, .lastName] | map(select(. != null and . != "")) | join(" "))}
     | with_entries(select(.value != null and .value != ""))
     | if . == {} then {} else {claims: .} end)
  + (if $c then (password_of($c) as $p | if $p then {password: $p} else {} end) else {} end)
```

and run it over the export files that contain users:

```sh
jq -c -f keycloak-to-anvilid.jq keycloak-export/*.json > users.ndjson
```

| Keycloak field | AnvilID record |
| --- | --- |
| `email` | `email`; users without an email are skipped |
| `emailVerified` | `email_verified` |
| `id` | `id` when it is a UUID; otherwise left out and AnvilID generates one |
| `firstName`, `lastName`, `username` | `claims.given_name`, `claims.family_name`, `claims.name`, `claims.preferred_username` |
| password credential | `password`, see the table in step 2 |

- Disabled users (`enabled: false`) are skipped: the import record has no field to keep a user
  disabled. Import them separately and disable them in AnvilID if you need their accounts.
- Users without a password credential in the export, or with an algorithm other than the four
  above (for example from a custom hash provider), are imported without a password. They set a
  password through account recovery or sign in with an upstream provider you configure in
  AnvilID.
- If a user id is not a UUID and your applications store it, define a custom attribute (for
  example `keycloak_id`) and add `attributes: {keycloak_id: .id}` to the record.
- Keycloak `attributes`, groups, role mappings, required actions, OTP and WebAuthn credentials
  and identity-provider links are not converted. Assign roles and memberships after the import;
  users enrol a second factor and passkeys again.

## 4. Import

```sh
anvilid users import users.ndjson --tenant default --source keycloak --dry-run
anvilid users import users.ndjson --tenant default --source keycloak
```

Check the dry-run report before the real run:

- **`over_cap` on `pbkdf2` (SHA-1) users.** AnvilID caps one PBKDF2 verification at 5,000,000
  iterations × output blocks. Keycloak derives a 64-byte key by default, which is four SHA-1
  blocks, so Keycloak's default 1,300,000 SHA-1 iterations exceed the cap and those hashes are
  rejected. Import those users without `password` (remove the `password` key from the rejected
  lines) and have them reset their password. The SHA-512 (one block) and SHA-256 (two blocks)
  defaults are within the cap, as are Keycloak's Argon2 defaults.
- **`weak`.** PBKDF2 hashes below 100,000 iterations (for example `pbkdf2-sha256` with 27,500
  iterations) are imported and counted as weak.
- **`id_conflict`.** The id is already used by another user in AnvilID.

## 5. After the import

- Users sign in with their Keycloak passwords. At the first successful sign-in the hash is
  replaced with Argon2id.
- If your Keycloak installation set the PBKDF2 option `max-padding-length` (Keycloak's default is
  0, no padding), Keycloak padded short passwords before hashing. AnvilID does not pad, so those
  users cannot sign in with their old password and need a reset.
- Sign in with a test account right after the import to confirm the conversion.

## Verification of this guide

The filter was run on a synthetic export with the documented structure: users with Argon2id
(Keycloak's default parameters), `pbkdf2-sha512` (210,000 iterations), `pbkdf2-sha256` (27,500
iterations) and `pbkdf2` SHA-1 (1,300,000 iterations) credentials with 64-byte keys, a disabled
user and a user without email. The hashes were generated locally. On an AnvilID 1.0 build the
Argon2id, SHA-512 and SHA-256 users signed in with their original passwords and kept their
Keycloak ids, the SHA-256 user was counted as weak, the SHA-1 user was rejected with `over_cap`,
and a wrong password was refused. No real Keycloak export was used.

---

Checked against (read on 2026-11-27):

- Keycloak guide, "Importing and Exporting Realms": <https://www.keycloak.org/server/importExport>
  (current release documentation): `kc.sh export` options and `--users` strategies, server must
  not be running, admin console partial export excludes users and masks secrets.
- Keycloak Server Administration Guide, "Password policies":
  <https://www.keycloak.org/docs/latest/server_admin/index.html>: supported algorithms
  (`argon2` default for non-FIPS, `pbkdf2-sha512` default for FIPS, `pbkdf2-sha256`, `pbkdf2`
  deprecated), default iterations per algorithm, stored hashes unchanged until the user signs in.
- Keycloak, "All provider configuration": <https://www.keycloak.org/server/all-provider-config>:
  Argon2 defaults (type `id`, version `1.3`, hash length 32, memory 7168, iterations 5,
  parallelism 1).
- Keycloak source code (main branch), for the formats the documentation does not describe:
  - <https://github.com/keycloak/keycloak/blob/main/model/storage-private/src/main/java/org/keycloak/exportimport/util/ExportUtils.java>:
    the full user export includes stored credentials, except for service accounts.
  - <https://github.com/keycloak/keycloak/blob/main/server-spi/src/main/java/org/keycloak/models/credential/dto/PasswordSecretData.java>
    and <https://github.com/keycloak/keycloak/blob/main/server-spi/src/main/java/org/keycloak/models/credential/dto/PasswordCredentialData.java>:
    `secretData` (`value`, base64 `salt`) and `credentialData` (`hashIterations`, `algorithm`,
    `additionalParameters`).
  - <https://github.com/keycloak/keycloak/blob/main/crypto/default/src/main/java/org/keycloak/crypto/hash/Argon2PasswordHashProvider.java>:
    Argon2 parameter keys, memory in KiB, raw hash stored as base64.
  - <https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/credential/hash/Pbkdf2PasswordHashProvider.java>
    and <https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/credential/hash/AbstractPbkdf2PasswordHashProviderFactory.java>:
    512-bit default derived key, key length taken from the stored hash, `max-padding-length`
    default 0.
