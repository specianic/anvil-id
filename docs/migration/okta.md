# Migrating from Okta

Okta's Users API returns user profiles but no password data, so this migration moves profiles
only. After the import, users set a new password through AnvilID account recovery or sign in
another way that the tenant offers (see [Users without a password](#6-users-without-a-password)).

You need an Okta API token or an OAuth 2.0 access token with the `okta.users.read` scope, `curl`,
`jq`, and access to the AnvilID server's configuration for `anvilid users import`.

## 1. What the export contains

`GET /api/v1/users` ("List all users") returns user objects with `id`, `status`, timestamps
(`created`, `activated`, `statusChanged`, `lastLogin`, `lastUpdated`, `passwordChanged`),
`type`, `profile` (for example `login`, `email`, `firstName`, `lastName`, `displayName`,
`nickName` and custom profile attributes) and `credentials`.

Okta documents that the password is write-only: when a user has a password, an imported hashed
password or a password hook, the response contains a bare `"password": {}` "without the value
property defined". A hashed password can be given when creating or updating a user, "but not for
other operations". Okta's documentation describes no way to export password hashes.

Notes from Okta's documentation:

- The list omits users with status `DEPROVISIONED` unless you pass `filter` or `search`.
- Results are paged with a cursor. The next page's URL is in the `Link` response header with
  `rel="next"`, and the last page has no `next` link. Okta asks clients to follow these links
  rather than build their own URLs.
- Okta user ids (for example `00ub0oNGTSWTBKOLGLNR`) are not UUIDs.
- The profile has no field that says whether the email address was verified.

## 2. Export the users

This script follows the `next` links and writes one user object per line:

```sh
url="https://${OKTA_DOMAIN}/api/v1/users"
: > okta-users.ndjson
while [ -n "$url" ]; do
  curl -sS --fail -D okta-headers.txt -o okta-page.json \
    -H "Authorization: SSWS ${OKTA_API_TOKEN}" -H "Accept: application/json" "$url" || exit 1
  jq -c '.[]' okta-page.json >> okta-users.ndjson
  url=$(tr -d '\r' < okta-headers.txt | grep -i '^link:' | grep -o '<[^>]*>; *rel="next"' |
        sed -E 's/^<([^>]*)>.*/\1/')
done
rm -f okta-headers.txt okta-page.json
```

With an OAuth 2.0 access token, send `Authorization: Bearer <token>` instead. If the script stops
on an error (for example a rate limit), run it again from the start. The file holds personal
data; delete it after the migration.

## 3. Convert the export

Save this filter as `okta-to-anvilid.jq`:

```jq
# Okta user objects (GET /api/v1/users, one per line) -> AnvilID import records (jq -c).
# Optional: --arg legacy_attr <custom attribute> keeps the Okta user id in that attribute;
#           --arg email_verified true imports every address as verified.
def put($k; $v): if ($v // "") != "" then {($k): $v} else {} end;
($ARGS.named.legacy_attr // "") as $legacy
| select(.status | IN("SUSPENDED", "DEPROVISIONED") | not)
| .profile as $p
| select(($p.email // "") != "")
| (put("name"; $p.displayName) + put("given_name"; $p.firstName)
   + put("family_name"; $p.lastName) + put("middle_name"; $p.middleName)
   + put("nickname"; $p.nickName)) as $claims
| {email: $p.email, email_verified: ($ARGS.named.email_verified == "true")}
  + (if $claims == {} then {} else {claims: $claims} end)
  + (if $legacy != "" then {attributes: {($legacy): .id}} else {} end)
```

and run it:

```sh
jq -c -f okta-to-anvilid.jq okta-users.ndjson > users.ndjson
# or, keeping Okta ids in the custom attribute `legacy_id` (define it in the tenant first):
jq -c --arg legacy_attr legacy_id -f okta-to-anvilid.jq okta-users.ndjson > users.ndjson
```

What the filter does:

| Okta | AnvilID record |
| --- | --- |
| `profile.email` | `email`; users without one are skipped |
| (no field) | `email_verified: false`, or `true` for everyone with `--arg email_verified true` |
| `profile.displayName` | `claims.name` |
| `profile.firstName`, `lastName`, `middleName`, `nickName` | `claims.given_name`, `family_name`, `middle_name`, `nickname` |
| `id` | the custom attribute named by `--arg legacy_attr` (optional) |
| `status` `SUSPENDED` or `DEPROVISIONED` | the user is skipped |

- **User ids and `sub`.** Okta ids are not UUIDs, so AnvilID generates a new id for every user and
  the `sub` claim changes. If your applications store Okta ids, define a custom attribute (for
  example `legacy_id`), pass `--arg legacy_attr legacy_id`, and map old ids in your applications.
- **Verified addresses.** Okta's profile does not say whether an address was verified. Pass
  `--arg email_verified true` only if you know the addresses are verified. Email code, sign-in
  link and automatic upstream linking need a verified address; account recovery works either way
  and marks the address as verified (step 6).
- **Suspended users** are skipped. To keep them, delete the `select(.status ...)` line and block
  them after the import (`PATCH /api/admin/v1/tenants/{slug}/users/{user_id}` with
  `{"status": "blocked"}`).
- `profile.login` (when it differs from the email), phone numbers, address fields, custom profile
  attributes, groups and app assignments are not converted. Add them to `claims` or `attributes`
  yourself if you need them; custom attributes must be defined in the tenant first.
- Users whose credentials come from a delegated directory or federated provider
  (`credentials.provider.type` `ACTIVE_DIRECTORY`, `LDAP` or `FEDERATION`) are imported like
  everyone else, without a password.
- Email addresses are lowercased at import.

## 4. Import

```sh
anvilid users import users.ndjson --tenant default --source okta --dry-run
anvilid users import users.ndjson --tenant default --source okta
```

Read the dry-run report first. Every line should be `created` (`unchanged` when you run the file
again). `invalid_record` usually means the same email twice or an attribute missing from the
tenant's definitions. Records carry no `password`, so there are no hash results.

## 5. MFA, groups and sessions

- **MFA.** The user objects carry no factor secrets, and the import has no field for them. Users
  enrol a second factor (authenticator app or passkey) again in AnvilID.
- **Groups** become roles or organization memberships that you assign after the import.
- **Sessions and tokens** issued by Okta are not valid at AnvilID. Users sign in again once your
  applications point at AnvilID.

## 6. Users without a password

Every imported user starts without a password. Tell your users how to sign in before you switch
your applications over. AnvilID offers these methods:

- **Account recovery** (needs SMTP). On the sign-in page, users choose **Forgot your
  password?**, receive a one-time link (valid one hour) and set a password. It works for every
  active account, including addresses imported with `email_verified: false`, and finishing it
  marks the address as verified. AnvilID does not email imported users by itself, so send your
  own announcement that points to the sign-in page.
- **Email code or sign-in link** (tenant settings `email_otp` and `magic_link`, both need SMTP).
  These are sent only to accounts with a verified address. They do not mark an address as
  verified.
- **Upstream sign-in** (social, OpenID Connect or OAuth 2.0 connections). With the tenant setting
  `auto_link` on (the default), a trusted, verified upstream email that matches a verified
  AnvilID account links that account automatically. In every other case the user has to sign in to
  the existing account first, which needs a password, so they use account recovery once.
- **Enterprise single sign-on** through organization connections, see
  [Organizations and enterprise SSO](../ORGANIZATIONS.md).
- **Passkeys** can be added on the account security page after the first sign-in. They are not a
  first sign-in method for imported users.

The tenant settings are described in [Declarative tenant configuration](../CONFIG-YAML.md) and
[Upgrading](../UPGRADING.md#defaults-after-the-upgrade). The import format is described in
[Migrating users](./) and [Importing and exporting users](../IMPORT-EXPORT.md).

## Verification of this guide

The export script was run against a local stand-in server that answered with two pages and Okta's
documented `Link` headers (`rel="self"` and `rel="next"`, also both in one header). The filter was
run on synthetic user objects in the documented shape (`example.test` addresses): an `ACTIVE` user
with `"password": {}`, a `SUSPENDED` user and a `PASSWORD_EXPIRED` user with a mixed-case email.
The output was checked against an AnvilID 1.0 build with `anvilid users import --dry-run`, a real
import, and a second import that reported every user as `unchanged`.

---

Checked against (read on 2026-11-27):

- Okta Management API, "List all users":
  <https://developer.okta.com/docs/api/openapi/okta-management/management/tags/user/other/listusers>:
  query parameters (`search`, `filter`, `limit`, `after`), omission of `DEPROVISIONED` users,
  user status values, response fields.
- Okta Management API, "Retrieve a user":
  <https://developer.okta.com/docs/api/openapi/okta-management/management/tags/user/other/getuser>:
  example user object with `profile` and `"password": {}`.
- Okta Management API overview, "Pagination" and "Link header":
  <https://developer.okta.com/docs/api/#pagination>: cursor pagination, `rel="next"`, last page
  without a `next` link, follow the links instead of building URLs.
- Okta Management OpenAPI specification:
  <https://github.com/okta/okta-management-openapi-spec/blob/master/dist/current/management-minimal.yaml>:
  `PasswordCredential` (bare password object in responses, `value` write-only),
  `PasswordCredentialHash` (hash only on create or update), `UserProfile` fields, authentication
  provider types, `SSWS` API token and `okta.users.read` scope for `listUsers`.
