# Migrating from Microsoft Entra External ID and Azure AD B2C

Both Microsoft Entra External ID (external tenants) and Azure AD B2C keep their users in a
directory that you read with Microsoft Graph. Graph returns profiles and sign-in identities but
no password data, so this migration moves profiles only. After the import, users set a new
password through AnvilID account recovery or sign in another way that the tenant offers (see
[Users without a password](#6-users-without-a-password)).

You need a Microsoft Graph access token with the `User.Read.All` permission for the tenant,
`curl`, `jq`, and access to the AnvilID server's configuration for `anvilid users import`.

## 1. What the export contains

`GET /v1.0/users` returns user objects. The properties this guide uses:

| Property | Meaning (per the Graph reference) |
| --- | --- |
| `id` | The user's object id. Microsoft says to treat it as opaque; in Microsoft identity platform tokens it is the `oid` claim |
| `identities` | The sign-in identities: `signInType` (`emailAddress`, `userName`, `federated`, `userPrincipalName`, ...), `issuer`, `issuerAssignedId`. For `emailAddress`, `issuerAssignedId` is the sign-in email |
| `mail`, `otherMails` | Email addresses. For Azure AD B2C profiles Microsoft recommends `otherMails` over `mail` |
| `displayName`, `givenName`, `surname`, `preferredLanguage` | Profile fields |
| `accountEnabled` | Whether the account is enabled |

`identities`, `otherMails` and `accountEnabled` are returned only when you name them in
`$select`. The `passwordProfile` property is documented only for setting a password (required
when a user is created, and updatable). Microsoft's documentation does not describe reading a
password or a password hash back, and describes no way to export password hashes.

Paging: the list returns at most 999 users per page (`$top=999`; the default is 100). When more
pages exist, the response carries `@odata.nextLink`; call that URL unchanged until no
`@odata.nextLink` is returned.

## 2. Export the users

```sh
url='https://graph.microsoft.com/v1.0/users?$select=id,displayName,givenName,surname,mail,otherMails,identities,accountEnabled,preferredLanguage&$top=999'
: > entra-users.ndjson
while [ -n "$url" ]; do
  curl -sS --fail -o entra-page.json -H "Authorization: Bearer ${GRAPH_TOKEN}" "$url" || exit 1
  jq -c '.value[]' entra-page.json >> entra-users.ndjson
  url=$(jq -r '."@odata.nextLink" // empty' entra-page.json)
done
rm -f entra-page.json
```

If the script stops on an error (for example throttling), run it again from the start. The file
holds personal data; delete it after the migration.

## 3. Convert the export

Save this filter as `entra-to-anvilid.jq`:

```jq
# Microsoft Graph user objects (GET /v1.0/users, one per line) -> AnvilID import records (jq -c).
# Optional: --arg legacy_attr <custom attribute> keeps the Graph object id in that attribute;
#           --arg email_verified true imports every address as verified.
def uuid: test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
def put($k; $v): if ($v // "") != "" then {($k): $v} else {} end;
($ARGS.named.legacy_attr // "") as $legacy
| select(.accountEnabled != false)
| ([(.identities // [])[] | select((.signInType // "") | startswith("emailAddress"))
    | .issuerAssignedId][0] // .mail // (.otherMails // [])[0]) as $email
| select(($email // "") != "")
| (put("name"; .displayName) + put("given_name"; .givenName)
   + put("family_name"; .surname) + put("locale"; .preferredLanguage)) as $claims
| {email: $email, email_verified: ($ARGS.named.email_verified == "true")}
  + (if (.id // "") | uuid then {id: .id} else {} end)
  + (if $claims == {} then {} else {claims: $claims} end)
  + (if $legacy != "" then {attributes: {($legacy): .id}} else {} end)
```

and run it:

```sh
jq -c -f entra-to-anvilid.jq entra-users.ndjson > users.ndjson
```

What the filter does:

| Graph | AnvilID record |
| --- | --- |
| the first `identities` entry with `signInType` `emailAddress`, else `mail`, else the first `otherMails` entry | `email`; users with none of these (for example `userName` sign-in only) are skipped |
| (no field) | `email_verified: false`, or `true` for everyone with `--arg email_verified true` |
| `id` | `id` when it is a lowercase UUID, otherwise no `id`; also the custom attribute named by `--arg legacy_attr` (optional) |
| `displayName`, `givenName`, `surname`, `preferredLanguage` | `claims.name`, `given_name`, `family_name`, `locale` |
| `accountEnabled: false` | the user is skipped |

- **User ids and `sub`.** A Graph `id` that is a valid UUID becomes the AnvilID user id, so the
  AnvilID `sub` claim equals the old object id. Which claim your applications stored decides
  whether that is enough:
  - Azure AD B2C fills `sub` with the user's object id by default, so stored `sub` values keep
    working.
  - In tokens from the Microsoft identity platform, the object id is the `oid` claim, while `sub`
    is a pairwise value that differs per application. Applications that stored `oid` keep
    working. Applications that stored `sub` need a mapping from their stored value to the new
    `sub`, and the Graph export does not contain the pairwise value.
  - An `id` that is not a lowercase UUID is left out and AnvilID generates a new id. Use
    `--arg legacy_attr legacy_id` (define the attribute in the tenant first) to keep the old id.
- **Verified addresses.** Graph does not say whether an address was verified. Pass
  `--arg email_verified true` only if you know the addresses are verified. Email code, sign-in
  link and automatic upstream linking need a verified address; account recovery works either way
  and marks the address as verified (step 6).
- **Social and federated identities** (`signInType` `federated`) are not carried over: the record
  has no field for linked accounts. Configure the same providers as upstream connections in AnvilID
  (step 6).
- **Disabled users** are skipped. To keep them, delete the `select(.accountEnabled != false)`
  line and block them after the import (`PATCH /api/admin/v1/tenants/{slug}/users/{user_id}`
  with `{"status": "blocked"}`).
- `userPrincipalName` is not used as an email: in external and B2C tenants it is often a
  generated name in the tenant's own domain. Custom attributes (`extension_...` properties),
  group memberships and app role assignments are not converted.
- Email addresses are lowercased at import.

## 4. Import

```sh
anvilid users import users.ndjson --tenant default --source entra --dry-run
anvilid users import users.ndjson --tenant default --source entra
```

Read the dry-run report first. Every line should be `created` (`unchanged` when you run the file
again). `invalid_record` usually means the same email twice or an attribute missing from the
tenant's definitions; `id_conflict` means another AnvilID user already has that id. Records carry
no `password`, so there are no hash results.

## 5. MFA, groups and sessions

- **MFA.** The user objects carry no authentication method secrets, and the import has no field
  for them. Users enrol a second factor (authenticator app or passkey) again in AnvilID.
- **Groups and app roles** become roles or organization memberships that you assign after the
  import.
- **Sessions and tokens** issued by Microsoft are not valid at AnvilID. Users sign in again once
  your applications point at AnvilID.

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
  Accounts from AnvilID's Microsoft connection never link automatically; those users confirm
  the link by signing in to the existing account.
- **Enterprise single sign-on** through organization connections, see
  [Organizations and enterprise SSO](../ORGANIZATIONS.md).
- **Passkeys** can be added on the account security page after the first sign-in. They are not a
  first sign-in method for imported users.

The tenant settings are described in [Declarative tenant configuration](../CONFIG-YAML.md) and
[Upgrading](../UPGRADING.md#defaults-after-the-upgrade). The import format is described in
[Migrating users](./) and [Importing and exporting users](../IMPORT-EXPORT.md).

## Verification of this guide

The export script was run against a local stand-in server that answered with two pages in the
documented shape (`value` plus `@odata.nextLink` on the first page). The filter was run on
synthetic user objects (`example.test` addresses): a local account with an `emailAddress`
identity, a federated account with only `otherMails`, an account with only `mail`, a disabled
account and a `userName`-only account. The output was checked against an AnvilID 1.0 build with
`anvilid users import --dry-run` and a real import, with and without `--arg legacy_attr` and
`--arg email_verified true`; the imported users kept their object ids.

---

Checked against (read on 2026-11-27):

- Microsoft Graph v1.0, "List users":
  <https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0>: permissions
  (`User.Read.All`), default page size 100 and maximum 999, `$select`, filtering on
  `identities`, notes for Azure AD B2C tenants.
- Microsoft Graph v1.0, "user resource type":
  <https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0>: `id` (opaque),
  `identities`, `mail` (use `otherMails` for B2C profiles), `otherMails`, `passwordProfile`,
  `accountEnabled`, `userPrincipalName`, profile fields, which properties need `$select`.
- Microsoft Graph v1.0, "passwordProfile resource type":
  <https://learn.microsoft.com/en-us/graph/api/resources/passwordprofile?view=graph-rest-1.0>:
  the `password` property is the password set at creation or update.
- Microsoft Graph v1.0, "objectIdentity resource type":
  <https://learn.microsoft.com/en-us/graph/api/resources/objectidentity?view=graph-rest-1.0>:
  `signInType`, `issuer`, `issuerAssignedId` (the sign-in email for `emailAddress`).
- Microsoft Graph, "Paging Microsoft Graph data in your app":
  <https://learn.microsoft.com/en-us/graph/paging>: `@odata.nextLink`, use the whole URL, stop
  when it is no longer returned.
- Microsoft identity platform, "ID token claims reference":
  <https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference>: `oid` is
  the Graph `id`, `sub` is pairwise per application.
- Azure AD B2C, "Overview of tokens":
  <https://learn.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview>: `sub` is the
  user's object id by default.
- Microsoft Entra External ID, "Migrate users and credentials to Microsoft Entra External ID":
  <https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-migrate-users>: covers
  migration into External ID only; it describes no export of password hashes out of a tenant.
