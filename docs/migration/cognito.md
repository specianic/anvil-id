# Migrating from Amazon Cognito user pools

Amazon Cognito's user APIs return user profiles and attributes, but no password data, so this
migration moves profiles only. After the import, users set a new password through AnvilID
account recovery or sign in another way that the tenant offers (see
[Users without a password](#6-users-without-a-password)).

You need the AWS CLI with IAM credentials that may call `ListUsers` on the user pool, `jq`, and
access to the AnvilID server's configuration for `anvilid users import`.

## 1. What the export contains

`ListUsers` (CLI: `aws cognito-idp list-users`) returns, for each user, `Username`, `Attributes`
(a list of `Name`/`Value` pairs, for example `sub`, `email`, `email_verified`, `given_name` and
`custom:...` attributes), `Enabled`, `UserStatus`, `UserCreateDate`, `UserLastModifiedDate` and
the legacy `MFAOptions`. The user object has no password or password-hash field, and AWS's
documentation describes no way to export password hashes from a user pool.

Notes from AWS's documentation:

- Every attribute value is a string, including `email_verified` (`"true"` or `"false"`).
- `sub` is the fixed user identifier, but AWS states that it is generated "in an Amazon
  Cognito-specific format that doesn't conform to a specific UUID format".
- Users who signed in through a third-party identity provider have their own profile, with
  `UserStatus` `EXTERNAL_PROVIDER` and the provider as a prefix of `Username`. Linked accounts
  appear twice (the provider user and the local user).
- `ListUsers` is eventually consistent.

## 2. Export the users

```sh
aws cognito-idp list-users --user-pool-id <region>_<pool id> --output json > cognito-users.json
```

`list-users` is a paginated operation: the CLI makes as many calls as needed (at most 60 users
per call) and writes all users into one `Users` array. Do not pass `--max-items` or
`--no-paginate`, which stop after a part of the pool, and do not pass `--attributes-to-get`,
which drops attributes. The file holds personal data; delete it after the migration.

## 3. Convert the export

Save this filter as `cognito-to-anvilid.jq`:

```jq
# `aws cognito-idp list-users` output -> AnvilID import records (NDJSON with jq -c).
# Optional: --arg legacy_attr <custom attribute> keeps every Cognito `sub` in that attribute.
def uuid: test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
def present: . != null and . != "";
($ARGS.named.legacy_attr // "") as $legacy
| .Users
| sort_by(.UserStatus == "EXTERNAL_PROVIDER")   # local users first
| .[]
| select(.Enabled != false)
| (reduce (.Attributes // [])[] as $a ({}; .[$a.Name] = $a.Value)) as $at
| select($at.email | present)
| (($at | with_entries(select((.key | IN("name", "given_name", "family_name", "middle_name",
      "nickname", "preferred_username", "profile", "picture", "website", "gender",
      "birthdate", "zoneinfo", "locale", "phone_number")) and (.value | present))))
   + (if $at.phone_number_verified == "true" and ($at.phone_number | present)
      then {phone_number_verified: true} else {} end)) as $claims
| {email: $at.email, email_verified: ($at.email_verified == "true")}
  + (if ($at.sub // "") | uuid then {id: $at.sub} else {} end)
  + (if $claims == {} then {} else {claims: $claims} end)
  + (if $legacy != "" and ($at.sub | present) then {attributes: {($legacy): $at.sub}} else {} end)
```

and run it:

```sh
jq -c -f cognito-to-anvilid.jq cognito-users.json > users.ndjson
# or, keeping every sub in the custom attribute `legacy_id` (define it in the tenant first):
jq -c --arg legacy_attr legacy_id -f cognito-to-anvilid.jq cognito-users.json > users.ndjson
```

What the filter does:

| Cognito | AnvilID record |
| --- | --- |
| attribute `email` | `email`; users without an email (for example phone-only) are skipped |
| attribute `email_verified` | `email_verified` (`true` only for the string `"true"`) |
| attribute `sub` | `id` when it is a lowercase UUID; otherwise no `id` (see below) |
| attributes `name`, `given_name`, `family_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `phone_number` | the claim of the same name |
| attribute `phone_number_verified` | `claims.phone_number_verified` |
| `Enabled: false` | the user is skipped |

- **User ids and `sub`.** A `sub` that is a valid UUID becomes the AnvilID user id, so the `sub`
  claim your applications stored stays the same. The filter accepts only the lowercase
  `8-4-4-4-12` form, which AnvilID keeps unchanged. Any other `sub` is left out, AnvilID
  generates a new id, and the user's `sub` changes. Because AWS does not promise a UUID format,
  check the dry-run report: if your applications store `sub`, define a custom attribute (for
  example `legacy_id`), pass `--arg legacy_attr legacy_id`, and map old ids in your applications.
- **Third-party users** (`EXTERNAL_PROVIDER`) are converted after the local users. When a provider
  profile has the same email as a local user, the import rejects the provider profile (the same
  email twice, `invalid_record` within one batch) and keeps the local user. Configure the same provider as an
  upstream connection in AnvilID so these users can sign in with it (see step 6).
- **Disabled users** are skipped. To keep them, delete the `select(.Enabled != false)` line and
  block those users after the import (`PATCH /api/admin/v1/tenants/{slug}/users/{user_id}` with
  `{"status": "blocked"}`).
- `custom:` attributes, `address` (a JSON string in Cognito), timestamps, groups and
  `UserStatus` are not converted. To import a `custom:` attribute, define it in the tenant and add
  it to `attributes` yourself.
- Email addresses are lowercased at import. Two Cognito users whose addresses differ only in case
  become the same AnvilID address, and only the first is imported.

## 4. Import

```sh
anvilid users import users.ndjson --tenant default --source cognito --dry-run
anvilid users import users.ndjson --tenant default --source cognito
```

Read the dry-run report first. Every line should be `created` (`unchanged` when you run the file
again). `invalid_record` usually means the same email twice or an attribute missing from the
tenant's definitions. Records carry no `password`, so there are no hash results.

## 5. MFA, groups and sessions

- **MFA.** The export contains no authenticator secrets (the user object has only the legacy
  `MFAOptions` settings). Users enrol a second factor (authenticator app or passkey) again in
  AnvilID.
- **Groups** become roles or organization memberships that you assign after the import.
- **Sessions and tokens** issued by Cognito are not valid at AnvilID. Users sign in again once
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
  These are sent only to accounts with a verified address, so they work for users imported with
  `email_verified: true`. They do not mark an address as verified.
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

The filter was run against a synthetic `list-users` output built in the documented shape
(`example.test` addresses): a confirmed user with a UUID `sub`, phone number and a `custom:`
attribute, an unconfirmed user whose `sub` is not a UUID (taken from AWS's documented example
value), a third-party profile sharing a local user's email, a disabled user and a phone-only user.
The output was checked against an AnvilID 1.0 build with `anvilid users import --dry-run` and a
real import, with and without `--arg legacy_attr`.

---

Checked against (read on 2026-11-27):

- Amazon Cognito API Reference, "ListUsers":
  <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html>:
  request parameters (`Limit` at most 60, `PaginationToken`, `AttributesToGet`), response syntax,
  eventual consistency, IAM-signed requests, separate profiles for identity-provider users.
- Amazon Cognito API Reference, "UserType":
  <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserType.html>:
  the complete list of user fields (no password field) and the `UserStatus` values.
- AWS CLI Command Reference, "list-users":
  <https://docs.aws.amazon.com/cli/latest/reference/cognito-idp/list-users.html>: automatic
  pagination, `--page-size` (at most 60), `--max-items`, `--no-paginate`, output structure.
- Amazon Cognito Developer Guide, "Working with user attributes":
  <https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html>:
  standard attribute names, `sub` format ("doesn't conform to a specific UUID format"),
  `email_verified`, `custom:` prefix, string values.
- AWS Solutions, "Cognito User Profiles Export Reference Architecture", overview:
  <https://docs.aws.amazon.com/solutions/latest/cognito-user-profiles-export-reference-architecture/overview.html>:
  AWS's export guidance "does not export sensitive information, such as user passwords".
