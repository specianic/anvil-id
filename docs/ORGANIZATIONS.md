# Organizations and enterprise SSO

Added in 1.0. This guide is for SaaS builders who serve business customers with AnvilID, and for
the operators who run it. It covers organizations, members and their roles, invitations, the
organization claims in tokens, organization admins, enterprise OIDC connections, domain
verification and home-realm discovery (routing users to their organization's identity provider
by email domain). SAML 2.0 connections are experimental and have their own guide:
[SAML.md](SAML.md).

Contents: [Concepts](#concepts) · [Creating an organization](#creating-an-organization) ·
[Members and roles](#members-and-roles) · [Invitations](#invitations) ·
[Organizations in tokens](#organizations-in-tokens) · [Switching organizations](#switching-organizations) ·
[Organization MFA and branding](#organization-mfa-and-branding) ·
[Organization admins](#organization-admins) · [Enterprise OIDC connections](#enterprise-oidc-connections) ·
[Domain verification](#domain-verification) ·
[Home-realm discovery](#home-realm-discovery-identifier-first-sign-in) ·
[Recovering from lockouts](#recovering-from-lockouts) · [Webhooks and audit](#webhooks-and-audit) ·
[Limitations in 1.0](#limitations-in-10)

## Concepts

- A **tenant** is the isolation boundary: its own issuer, users, clients, keys and settings.
- An **organization** is a customer company *inside* a tenant. Users stay tenant users. An
  organization groups them (membership), gives them roles that apply inside that organization,
  and can bring its own identity provider (IdP) for its email domains.
- One user can belong to several organizations of the same tenant. Consent and browser sessions
  stay per user; the organization a user acts for is chosen per authorization request and bound to
  the resulting tokens.
- The `system` tenant has no organizations (creating one there answers `422`).

Everything below can be done in the admin console (tenant page, **Organizations**) or through the
admin API. API paths are relative to `/api/admin/v1/tenants/{slug}`, and `{org}` accepts the
organization's id or its slug. A system administrator needs `admin:organizations:read` /
`admin:organizations:write` (or `admin:read` / `admin:write`).

## Creating an organization

```sh
curl -sX POST "$ANVIL/api/admin/v1/tenants/acme/organizations" \
  -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"slug": "globex", "display_name": "Globex Corporation", "mfa_policy": "optional"}'
```

- `slug`: 2-63 characters of `a-z`, `0-9` and `-`, not starting with `-`, unique per tenant.
- `mfa_policy` (`off`, `optional`, `required` or absent): see
  [Organization MFA](#organization-mfa-and-branding).
- `metadata`: a JSON object for your own use.
- `default_role_ids` (on `PATCH` only, because organization roles cannot exist before the
  organization does): the roles that just-in-time SSO sign-ups get in this organization.

Deleting an organization removes its memberships, its own roles and their assignments, its
connections with their identity links, its domains, invitations and branding, and revokes every
token family bound to it, in one transaction.

### Letting a client use organizations

Each client has an `organization` policy (client create/update in the API, or the client page in
the console):

| Policy | Effect |
|---|---|
| `off` (default) | The client never gets organization claims. An `organization` parameter is refused with `invalid_request` |
| `optional` | Tokens carry an organization only when the request names one with `organization` |
| `required` | Every token carries an organization. A user in one organization gets it; a user in several chooses on a switcher page; a user in none is refused with `access_denied` |

Clients of the `system` tenant, dynamically registered clients and Client ID Metadata Document
clients always have `off`.

## Members and roles

| Route | What it does |
|---|---|
| `GET /organizations/{org}/members` | List members (with email) |
| `POST /organizations/{org}/members` `{user_id, role_ids}` | Add an existing tenant user, optionally with roles. Tenant admins only |
| `DELETE /organizations/{org}/members/{user_id}` | Remove a member. Their token families bound to this organization are revoked at once |
| `GET /organizations/{org}/members/{user_id}/roles` | Roles the member holds in this organization (`404` when the user is not a member) |
| `PUT\|DELETE /organizations/{org}/members/{user_id}/roles/{role}?scope=org\|tenant` | Assign or unassign a role within the organization |
| `GET\|POST /organizations/{org}/roles`, `GET\|PATCH\|DELETE /organizations/{org}/roles/{name}` | Roles owned by the organization |

There is one role model with two kinds of roles, both assigned per organization:

- **Tenant roles** (the 0.4 RBAC roles) can be assigned to a member *within* an organization
  (`?scope=tenant`). Such an assignment applies only in that organization; it does not give the
  user the role tenant-wide.
- **Organization roles** are owned by one organization (`?scope=org`). Their names are unique
  within the organization and may repeat across organizations and next to tenant roles.

Roles with an `admin:*` permission can never be assigned or offered inside an organization
(`422`): organization roles never grant access to the management API beyond the organization
admin routes described below. Removing a member removes their assignments in that organization.

## Invitations

| Route | What it does |
|---|---|
| `POST /organizations/{org}/invitations` `{email, role_ids}` | Invite an address, with up to 20 roles to receive on acceptance |
| `GET /organizations/{org}/invitations?include_closed=true` | List invitations (newest first) with status `open`, `accepted`, `revoked` or `expired` |
| `DELETE /organizations/{org}/invitations/{id}` | Revoke an open invitation |

How invitations behave:

- The token is 32 random bytes. Only its SHA-256 hash is stored; no API response or log ever shows
  the token. The invitation expires after **7 days** and can be used once.
- The invitee gets the `org_invitation` email through the outbox (sealed at rest like every
  email), with the link `{issuer}/ui/invitation?token=…`. Tenants can customise the template like
  the other email kinds.
- Creating an invitation never looks up an account: the answer is the same whether an account
  exists for the address or not.
- Opening the link (`GET`) only shows the organization's name and an **Accept** button, so mail
  link scanners consume nothing. The token is used only by a `POST` from the same browser
  (a nonce cookie plus a token-bound CSRF value). Every invalid token (unknown, used, revoked,
  expired, another tenant's) gets the same page.
- **Signed in:** the invitation is accepted only when the account's **verified** email equals the
  invited address. A different account is told to sign out and use the invited account, and the
  invitation stays open. An account whose address is not verified yet must verify it first.
- **Signed out:** the page offers sign-in and, unless the tenant's registration mode is
  `disabled`, a registration form for the invited address (shown read-only; the address always
  comes from the invitation). Registration works under `invite_only`. The new account is created
  with a verified email (the invitation proved the address) and joins the organization in the
  same transaction. If an account already exists for the address, the user is asked to sign in.
- Concurrent acceptances of one invitation have exactly one winner.

**Current limitation:** the invitation page does not carry the user through sign-in. A signed-out
user who already has an account signs in and then opens the invitation link again, and a user
who registered through an invitation is not signed in afterwards (the page offers a sign-in link).
A return-to-invitation after sign-in is planned.

## Organizations in tokens

The `organization` authorization parameter names the organization by id or slug:

```text
https://id.example.net/t/acme/authorize?response_type=code&client_id=billing-web
  &redirect_uri=https%3A%2F%2Fbilling.example.net%2Fcallback&scope=openid%20profile%20roles
  &code_challenge=…&code_challenge_method=S256&state=…&nonce=…
  &organization=globex
```

After sign-in the active organization is resolved from the client's policy, the parameter and the
user's memberships. It is bound to the authorization code and its token family, never to a cookie
or the browser session.

| Situation | Answer |
|---|---|
| `organization` sent to a client with policy `off`, repeated, longer than 128 bytes or with control characters | `invalid_request` |
| The user is not a member of the named organization (unknown organizations included) | `access_denied` |
| Policy `required`, the user is in no organization | `access_denied` |
| Policy `required`, several organizations, `prompt=none` | `interaction_required` (never a silent choice) |
| Policy `required`, several organizations | The switcher page (`/ui/select-organization`) |
| Code exchange or refresh after the user left the organization, or the organization was deleted | `invalid_grant`, and the token family is revoked |

A decoded access token with an active organization (illustrative values):

```json
{
  "iss": "https://id.example.net/t/acme",
  "sub": "0195b7a3-1f2e-7a4b-8c00-5d6e7f8091a2",
  "aud": "billing-web",
  "scope": "openid profile roles",
  "org_id": "0195b7c0-4d1a-7e2b-9a00-1c2d3e4f5a6b",
  "org_slug": "globex",
  "org_roles": ["billing-admin"],
  "org_permissions": ["invoices:read", "invoices:write"]
}
```

| Claim | ID token | JWT access token | UserInfo | Introspection |
|---|---|---|---|---|
| `org_id`, `org_slug` | yes | yes | yes | yes |
| `org_roles` (roles held in the active organization) | with scope `roles` | with scope `roles` | with scope `roles` | with scope `roles` |
| `org_permissions` | no | yes | no | yes |

- Without an active organization no token carries any organization claim. Client credentials
  tokens never do.
- `org_roles` and `org_permissions` are recomputed at every refresh, so role changes reach the
  next refreshed token. They come from the user's roles in the active organization only; the
  tenant-wide `roles` / `permissions` claims are unchanged.
- The names `org_roles` and `org_permissions` can be changed or disabled in the tenant claim
  mapping (`claims.org_roles`, `claims.org_permissions`; `null` disables). `org_id` and `org_slug`
  are fixed. All four names are reserved: no attribute or role mapping can emit or override them.
- Opaque access tokens: since 1.0 introspection and UserInfo return the same role, permission,
  attribute and organization claims as a JWT would carry.
- Discovery lists the four claims in `claims_supported`.
- Removing a member revokes their refresh tokens for that organization at once. A JWT access
  token already issued stays valid at resource servers that verify it offline until it expires;
  UserInfo answers `invalid_token` and introspection `{"active": false}` for it.

## Switching organizations

Switching is a new authorization request with `organization=<other>`. With an existing session
and `prompt=none` it completes without any page. The previous tokens keep their organization.

When a `required` client sends no `organization` and the user belongs to several organizations,
the user picks one on `/ui/select-organization`. The page lists only the user's own memberships
(display name and slug), works without JavaScript, and refuses any other value with `403`. The
choice is written into the stored authorization request and resolved like a parameter.

## Organization MFA and branding

- **MFA:** an organization's `mfa_policy` joins the tenant and client policies, and the strictest
  wins (`required` > `optional` > `off`). An organization can only make sign-in stricter. When the
  user signs in with a password before the organization is known, the organization's policy is
  applied right after sign-in as a step-up: no code is issued before the second factor.
- **Branding:** `GET|PUT|DELETE /organizations/{org}/branding` (plus `logo`, `preview` and
  `publish`, with the same bodies and limits as tenant and client branding). The sign-in pages of
  a request that names the organization (`organization=` by id or slug) use the organization
  layer. Precedence per field is client > organization > tenant; custom CSS is applied in the
  order tenant, organization, client. An unknown organization falls back to the tenant theme.

## Organization admins

An organization admin is an ordinary user of the tenant who holds the permission `org:admin` in
that organization (through an organization role, or a tenant role assigned within the
organization). They manage their own organization through the same admin API, with a token from
their own tenant.

What an organization admin can do, on `/organizations/{org}/…` of their own organization only:

| Allowed | Refused |
|---|---|
| Read the organization; list members and their roles; remove members; assign and unassign roles; create, edit and delete organization roles; send, list and revoke invitations; manage connections, domains, routing and branding | Edit or delete the organization itself (`403`); add a user directly (`403`; they invite instead); any route outside their organization, any other organization (`403`), any tenant-level or installation route (`401`) |

### Getting an organization-admin token

1. Create a client in the application tenant (not `system`) for the organization admin tool, with
   `token_format: jwt`, the scope `org:admin` in `scopes`, `organization: optional` (or
   `required`), and the management API in `allowed_resources`:
   `{public_url}/api/admin/v1`, for example `https://id.example.net/api/admin/v1`.
2. Give the admin user the `org:admin` permission in the organization, for example:

   ```sh
   curl -sX POST "$ANVIL/api/admin/v1/tenants/acme/organizations/globex/roles" \
     -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
     -d '{"name": "org-admin", "permissions": ["org:admin"]}'
   curl -sX PUT "$ANVIL/api/admin/v1/tenants/acme/organizations/globex/members/$USER_ID/roles/org-admin?scope=org" \
     -H "authorization: Bearer $ADMIN_TOKEN"
   ```

3. Send the user through an authorization request for that organization and resource:

   ```text
   https://id.example.net/t/acme/authorize?response_type=code&client_id=globex-admin-tool
     &redirect_uri=https%3A%2F%2Fadmin-tool.example.net%2Fcallback
     &scope=openid%20org%3Aadmin&organization=globex
     &resource=https%3A%2F%2Fid.example.net%2Fapi%2Fadmin%2Fv1
     &code_challenge=…&code_challenge_method=S256&state=…&nonce=…
   ```

4. Call the organization routes with the resulting access token:

   ```sh
   curl -s "$ANVIL/api/admin/v1/tenants/acme/organizations/globex/members" \
     -H "authorization: Bearer $ORG_ADMIN_TOKEN"
   ```

The token is accepted only when all of these hold, and they are checked again on every request:
it is a JWT issued by tenant `acme` (opaque tokens are refused); its `aud` contains
`{public_url}/api/admin/v1` and the client still exists and still lists that resource; it carries
`org:admin` and an `org_id` equal to the organization in the path; its token family is live and
bound to that organization and user; and the user is active, still a member, and still holds
`org:admin` there. `org:admin` itself is only issued while the user holds the permission in the
active organization, and is dropped at the next refresh when they lose it. It is never issued
without an active organization, never to client credentials, never to a `system` tenant client,
and it can never be registered through dynamic registration or a client metadata document.

Changes made by an organization admin are audited with the user as the actor; changes by a tenant
admin with the admin actor.

**Last organization admin.** An organization admin cannot leave the organization without an
admin: removing, unassigning, editing a role so that it loses `org:admin`, or deleting such a
role is refused with `409` when no other active member would still hold `org:admin`. Tenant
admins are not limited by this guard (see [Recovering from lockouts](#recovering-from-lockouts)).

## Enterprise OIDC connections

An organization can have its own connections: OpenID Connect, or SAML 2.0
([SAML.md](SAML.md), experimental). Social presets and generic OAuth 2.0 are tenant-level only.

| Route | What it does |
|---|---|
| `GET\|POST /organizations/{org}/connections` | List or create |
| `GET\|PATCH\|DELETE /organizations/{org}/connections/{id}` | Read, change, delete. Another organization's connection answers `404` |
| `PUT /organizations/{org}/connections/{id}/secret` | Set the client secret (write-only) |

```sh
curl -sX POST "$ANVIL/api/admin/v1/tenants/acme/organizations/globex/connections" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"slug": "globex-sso", "display_name": "Globex SSO",
       "config": {"type": "oidc", "issuer": "https://login.example.com", "client_id": "anvilid"},
       "secret": "…"}'
```

Register the connection's `redirect_uri` (shown in the response) at the IdP. Organization
connections share the tenant's slug namespace, use the same guarded outbound client, ID token
validation and linking rules as tenant connections (0.3), and differ in four ways:

- **Not on the sign-in page.** Organization connections get no button. Users reach them through
  [home-realm discovery](#home-realm-discovery-identifier-first-sign-in), or through an
  authorization request with `organization=…` when that organization has exactly one enabled
  connection (the user then goes straight to its IdP).
- **Domain-bound email trust.** An email asserted by an organization's IdP counts as verified only
  when its domain exactly equals one of **that organization's verified domains** and the IdP did
  not say `email_verified: false` (OIDC needs a strict `true`). Subdomains and other
  organizations' domains are never trusted. So organization A's IdP can never take over an account
  on organization B's domain: such a sign-in gets the confirmation step (the user must prove the
  existing account), never an automatic link, and adds no membership.
- **Membership.** A just-in-time account is created together with its identity link and the
  membership (with the organization's `default_role_ids` that still exist) in one transaction. An
  existing linked user who is not a member becomes one at sign-in. Both are audited as
  `org_member_added`.
- **Read-only at tenant level.** The tenant's connection list shows organization connections with
  their organization, but changing them there answers `409`; use the organization routes.

**Just-in-time sign-up and tenant registration.** A first sign-in through an organization's own
connection (OIDC or SAML) creates the account just in time **whatever the tenant's registration
setting**, as long as the asserted email is trusted for that organization: it is on one of the
organization's verified domains (and, for OIDC, the IdP says `email_verified: true`). An admin
configured the connection and verified the domain, so a B2B tenant with `invite_only` or `disabled`
registration still onboards the organization's own people through their IdP. An organization
connection that asserts any other address (another domain, a pending domain, or an address its IdP
did not verify) gets no such exception: it follows the tenant's `upstream_registration` like a
tenant-level connection does. Tenant-level connections keep following `upstream_registration`,
which, when unset, follows the registration mode (only `open` allows it). A refused first sign-in
shows the generic "sign-in failed" page and is audited `upstream_login_failed` with reason
`no_account`; no user is created.

## Domain verification

An organization proves it controls a domain with a DNS TXT record.

```sh
curl -sX POST "$ANVIL/api/admin/v1/tenants/acme/organizations/globex/domains" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"domain": "example.com"}'
```

The answer (`201`) contains the record to publish:

```text
_anvilid-challenge.example.com.  300  IN  TXT  "anvilid-domain-verification=k7v3m2q9x4b8n1c5z6w0t2y7ra"
```

- `record_name` is `_anvilid-challenge.{domain}.` and `record_value` is
  `anvilid-domain-verification=` followed by a 26-character token. Publish the value exactly, as
  one TXT record (it may be split into several strings within that record).
- The domain is normalised (lowercase, IDNs as A-labels). Public suffixes, IP addresses,
  wildcards, single labels, URLs (scheme, port or path) and reserved names (`localhost`, `.local`,
  `.internal`, `.invalid`, `.test`, `.example`) are refused with `422`.
- Then call `POST /organizations/{org}/domains/{id}/verify`. The answer is `200` with
  `status: verified` or `status: pending`. **Every failure looks the same**: no record, a wrong
  value and a failed DNS lookup all give the identical `pending` answer.
- Within a tenant, a domain can be verified by **one organization only**. Another organization
  may claim it, but verifying it answers `409` while the first organization holds it. The same
  organization claiming a domain twice also answers `409`.
- The lookup goes to the operator's resolvers (`domain_verification_resolvers`) or the system
  resolver configuration, without caching, with a 5-second bound
  ([OPERATIONS.md](OPERATIONS.md#domain-verification-and-the-daily-re-check)).

**Daily re-check.** Verified domains are checked again about once a day. A failing check starts a
failure streak (`failing_since`), and routing keeps working. After **7 days** of failing checks the
domain returns to `pending` (audited `org_domain_unverified`, webhook
`organization.domain_unverified`): routing for it stops and its email trust ends. A successful
check ends the streak. Keep the TXT record published for as long as the domain should stay
verified.

## Home-realm discovery (identifier-first sign-in)

Each domain has two routing settings, changed with
`PATCH /organizations/{org}/domains/{id}` `{connection_id, routing, allow_local_password}`:

| Field | Default | Meaning |
|---|---|---|
| `connection_id` | none | The organization connection to route to |
| `routing` | `false` | Route addresses on this domain to that connection |
| `allow_local_password` | `true` | Keep password, email-code and magic-link sign-in for addresses on this domain |

```sh
curl -sX PATCH "$ANVIL/api/admin/v1/tenants/acme/organizations/globex/domains/$DOMAIN_ID" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"connection_id\": \"$CONNECTION_ID\", \"routing\": true}"
```

**Sign-in page.** A tenant without any routed domain keeps the combined sign-in form, unchanged.
Once a domain of the tenant is verified and routed to a connection that can route (enabled, owned
by the organization, OIDC, or SAML only while the operator flag `saml_experimental` is on: the
same rule routing uses), the sign-in page asks for the **email first**:

- An address on a routed domain whose organization turned passwords off goes straight to the
  organization's IdP.
- An address on a routed domain that still allows passwords gets a choice: **Continue with single
  sign-on** or **Use password instead**.
- Every other address, known or unknown, gets the same password step. Routing looks only at the
  domain: it reads no account and hashes nothing, so the page reveals nothing about which accounts
  exist. Subdomains of a routed domain are not routed.
- Passkey sign-in and the tenant's social buttons stay on the email page. A `login_hint` that is
  an email skips the email page and is routed at once.
- The brute-force lock page and the CAPTCHA page show the same email-first form (with the address
  filled in), and the answer is the same whether or not the account exists. When the address
  needs a CAPTCHA, the password step after the email page carries it.
- Everything works without JavaScript.

### Guards against locking an organization out

| Rule | Answer when broken |
|---|---|
| `routing: true` needs a verified domain and a target connection of the same organization that is enabled | `409` |
| `allow_local_password: false` additionally needs routing on and a target connection that has completed at least one successful sign-in (it has at least one identity link) | `409` |
| Disabling or deleting the target connection | Allowed; routing for the domain stops and local sign-in works again |
| The domain returns to `pending` (re-check) or is deleted | Routing stops |

These rules apply to organization admins and tenant admins alike. Setting up a new connection and
routing to it is allowed before anyone has signed in through it; only turning passwords off waits
for proof that SSO works.

### The `allow_local_password` trade-off

With `allow_local_password: true` (the default), a verified, routed domain offers single sign-on
first but keeps password, email-code and magic-link sign-in. Nobody is locked out while the
organization's IdP is being set up, at the cost that a former employee whose IdP account was
disabled can still sign in with a local password until the organization turns passwords off or
the account is blocked.

With `allow_local_password: false`, addresses on that domain go straight to the IdP, and password,
email-code and magic-link sign-in are refused with "use your organization's sign-in". This also
applies to codes and links requested before the switch. The refusal depends only on the email's
domain, so it reveals nothing about which accounts exist.

**Passkeys stay allowed in both modes.** A passkey is bound to the account and phishing-resistant,
and it is what an admin, or a user locked out by a broken IdP, can still use. Organizations that
want IdP-only access should also remove members' passkeys or block accounts at offboarding.

SAML routes are honoured only while the operator flag `saml_experimental` is on; with the flag
off, an address on a domain routed to a SAML connection gets the normal password step, and a
tenant whose only routes point at SAML connections keeps the combined sign-in form.

## Recovering from lockouts

The **tenant admin is always the recovery path**. Nothing an organization admin can do takes
access away from the tenant's administrators, who use system-tenant tokens and are not subject to
the organization guards.

| Situation | Recovery |
|---|---|
| The organization has no working admin | A tenant admin adds or re-assigns one: `POST /organizations/{org}/members` or `PUT /organizations/{org}/members/{user_id}/roles/{role}`. The last-org-admin guard does not apply to tenant admins |
| The organization's IdP is broken and passwords are off | Send `{"routing": false, "allow_local_password": true}` (together: turning routing off alone while passwords are off is refused) to `PATCH /organizations/{org}/domains/{id}`. An organization admin can do this too, for example signing in with a passkey |
| The IdP is broken and nobody in the organization can sign in | A tenant admin sends the same patch, or disables the connection with `PATCH /organizations/{org}/connections/{id}` `{"enabled": false}`. Disabling the target connection stops routing and restores local sign-in at once |
| A domain was verified by the wrong organization | A tenant admin deletes that organization's domain claim; the right organization can then verify it |

## Webhooks and audit

Webhook events (ids only, see [WEBHOOKS.md](WEBHOOKS.md)): `organization.created`,
`organization.deleted`, `organization.member_added`, `organization.member_removed`,
`organization.domain_verified`, `organization.domain_unverified`.

Audit actions: `organization_created|updated|deleted`, `org_member_added|removed`,
`org_role_assigned|unassigned`, `org_invitation_created|revoked|accepted`,
`org_domain_created|verified|verification_failed|updated|deleted|unverified`,
`saml_login_succeeded|failed`, plus the connection and branding events of 0.3 with the
organization in their details.

## Limitations in 1.0

- **SAML 2.0 is experimental** and off by default ([SAML.md](SAML.md)).
- **Invitations** do not return the user to the invitation after sign-in, and do not sign in a user
  who registered through one ([Invitations](#invitations)).
- **Organization admins use the API.** The admin console is for system administrators; there is no
  organization-admin console or self-service SSO setup portal in 1.0.
- **Tenant-restricted system administrators** (system roles limited to a list of tenants) are
  deferred to Phase 7.
- The admin API has no per-user membership list and no email filter on the user list; the console
  works around both with several requests.
- Tenant YAML documents do not contain organizations or anything they own
  ([CONFIG-YAML.md](CONFIG-YAML.md#organizations-are-not-part-of-the-document)).
