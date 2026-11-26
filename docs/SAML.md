# SAML 2.0 connections (experimental)

Added in 1.0, **experimental**. An organization can sign its users in through its own SAML 2.0
identity provider (IdP), with AnvilID acting as the service provider (SP). This guide states
exactly what is supported, what AnvilID checks, how the implementation is tested, and what still
has to happen before SAML loses the experimental label. Organizations, domains and routing are
described in [ORGANIZATIONS.md](ORGANIZATIONS.md).

## Status: experimental and off by default

SAML is behind the operator key **`saml_experimental`** (`ANVILID_SAML_EXPERIMENTAL`,
`--saml-experimental`), default **`false`**.

- **Off:** every SAML route (`/ui/login/saml/…`, `/saml/{slug}/metadata`) answers `404`. Creating
  a SAML connection, importing IdP metadata, enabling a stored SAML connection or changing one
  answers `403` (`feature_disabled`). Disabling and deleting still work, so a SAML connection can
  always be turned off. Domains routed to a SAML connection are not routed (their users get the
  password step), and the tenant view reports `features.saml: false`.
- **On:** the server logs a warning at start and `anvilid config validate` prints it. The console
  marks every SAML connection **Experimental**.

**Why it stays off by default through 1.0** (decision Q3): signature wrapping and XML parser
differences have broken SAML service providers in many products over the years, and the risk sits
in exactly the code this feature adds: the XML parser, canonicalisation, the signature verifier
and the logic that decides which element was signed. AnvilID uses a pure-Rust stack for this
(below), and its own SAML layer is new. The attack corpus described below passes in CI, but a
passing corpus shows that the known attacks fail, not that no unknown one succeeds. SAML stays
experimental until the Phase 7 external security review and a real-IdP interop run (the
[checklist](#real-idp-interop-checklist-template) at the end) are done. Turn it on only for
organizations that need it, and prefer OIDC when the IdP offers both.

## Supported profile

AnvilID implements one narrow profile and refuses everything else.

| Aspect | Supported | Not supported |
|---|---|---|
| Initiation | SP-initiated Web Browser SSO | **IdP-initiated SSO is refused** (decision Q4): an unsolicited response has no matching pending request and fails |
| Request binding | HTTP-Redirect `AuthnRequest`, **unsigned** (raw DEFLATE, base64, `SAMLRequest` + `RelayState`) | Signed AuthnRequests, POST binding for requests |
| Response binding | HTTP-POST to the ACS | Artifact binding, Redirect binding for responses |
| Signatures | The **Assertion must be signed**. The Response may be signed in addition; if it is, that signature must verify too. A response signed only at the Response level is refused | Unsigned assertions |
| Signature algorithms | RSA-SHA256/384/512, ECDSA-SHA256/384 | SHA-1, HMAC, any other method |
| Digests | SHA-256/384/512 | SHA-1 |
| Canonicalisation and transforms | Exclusive C14N (without comments), with exactly the enveloped-signature transform followed by exclusive C14N | Inclusive C14N, C14N with comments, XPath, XSLT, any other or extra transform |
| Keys | 1 to 3 pinned IdP signing certificates per connection (rollover); only their public keys are used | Keys or certificates from `KeyInfo`, `RetrievalMethod`, certificate chains or trust stores |
| Encryption | None | `EncryptedAssertion`, `EncryptedID`, `EncryptedAttribute` (refused) |
| Logout | None | Single Logout (SLO) |
| NameID | `persistent`, `emailAddress`, `unspecified` (requested format configurable) | `transient` (refused: it cannot identify a returning user) |
| Attributes | `email`, `given_name`, `family_name`, `name`, each mapped from an attribute `Name` or `FriendlyName`; the first value is used | Other attributes are ignored |
| SP metadata | Unsigned, served at `{issuer}/saml/{slug}/metadata` | Signed SP metadata |
| IdP metadata | Imported once from pasted XML or an https URL (fetched through the guarded outbound client, at most 1 MiB) to fill the fields | Automatic metadata refresh: re-import to pick up new certificates |

The SP values of a connection (also shown in the console with copy buttons, and in the API under
`sp`):

| Value | Form |
|---|---|
| SP entity ID (the IdP's audience) | `{issuer}/saml/{slug}` |
| ACS URL (the IdP's reply URL, also `Recipient` and `Destination`) | `{issuer}/ui/login/saml/{slug}/acs` |
| SP metadata | `{issuer}/saml/{slug}/metadata` |

`{issuer}` is the tenant's issuer (for example `https://id.example.net/t/acme`) and `{slug}` the
connection slug.

## Setting up a connection

With the flag on, an organization admin or a tenant admin (see
[ORGANIZATIONS.md](ORGANIZATIONS.md#organization-admins)):

```sh
# 1. Optional: let AnvilID read the IdP metadata (nothing is stored)
curl -sX POST "$ANVIL/api/admin/v1/tenants/acme/organizations/globex/connections/saml-metadata" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"url": "https://idp.example.com/saml/metadata"}'
# -> {"idp_entity_id": "...", "sso_url": "https://...", "signing_certs": ["-----BEGIN CERTIFICATE-----..."], "metadata_url": "..."}

# 2. Create the connection
curl -sX POST "$ANVIL/api/admin/v1/tenants/acme/organizations/globex/connections" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"slug": "globex-saml", "display_name": "Globex",
       "config": {"type": "saml",
                  "idp_entity_id": "https://idp.example.com/entity",
                  "sso_url": "https://idp.example.com/saml/sso",
                  "signing_certs": ["-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"],
                  "name_id_format": "persistent",
                  "attributes": {"email": "email", "given_name": "given_name", "family_name": "family_name"}}}'
```

- `idp_entity_id`: 1 to 1024 bytes. `sso_url` and `metadata_url` must be `https`.
- `signing_certs`: 1 to 3 PEM blocks of one `CERTIFICATE` each, at most 16 KiB each. Expired
  certificates are accepted (the console warns), because only the pinned public key matters.
- IdP metadata must contain an IdP SSO descriptor with an HTTP-Redirect SSO endpoint over https
  and at least one signing certificate. Metadata URLs pass the outbound policy (no private,
  loopback or link-local destinations unless allow-listed by the operator).
- A SAML connection has no secret (`PUT …/secret` answers `422`). SAML connections exist only
  in organizations; the tenant-level connection API refuses them.

Then configure the application at the IdP with the SP entity ID and ACS URL from the response,
verify a domain and route it to the connection (ORGANIZATIONS.md). Users on that domain are sent
to the IdP from the email-first page; a request with `organization=globex` goes straight to the
IdP when the connection is the organization's only enabled one.

## What AnvilID checks

### The browser binding

1. **Start** (`POST /ui/login/saml/{slug}/start?flow=`, CSRF-bound to the sign-in flow): AnvilID
   creates a request id (`_` + 32 hex characters), stores it in the flow with the hash of a
   59-byte `RelayState` (flow id plus a random nonce) and sets the same `SameSite=Lax` binding
   cookie as upstream OIDC sign-in. `ForceAuthn="true"` is sent when the authorization request has
   `prompt=login`. The pending request expires after 10 minutes.
2. **ACS** (`POST /ui/login/saml/{slug}/acs`): outside the cross-site form protection, because the
   IdP posts from its own origin. It reads and sets no cookie. The body limit is 256 KiB (`413`
   above). The `RelayState` must name a live flow and match the stored hash, the flow's pending
   request must exist and be for this connection, and it is consumed once by compare-and-swap. A
   valid response seals only the extracted identity into the flow.
3. **Continue** (`GET /ui/login/saml/{slug}/continue`): requires the binding cookie of the browser
   that started the sign-in, then completes like every upstream sign-in (account linking, MFA
   policy, session, `amr: ["fed"]`).

### The XML document

Before the signature library sees the document, AnvilID parses it once with DTDs forbidden
(no `DOCTYPE`, no entities, internal or external), a depth limit of 64 and a markup cap, and runs a
strict profile check on that one parsed document:

- exactly one `Response` root (SAML 2.0) with only the expected children; exactly one `Assertion`
  anywhere in the document, as a direct child of the `Response`; no `Advice`, no processing
  instructions, no duplicate attributes, no duplicate ids across every id attribute name;
- the Assertion signature sits at its schema position (right after the Assertion's `Issuer`), the
  optional Response signature right after the Response `Issuer`; no other signature anywhere;
- each signature has exactly one `Reference`, whose `URI` is `#` plus the id of its parent element
  (no empty, external, file or other-element reference), the allowed algorithms and transforms
  above, non-empty digest and signature values, no `Object` and no key retrieval;
- no encrypted elements; `NameID` and attribute values must be plain text (a comment or element
  inside them is refused).

The signature is then verified (bergshamra-dsig on aws-lc) against the configured certificates
only, the verified reference must resolve to the pinned Assertion node, and every claim is read
from that verified node and nowhere else.

### The assertion

After the signature, in this order (each failure has its own reason code in the audit event
`saml_login_failed`; the user always sees one generic error page):

| Check | Reason code |
|---|---|
| Response `Destination` equals the ACS URL | `destination_mismatch` |
| Response `InResponseTo` equals the pending request id | `in_response_to_mismatch` |
| Status is `Success` | `status_not_success` |
| Response `Issuer`, if present, equals the IdP entity ID | `response_issuer_mismatch` |
| `IssueInstant` present, not in the future beyond the skew, not older than 1 hour | `issue_instant_invalid` |
| Assertion id present (the replay guard needs it) | `missing_assertion_id` |
| Assertion `Issuer` equals the IdP entity ID | `assertion_issuer_mismatch` |
| `NameID` present and not blank; not `transient` | `empty_name_id`, `transient_name_id` |
| A bearer `SubjectConfirmation` exists | `no_bearer_confirmation` |
| Its `Recipient` equals the ACS URL | `recipient_mismatch` |
| Its `InResponseTo` equals the request id | `confirmation_in_response_to_mismatch` |
| Its `NotOnOrAfter` is present and not passed | `confirmation_missing_not_on_or_after`, `confirmation_expired` |
| `Conditions` present, with `NotOnOrAfter`; `NotBefore` reached; not expired | `missing_conditions`, `conditions_missing_not_on_or_after`, `not_yet_valid`, `conditions_expired` |
| An `AudienceRestriction` exists, and every one contains the SP entity ID | `missing_audience_restriction`, `audience_mismatch` |
| An `AuthnStatement` exists | `missing_authn_statement` |
| The assertion id was not seen before | `replay` |

The clock skew is 90 seconds. **Replay protection:** the assertion id is recorded in the database
replay guard (keyed by a hash of the IdP entity ID and the assertion id) until the assertion's
`NotOnOrAfter`, at most one hour. Because the guard is in the database, a response replayed to
another node of the same installation is refused as well.

XML-level reason codes: `size`, `parse`, `dtd`, `structure`, `duplicate_id`, `encrypted`,
`signature_profile`, `algorithm`, `signature`, `untrusted_key`. Flow-level codes: `relay_state`
(also covers unsolicited, IdP-initiated responses), `no_pending_request`, `expired`,
`connection_mismatch`, `connection_disabled`, `binding`, `state_invalid`, `encoding`.

### The account

A SAML sign-in completes through the same code as organization OIDC connections
([ORGANIZATIONS.md](ORGANIZATIONS.md#enterprise-oidc-connections)): the subject is the `NameID`;
the asserted email is trusted only when its domain is one of the organization's verified domains
(SAML has no `email_verified`, so the verified domain alone decides); just-in-time accounts get
the membership and default roles; another organization's domain never auto-links.

## Testing: the attack corpus is necessary, not sufficient

- **Attack corpus** (`crates/anvil-web/tests/security_saml.rs`, runs in CI): 67 cases, each
  asserting its exact reason code. They cover the eight classic XML signature wrapping shapes
  (XSW1-XSW8) and variants (signed assertion moved into `Extensions`, `Advice`,
  `SubjectConfirmationData`, a signature `Object`), signature exclusion, key injection through
  `KeyInfo`, comment and element injection in `NameID` and attributes, namespace and prefix
  tricks, parser differentials, void canonicalisation, algorithm downgrades (SHA-1, HMAC, other
  canonicalisations and transforms), external and file references, DTDs and entity expansion,
  duplicate ids, encrypted elements, oversized and deeply nested documents. Several cases are
  documents the signature library alone accepts; AnvilID's profile check refuses them.
- **Adapter and flow tests:** `saml_xml_adapter.rs` (every extracted field, certificate rollover,
  metadata import), `saml_login.rs` (start, ACS, continue, replay across instances, unsolicited
  responses, binding cookie, expiry, the flag), and unit tests for every assertion check.
- **Fuzzing:** `saml_response_parse` and `saml_metadata_parse` run in the nightly fuzz workflow.
- **Browser e2e:** `tests/e2e/specs/saml.spec.ts` signs in through a local mock IdP
  (`tests/e2e/lib/mock-saml-idp.ts`).

A green corpus proves that the attacks we know about fail. It does not prove that none we have not
thought of succeeds, and it says nothing about interoperability with real IdPs. Hence the
experimental flag, the external review and the checklist below.

## Dependencies and the `chrono` exception

The SAML stack is `bergshamra-dsig` / `bergshamra-keys` / `bergshamra-xml` 0.12 for XML signatures
(built with `default-features = false, features = ["aws-lc"]`, so all signature cryptography runs on
aws-lc-rs, the project's single crypto backend), `uppsala` as the only XML parser, `flate2`
(pure-Rust backend) for the Redirect binding, and AnvilID's own SAML layer on top. No C XML
security library is used (`samael`/`xmlsec` stay banned).

`bergshamra-keys` depends on `tsp-ltv` (its X.509 trust facade), which depends on `chrono`.
`chrono` is otherwise banned (ARCHITECTURE §2: one time library, `time`). `deny.toml` has exactly
one exception for it, scoped with `wrappers = ["tsp-ltv"]`, so no other crate may pull it in and
AnvilID's own code stays on `time`. `cargo tree -i chrono` must show `tsp-ltv` as the only
parent. AnvilID pins the IdP keys and skips X.509 time and chain checks, so certificate
validity is never judged with `chrono` types. This exception is flagged for the owner's review
(ARCHITECTURE §20, D4).

## Decisions

- **Q3: experimental flag.** SAML stays behind `saml_experimental`, off by default, through 1.0,
  even with the corpus green, until the Phase 7 external security review and a real-IdP interop
  run.
- **Q4: IdP-initiated SSO.** Refused in 1.0. Every response must answer a pending request of the
  same browser flow (`InResponseTo`, `RelayState`, binding cookie).
- Unsigned AuthnRequests: AnvilID holds no SP signing key; the response checks
  (`InResponseTo`, `Destination`, `Recipient`, audience) bind the response to the request.

## Real-IdP interop checklist (template)

To be completed in Phase 7 for each IdP before the experimental label is removed. Record the IdP
version or service date, who ran it, and the result of every row. Use a fresh tenant, a verified
test domain and test accounts only; never paste production metadata or certificates into issues.

IdPs to cover: Microsoft Entra ID, Okta, Google Workspace, Keycloak.

| # | Step | Entra ID | Okta | Google Workspace | Keycloak |
|---|---|---|---|---|---|
| 1 | Create the SAML application at the IdP with the SP entity ID and ACS URL from AnvilID | | | | |
| 2 | Import the IdP metadata into AnvilID (URL or pasted XML); entity ID, SSO URL and certificate filled in | | | | |
| 3 | Assertion signing enabled at the IdP; algorithm used (must be SHA-256 or stronger) | | | | |
| 4 | NameID format sent; it is `persistent`, `emailAddress` or `unspecified` and stable for one user | | | | |
| 5 | Attribute names for email, given name and family name; mapping set in AnvilID | | | | |
| 6 | SP-initiated sign-in from the email-first page: just-in-time user, link and membership created; email trusted on the verified domain | | | | |
| 7 | Second sign-in of the same user signs in through the existing link | | | | |
| 8 | `prompt=login` sends `ForceAuthn`, and the IdP asks for credentials again | | | | |
| 9 | IdP-initiated sign-in (from the IdP's app portal) is refused with the generic error | | | | |
| 10 | Replaying a captured response is refused (`replay` or `relay_state`) | | | | |
| 11 | Clock skew within 90 seconds is accepted | | | | |
| 12 | Certificate rollover: add the new certificate as a second entry, switch the IdP, remove the old one; sign-in works throughout | | | | |
| 13 | Encrypted assertions turned on at the IdP are refused (`encrypted`), and work again when turned off | | | | |
| 14 | Response-only signing (assertion unsigned) is refused (`signature_profile`) | | | | |
| 15 | Organization MFA policy applies after a SAML sign-in | | | | |
| 16 | Audit shows `saml_login_succeeded` and, for every failure above, `saml_login_failed` with the expected reason | | | | |

Notes per IdP (settings that had to be changed, error messages seen):

- Entra ID:
- Okta:
- Google Workspace:
- Keycloak:
