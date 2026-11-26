# Putting an MCP server behind AnvilID

This guide shows how to use AnvilID as the authorization server of an MCP (Model Context
Protocol) server. MCP clients find AnvilID through the MCP server's metadata. They identify
themselves with a Client ID Metadata Document, or register dynamically, and they receive access
tokens bound to that one MCP server.

The MCP requirements quoted here come from the MCP authorization specification, **revision
2026-07-28** ("Authorization", "Authorization Server Discovery", "Client Registration" and
"Security Considerations"), checked against the published specification on 2026-11-26. Later
revisions may differ, so check the current one before relying on a detail.

AnvilID 0.4 provides:

| MCP needs | AnvilID 0.4 |
|---|---|
| Authorization server metadata (RFC 8414 or OpenID Connect Discovery) | Both, per tenant, including RFC 8414 path insertion for path tenants |
| PKCE with S256, advertised in `code_challenge_methods_supported` | S256 only, and PKCE is always required for metadata-document and dynamic clients |
| Client ID Metadata Documents (`client_id_metadata_document_supported`) | draft-ietf-oauth-client-id-metadata-document-03, one tenant setting (off by default) |
| Dynamic client registration (RFC 7591), optional in MCP | RFC 7591 and RFC 7592, one tenant setting (off by default) |
| Resource indicators (RFC 8707) at `/authorize` and `/token` | Yes. The access token `aud` is the requested resource |
| `iss` in the authorization response (RFC 9207) | Yes, advertised with `authorization_response_iss_parameter_supported` |
| Protected resource metadata (RFC 9728) | Published by **your MCP server**, not by AnvilID (see step 1) |

The MCP specification cites draft -00 of the Client ID Metadata Document specification. AnvilID
implements draft -03. The rules a client needs to follow are listed in step 3.

## The issuer and its metadata URLs

Every tenant is its own authorization server with its own issuer:

| Tenant | Issuer |
|---|---|
| `default` | the public URL, for example `https://id.example.com` |
| a path tenant, for example `agents` | `https://id.example.com/t/agents` |
| a tenant with its own host | `https://agents.example.com` |

The admin API returns the issuer of each tenant (`issuer` and `discovery_url` on
`GET /api/admin/v1/tenants/{slug}`).

For an issuer with a path, MCP clients try three metadata URLs in this order:

1. `https://id.example.com/.well-known/oauth-authorization-server/t/agents` (RFC 8414 path
   insertion). AnvilID serves this URL.
2. `https://id.example.com/.well-known/openid-configuration/t/agents` (OpenID Connect path
   insertion). AnvilID does **not** serve this URL. Clients that follow the MCP order never reach
   it, because URL 1 answers first.
3. `https://id.example.com/t/agents/.well-known/openid-configuration` (path appending). AnvilID
   serves this URL.

All URLs that AnvilID serves for a tenant return the same document. Its `issuer` is exactly the
tenant issuer, and MCP clients reject a document whose `issuer` differs from the issuer they
started from. For the default tenant and for host tenants, the root URLs
`/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` are used.

Fields that MCP clients read:

| Field | Value |
|---|---|
| `issuer` | the tenant issuer |
| `authorization_endpoint`, `token_endpoint` | `{issuer}/authorize`, `{issuer}/token` |
| `jwks_uri` | `{issuer}/jwks` |
| `code_challenge_methods_supported` | `["S256"]` |
| `authorization_response_iss_parameter_supported` | `true` |
| `client_id_metadata_document_supported` | `true` only while the tenant's CIMD policy is not `disabled` |
| `registration_endpoint` | `{issuer}/register`, only while the tenant's DCR policy is not `disabled` |

The system tenant (the one that holds the console and the admin API) never advertises CIMD or
DCR and cannot enable them. Use a separate tenant for agents.

## Step 1: publish protected resource metadata on the MCP server

MCP clients start from the MCP server. The server publishes an OAuth 2.0 Protected Resource
Metadata document (RFC 9728) that names the AnvilID tenant issuer as its authorization server.
Example ([docs/examples/mcp/oauth-protected-resource.json](examples/mcp/oauth-protected-resource.json)):

```json
{
  "resource": "https://mcp.example.com/mcp",
  "resource_name": "Example MCP server",
  "authorization_servers": ["https://id.example.com/t/agents"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["openid", "profile"]
}
```

- `resource` is the canonical URL of the MCP endpoint. Clients send exactly this string as the
  RFC 8707 `resource` parameter, and AnvilID compares it exactly (see step 2). RFC 9728 §3.3
  requires `resource` to be identical to the URL the client requested, so publish the same string
  everywhere. MCP recommends the form without a trailing slash.
- `authorization_servers` holds the tenant issuer, exactly as in AnvilID's metadata (no trailing
  slash).
- Serve the document over https, at the path-inserted well-known URL for the endpoint
  (`https://mcp.example.com/.well-known/oauth-protected-resource/mcp` for `/mcp`). MCP clients
  fall back to the root `/.well-known/oauth-protected-resource` when no hint is given.

When a request has no valid token, answer `401` and point at the document (RFC 9728 §5.1):

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
```

For a token that fails validation, add `error="invalid_token"` to the same header. MCP also lets
the server add a `scope="..."` parameter that names the scopes the request needs.

## Step 2: allow the MCP server as a resource

AnvilID issues a token for a resource only when the client is allowed to request that resource.
Matching is an exact string comparison with no normalisation. `https://mcp.example.com/mcp`,
`https://mcp.example.com/mcp/` and `https://MCP.example.com/mcp` are three different resources.
Register exactly the string the server publishes as `resource`. The MCP specification asks
implementations to accept uppercase scheme and host variants. AnvilID 0.4 does not, so make sure
clients use the published string.

- **Metadata-document and dynamically registered clients** get their resources from the tenant
  setting `dcr.allowed_resources`. One list covers both kinds of client, and 0.4 has no separate
  CIMD resource setting.
- **Static clients** (created by an administrator) have their own `allowed_resources` list on the
  client.

Resource indicators must be absolute URIs without a fragment or query, at most 2048 characters.

```sh
curl -X PATCH https://id.example.com/api/admin/v1/tenants/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"settings": {"dcr": {"allowed_resources": ["https://mcp.example.com/mcp"]}}}'
```

The PATCH merges field by field: fields you leave out keep their value, and a list replaces the
whole list. The token needs `admin:tenants:write` (or `admin:write`).

## Step 3: enable Client ID Metadata Documents

With CIMD, an MCP client's `client_id` is an https URL that serves a JSON document describing the
client. No registration step is needed. Enabling it is one tenant setting:

```sh
curl -X PATCH https://id.example.com/api/admin/v1/tenants/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"settings": {"cimd": {"policy": "open"}}}'
```

The same settings as an excerpt of a declarative tenant document
([CONFIG-YAML.md](CONFIG-YAML.md)):

```yaml
tenant:
  slug: agents
  settings:
    cimd:
      policy: open
    dcr:
      allowed_resources: [https://mcp.example.com/mcp]
```

Policies (`cimd.policy`):

| Policy | Effect |
|---|---|
| `disabled` (default) | URL client ids are ordinary unknown ids, and nothing is fetched. Existing metadata-document clients stop working at once. |
| `allow_listed` | Only documents on hosts in `cimd.allowed_hosts` are fetched (at least one host is required). |
| `open` | Any https document URL that passes the URL checks is fetched. |

`cimd.allowed_hosts` holds host names or IP literals with no scheme, port, path or wildcard
(at most 100, no duplicates). Matching ignores the port.

### What a client's document must look like

- The `client_id` URL is https, with a path other than `/`, and has no userinfo, query, fragment
  or dot segments. In production, plain http is refused, loopback included.
- The document is a JSON object of at most 5 KiB. Its `client_id` equals the document URL by
  plain string comparison.
- `redirect_uris` is required and follows the usual redirect URI rules. Loopback redirect URIs
  (`http://127.0.0.1:{port}/...`) need `"application_type": "native"`.
- `token_endpoint_auth_method` is `none` (the default when absent) or `private_key_jwt` with an
  **inline** `jwks`. `jwks_uri` is not supported in 0.4: a document that contains it is refused,
  even next to `jwks`. Shared-secret methods and `client_secret` are refused.
- `grant_types` and `response_types` are intersected with what AnvilID supports for these clients
  (authorization code, refresh token, response type `code`).
- `scope` must not contain `admin:` scopes. When `scope` is absent, the client gets `openid`.
- `client_name` is optional and is shown as unverified (see "Consent").

Minimal example:

```json
{
  "client_id": "https://agent.example.net/client.json",
  "client_name": "Example Agent",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "application_type": "native",
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile"
}
```

### How AnvilID fetches documents

- Documents are fetched only through AnvilID's outbound HTTP client. Private, loopback and
  link-local destinations are blocked, redirects are not followed, and the response is capped
  at 5 KiB.
- The policy, the URL rules and the host allow-list are checked before anything is fetched.
- A valid document is stored as a client of the tenant (`registration_source: cimd` in the admin
  API's client list, where it can also be deleted). Its lifetime is the document's
  `Cache-Control: max-age`, clamped to `cimd.min_cache_secs..=cimd.max_cache_secs` (defaults 300
  and 86400 seconds, allowed range 60 to 604800). Without `max-age` the minimum applies.
- Errors are never cached. A refused document (invalid, too large, a 3xx or 4xx answer, a blocked
  destination) leads to `invalid_client`, and nothing is stored. A transient failure (network,
  timeout, 429, 5xx) leads to `503`, unless a stored copy exists that is less than
  `max_cache_secs` past its expiry, in which case the stored copy is used.
- At `/authorize`, a refused or unknown client gets an error page. AnvilID never redirects to a
  redirect URI it could not verify.
- Fetches have a per-host budget in the `Auth` rate class. The budget is **installation-wide**:
  one counter per document host, shared by all tenants, to protect the third-party host. At most
  16 fetches run at the same time.

### Local development

When AnvilID runs in development mode (public URL `http://localhost...` or `http://127.0.0.1...`),
documents may also be served over plain http from a loopback address, for example
`http://127.0.0.1:8123/client.json`. The e2e test uses this mode. Production document URLs must
be https.

## Optional: dynamic client registration

MCP lets clients fall back to dynamic registration (RFC 7591) when CIMD is not available. In
AnvilID it is a separate tenant setting, `dcr.policy`:

| Policy | Effect |
|---|---|
| `disabled` (default) | `/register` and `/register/{client_id}` answer 404, and there is no `registration_endpoint` in the metadata. |
| `allow_listed` | Registration needs an initial access token (`Authorization: Bearer ...`), and redirect URI hosts must be in `dcr.allowed_redirect_hosts`. |
| `open` | Anyone may register. |

- Requests are `application/json`. A successful registration answers `201` with the registered
  metadata, `client_id`, `registration_client_uri` and a `registration_access_token` for RFC 7592
  read, replace and delete. Registered clients always need PKCE and always get the consent
  screen. MCP revision 2026-07-28 asks clients to send `application_type` (`native` for loopback
  redirect URIs).
- Scopes: a client may register only scopes from `dcr.allowed_scopes`. When the list is empty,
  the default is `openid profile email address phone` (the same list as `scopes_supported`).
  `admin:` scopes are never registrable.
- `logo_uri`, `client_uri`, `policy_uri` and `tos_uri` are validated, but they are neither stored
  nor echoed in the response.
- Initial access tokens (`POST /api/admin/v1/tenants/{slug}/initial-access-tokens` with
  `description`, `expires_in` in seconds and `uses`) are shown once and stored hashed. They always
  expire: the default is 24 hours, the allowed range 1 minute to 365 days. `uses` is 1 to 100000,
  or omitted for unlimited. A rejected registration does not consume a single-use token.
- `dcr.max_clients` (default 1000, at most 1000000) is a **soft** cap. Clients are counted before
  each insert, so concurrent registrations can overshoot it by the number of requests in flight.
- Setting the policy back to `disabled` makes the RFC 7592 endpoints answer 404 as well.
- Every `/register*` request (any method) is rate limited in the `Auth` class.

## Consent

Metadata-document and dynamically registered clients always see the consent screen: their
clients created through CIMD or DCR get `consent_mode: required`.

- A metadata-document client is named by the **host of its `client_id`**, including a non-default
  port. Its `client_name` is shown separately and marked "name not verified". The screen shows
  initials instead of a logo, because AnvilID never loads images from a client's server.
- The screen lists the requested resources (the MCP server URLs) under "Access to".
- A remembered consent covers its scopes **and** resources. A request for a resource the user has
  not approved yet shows the screen again. A request with `prompt=none` then fails with
  `consent_required`.
- Users can revoke an app at `/ui/account/apps`, which also revokes its refresh tokens.

## Tokens and how the MCP server validates them

A client that sends `resource=https://mcp.example.com/mcp` to `/authorize` and `/token` (MCP
requires both) gets an access token with:

- `aud` equal to `"https://mcp.example.com/mcp"`. With one resource `aud` is a string. With
  several it is an array in request order. Without a resource, `aud` is the client id. At the
  token endpoint a client can only narrow the resources it was granted. Any other resource is
  `invalid_target`, and the code is consumed.
- `iss` equal to the tenant issuer, plus `client_id`, `scope`, `sub`, `iat` and `exp` (access
  tokens live 10 minutes).
- A JWT with header `typ: at+jwt` (RFC 9068), signed with one of the tenant's signing algorithms
  (RS256, PS256, ES256 or Ed25519). Metadata-document clients always get JWT access tokens.

The ID token keeps `aud` = the client id. AnvilID's own UserInfo endpoint refuses an access
token whose `aud` holds only other resources.

Checklist for the MCP server (RFC 9068 §4, OAuth 2.1 §5.2, MCP "Token Handling"):

1. Take the token from the `Authorization: Bearer` header only, never from the query string.
2. Parse it as a compact JWS. Require `typ` = `at+jwt`, and an `alg` from the list above (never
   `none`).
3. Verify the signature with the key whose `kid` matches, taken from the tenant's `jwks_uri` (from
   the authorization server metadata). Cache the key set. On an unknown `kid`, fetch it once more
   (signing keys rotate).
4. `iss` must equal the tenant issuer exactly.
5. `aud` (a string or an array) must contain the server's own `resource` URL exactly. Refuse
   tokens issued for other audiences, and never forward a client's token to another service.
6. `exp` must be in the future. If `nbf` is present, it must not be in the future (allow a small
   clock skew).
7. Check `scope` against what the request needs: answer `403` with
   `error="insufficient_scope"` when a scope is missing.
8. On any failure, answer `401` with `WWW-Authenticate: Bearer error="invalid_token",
   resource_metadata="..."`.

## Testing it locally

`tests/mcp/` contains a zero-dependency mock MCP server and a mock MCP client that perform these
steps against a running AnvilID in development mode. `tests/e2e/specs/mcp.spec.ts` runs the whole
journey in a browser: discovery, consent, the code exchange with `resource`, the MCP server
accepting the token, and the error page once the CIMD policy is disabled. See
[tests/mcp/README.md](../tests/mcp/README.md).

## Limits in 0.4

- No `jwks_uri` in metadata documents: `private_key_jwt` clients put their keys inline (`jwks`).
- Metadata-document clients take their resources from `dcr.allowed_resources`. There is no
  separate CIMD resource list.
- Resource indicators match exactly, with no case folding or trailing-slash normalisation.
- The CIMD fetch budget is per document host for the whole installation, not per tenant.
- `dcr.max_clients` is a soft cap.
- The OpenID Connect path-insertion URL (`/.well-known/openid-configuration/t/{slug}`) is not
  served. The RFC 8414 and path-appended URLs are.
