# MCP authorization mocks

Two zero-dependency Node.js modules (only `node:http` and `node:crypto`) that act out the
authorization side of the Model Context Protocol against AnvilID. The e2e spec
`tests/e2e/specs/mcp.spec.ts` (through `tests/e2e/lib/mcp.ts`) uses them, and they can also run on
their own. See [docs/MCP.md](../../docs/MCP.md) for the integration guide.

| File | Role |
|---|---|
| `mock-mcp-server.ts` | An MCP resource server. `/mcp` answers 401 with `WWW-Authenticate: Bearer resource_metadata="…"` and serves the RFC 9728 document naming the tenant issuer. It accepts a bearer token only after checking `typ` (`at+jwt`), `alg`, the signature against the issuer's JWKS, `iss`, `aud` (its own `/mcp` URL) and `exp`. |
| `mock-mcp-client.ts` | An MCP client. It discovers the resource metadata and then the authorization server metadata in the MCP order (RFC 8414 path insertion first) and checks `issuer` and S256. It serves its Client ID Metadata Document at `http://127.0.0.1:<port>/client.json`, builds the PKCE authorization URL with `resource`, checks `state` and `iss` on the callback, exchanges the code with the same `resource` and calls the MCP server. |

Both bind `127.0.0.1` on a free port and use plain http. AnvilID fetches an http metadata
document only in development mode (a public URL such as `http://localhost:8080`), and only from
loopback. Real clients and servers use https.

## Run by hand

Node.js 22.18 or later (type stripping is on by default from Node 23.6 and 22.18):

```sh
# 1. AnvilID in development mode, with a tenant `agents` whose CIMD policy is `open` and whose
#    dcr.allowed_resources lists the mock server's URL (step 2 prints it; set it afterwards with
#    PATCH /api/admin/v1/tenants/agents, see docs/MCP.md).
anvilid serve --public-url http://localhost:8080

# 2. The MCP server, protected by the tenant issuer.
node tests/mcp/mock-mcp-server.ts http://localhost:8080/t/agents 8931

# 3. The MCP client: prints an authorization URL. Open it, sign in and approve. The client then
#    exchanges the code and calls the MCP server.
node tests/mcp/mock-mcp-client.ts http://127.0.0.1:8931/mcp "openid profile"
```

## Run the e2e spec

```sh
tests/e2e/run.sh sqlite specs/mcp.spec.ts
```

`run.sh` needs Docker (for Mailpit). The spec itself does not send mail, so it can also run
against a local development-mode instance by setting `ANVIL_URL`, `SETUP_URL` and
`E2E_STATE_FILE` as `run.sh` does.
