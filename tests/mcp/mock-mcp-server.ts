// A mock MCP resource server (an OAuth protected resource) for the MCP authorization tests.
//
// Zero npm dependencies (node:http, node:crypto), so it also runs on its own with
// `node tests/mcp/mock-mcp-server.ts <issuer> [port]` (Node.js 22.18+ / 24 strip the types).
// It implements only the authorization surface of an MCP server, not the MCP protocol itself:
//
//   GET|POST /mcp without a bearer token
//        401 with `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource/mcp"`
//        (RFC 9728 §5.1), the discovery hint MCP clients start from.
//   GET /.well-known/oauth-protected-resource/mcp (RFC 9728 §3.1 path insertion for `<base>/mcp`;
//        also served at the root /.well-known/oauth-protected-resource, the MCP fallback)
//        the RFC 9728 document: `resource` = the MCP endpoint URL, `authorization_servers` = the
//        AnvilID tenant issuer, `bearer_methods_supported` = ["header"].
//   GET|POST /mcp with `Authorization: Bearer <JWT access token>`
//        200 `{ ok, sub, client_id, scope }` when the token passes every check below, otherwise
//        401 with `error="invalid_token"` (and the same resource_metadata). The token is never
//        echoed or logged.
//
// Token checks (what docs/MCP.md asks of a real MCP server): compact JWS; header `typ` is
// `at+jwt` (RFC 9068 §4); `alg` is one AnvilID signs with (RS256, PS256, ES256, Ed25519; never
// `none`) and matches the key's `alg`; the signature verifies against the issuer's JWKS (fetched
// from `jwks_uri` of `{issuer}/.well-known/openid-configuration`, refetched once for an unknown
// `kid`); `iss` equals the configured issuer exactly; `aud` (string or array) contains this
// server's resource URL exactly; `exp` is in the future and `nbf`/`iat` are not in the future
// (60 s leeway).
//
// The server binds 127.0.0.1 on a free port; everything it talks to is passed in. Plain http is
// only for local tests: a real MCP server and its metadata are served over https.

import { createPublicKey, constants as cryptoConstants, verify } from 'node:crypto';
import type { JsonWebKey, KeyObject } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { pathToFileURL } from 'node:url';

export interface MockMcpServerOptions {
  /** The AnvilID tenant issuer named in `authorization_servers` and required as `iss`. */
  issuer: string;
  /** JWKS URL; default: `jwks_uri` of `{issuer}/.well-known/openid-configuration`. */
  jwksUri?: string;
  /** Port on 127.0.0.1 (default: a free port). */
  port?: number;
  /** Scopes listed in the RFC 9728 document (`scopes_supported`), if any. */
  scopesSupported?: string[];
}

/** One request to /mcp as seen by the server (no token material). */
export interface McpRequestLog {
  method: string;
  status: number;
  /** Why a token was refused (`missing`, `aud`, `iss`, `exp`, `signature`, ...). */
  reason?: string;
}

export interface MockMcpServer {
  /** `http://127.0.0.1:<port>` */
  base: string;
  /** The MCP endpoint and RFC 8707 resource indicator: `{base}/mcp`. */
  resource: string;
  /** `{base}/.well-known/oauth-protected-resource/mcp` (the `resource_metadata` hint) */
  metadataUrl: string;
  /** Requests to /mcp, oldest first. */
  requests: McpRequestLog[];
  stop(): Promise<void>;
}

const LEEWAY_SECS = 60;
const ALLOWED_ALGS = new Set(['RS256', 'PS256', 'ES256', 'Ed25519']);

class TokenError extends Error {}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(text),
    ...headers,
  });
  res.end(text);
}

async function fetchJson(url: string): Promise<Record<string, unknown>> {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (res.status !== 200) throw new Error(`GET ${url}: HTTP ${res.status}`);
  const body = (await res.json()) as unknown;
  if (!isObject(body)) throw new Error(`GET ${url}: not a JSON object`);
  return body;
}

/** The node:crypto verify arguments for a JOSE alg. */
function verifyToken(alg: string, key: KeyObject, input: Buffer, signature: Buffer): boolean {
  switch (alg) {
    case 'RS256':
      return verify('sha256', input, key, signature);
    case 'PS256':
      return verify(
        'sha256',
        input,
        { key, padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        signature,
      );
    case 'ES256':
      return verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, signature);
    case 'Ed25519':
      return verify(null, input, key, signature);
    default:
      return false;
  }
}

export async function startMockMcpServer(opts: MockMcpServerOptions): Promise<MockMcpServer> {
  const issuer = opts.issuer.replace(/\/+$/, '');
  const requests: McpRequestLog[] = [];
  let jwks: JsonWebKey[] | undefined;
  let base = '';

  async function loadJwks(): Promise<JsonWebKey[]> {
    const uri =
      opts.jwksUri ?? String((await fetchJson(`${issuer}/.well-known/openid-configuration`)).jwks_uri ?? '');
    if (!uri) throw new Error('the issuer metadata has no jwks_uri');
    const set = await fetchJson(uri);
    if (!Array.isArray(set.keys)) throw new Error('JWKS has no keys array');
    return set.keys as JsonWebKey[];
  }

  async function keyFor(kid: string): Promise<JsonWebKey> {
    jwks ??= await loadJwks();
    let jwk = jwks.find((k) => k.kid === kid);
    if (!jwk) {
      // Key rotation: refetch once for an unknown kid.
      jwks = await loadJwks();
      jwk = jwks.find((k) => k.kid === kid);
    }
    if (!jwk) throw new TokenError('kid');
    return jwk;
  }

  async function validate(token: string): Promise<Record<string, unknown>> {
    const parts = token.split('.');
    if (parts.length !== 3) throw new TokenError('format');
    let header: unknown;
    let claims: unknown;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      throw new TokenError('format');
    }
    if (!isObject(header) || !isObject(claims)) throw new TokenError('format');
    const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
    if (typ !== 'at+jwt' && typ !== 'application/at+jwt') throw new TokenError('typ');
    const alg = typeof header.alg === 'string' ? header.alg : '';
    if (!ALLOWED_ALGS.has(alg)) throw new TokenError('alg');
    if (typeof header.kid !== 'string') throw new TokenError('kid');
    const jwk = await keyFor(header.kid);
    if (typeof jwk.alg === 'string' && jwk.alg !== alg) throw new TokenError('alg');
    let key: KeyObject;
    try {
      key = createPublicKey({ key: jwk, format: 'jwk' });
    } catch {
      throw new TokenError('kid');
    }
    const input = Buffer.from(`${parts[0]}.${parts[1]}`);
    if (!verifyToken(alg, key, input, Buffer.from(parts[2], 'base64url'))) throw new TokenError('signature');

    if (claims.iss !== issuer) throw new TokenError('iss');
    const aud = claims.aud;
    const audiences = Array.isArray(aud) ? aud : [aud];
    if (!audiences.includes(`${base}/mcp`)) throw new TokenError('aud');
    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.exp !== 'number' || claims.exp <= now) throw new TokenError('exp');
    if (typeof claims.nbf === 'number' && claims.nbf > now + LEEWAY_SECS) throw new TokenError('nbf');
    if (typeof claims.iat === 'number' && claims.iat > now + LEEWAY_SECS) throw new TokenError('iat');
    return claims;
  }

  function challenge(error?: string): Record<string, string> {
    const params = [`resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`];
    if (error) params.unshift(`error="${error}"`);
    return { 'www-authenticate': `Bearer ${params.join(', ')}` };
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', base);
    if (
      req.method === 'GET' &&
      (url.pathname === '/.well-known/oauth-protected-resource' ||
        url.pathname === '/.well-known/oauth-protected-resource/mcp')
    ) {
      sendJson(res, 200, {
        resource: `${base}/mcp`,
        authorization_servers: [issuer],
        bearer_methods_supported: ['header'],
        ...(opts.scopesSupported ? { scopes_supported: opts.scopesSupported } : {}),
      });
      return;
    }
    if (url.pathname !== '/mcp' || (req.method !== 'GET' && req.method !== 'POST')) {
      sendJson(res, 404, { error: 'not_found' });
      return;
    }
    req.resume();
    const method = req.method;
    const auth = req.headers.authorization ?? '';
    const match = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/.exec(auth);
    if (!match) {
      requests.push({ method, status: 401, reason: 'missing' });
      sendJson(res, 401, { error: 'unauthorized' }, challenge());
      return;
    }
    try {
      const claims = await validate(match[1]);
      requests.push({ method, status: 200 });
      sendJson(res, 200, { ok: true, sub: claims.sub, client_id: claims.client_id, scope: claims.scope });
    } catch (e) {
      const reason = e instanceof TokenError ? e.message : 'error';
      requests.push({ method, status: 401, reason });
      sendJson(res, 401, { error: 'invalid_token' }, challenge('invalid_token'));
    }
  }

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { error: 'server_error' });
      else res.destroy();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port ?? 0, '127.0.0.1', () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
  return {
    base,
    resource: `${base}/mcp`,
    metadataUrl: `${base}/.well-known/oauth-protected-resource/mcp`,
    requests,
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

// Standalone: node tests/mcp/mock-mcp-server.ts <issuer> [port]
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const issuer = process.argv[2];
  if (!issuer) {
    console.error('usage: mock-mcp-server.ts <issuer> [port]');
    process.exit(2);
  }
  const server = await startMockMcpServer({ issuer, port: process.argv[3] ? Number(process.argv[3]) : undefined });
  console.log(`MCP endpoint (resource): ${server.resource}`);
  console.log(`Protected resource metadata: ${server.metadataUrl}`);
}
