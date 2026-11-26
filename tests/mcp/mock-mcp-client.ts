// A mock MCP client: the authorization steps an MCP client performs against AnvilID.
//
// Zero npm dependencies (node:http, node:crypto), so it also runs on its own with
// `node tests/mcp/mock-mcp-client.ts <mcp-endpoint-url> [scope]` (Node.js 22.18+ / 24 strip the
// types); the e2e spec (tests/e2e/specs/mcp.spec.ts) drives the same functions with a browser.
//
// Steps, following the MCP authorization specification (revision 2026-07-28, "Authorization
// Server Discovery" and "Client Registration"):
//
//   1. Call the MCP endpoint without a token; read `resource_metadata` from the 401's
//      `WWW-Authenticate` (RFC 9728 §5.1), falling back to the RFC 9728 well-known URIs.
//   2. Fetch the protected resource metadata; its `resource` must equal the MCP endpoint and
//      `authorization_servers[0]` is the issuer.
//   3. Discover the authorization server metadata in the MCP order (RFC 8414 path insertion,
//      OIDC path insertion, OIDC path appending); the document's `issuer` must equal the issuer
//      exactly, and `code_challenge_methods_supported` must contain S256.
//   4. Identify with a Client ID Metadata Document: the client serves its document at
//      `http://127.0.0.1:<port>/client.json` (client_id = that URL, a loopback redirect URI,
//      `token_endpoint_auth_method: none`). Plain http on loopback is accepted by AnvilID only in
//      development mode; real clients publish their document over https.
//   5. Authorization code + PKCE (S256) with `resource=<MCP endpoint>` at /authorize and /token
//      (RFC 8707); the callback's `iss` must equal the issuer (RFC 9207).
//   6. Call the MCP endpoint with the access token.
//
// Nothing here holds a credential; the PKCE verifier and tokens live in memory only.

import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { pathToFileURL } from 'node:url';

export type Json = Record<string, unknown>;

export interface ProtectedResource {
  /** Where the RFC 9728 document was read. */
  metadataUrl: string;
  resource: string;
  authorizationServers: string[];
  scopesSupported?: string[];
}

export interface AuthorizationServer {
  issuer: string;
  /** The well-known URL that answered. */
  metadataUrl: string;
  metadata: Json;
  authorizationEndpoint: string;
  tokenEndpoint: string;
}

export interface Callback {
  code?: string;
  state?: string;
  iss?: string;
  error?: string;
  errorDescription?: string;
}

export interface CimdClient {
  /** The document URL, used as `client_id`. */
  clientId: string;
  redirectUri: string;
  /** The document served at `clientId`. */
  document: Json;
  /** Authorization responses received at the redirect URI, oldest first. */
  callbacks: Callback[];
  /** How many times the document was fetched. */
  documentFetches(): number;
  /** Resolves with the first callback after the `seen`-th one (default: the next new one). */
  waitForCallback(timeoutMs?: number, seen?: number): Promise<Callback>;
  stop(): Promise<void>;
}

function isObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function getJson(url: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, { headers: { accept: 'application/json' }, redirect: 'manual' });
  const text = await res.text();
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  return { status: res.status, body };
}

/** A PKCE verifier and its S256 challenge (RFC 7636 §4.1, §4.2). */
export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier, 'ascii').digest('base64url') };
}

/** The `resource_metadata` parameter of a `WWW-Authenticate: Bearer ...` header (RFC 9728 §5.1). */
export function resourceMetadataHint(header: string | null): string | undefined {
  if (!header || !/^\s*Bearer\b/i.test(header)) return undefined;
  return /(?:^|[\s,])resource_metadata="([^"]*)"/i.exec(header)?.[1];
}

/** The RFC 9728 well-known URIs for `resource`, in the MCP fallback order (path, then root). */
export function protectedResourceMetadataUrls(resource: string): string[] {
  const url = new URL(resource);
  const path = url.pathname === '/' ? '' : url.pathname.replace(/\/+$/, '');
  const urls = [`${url.origin}/.well-known/oauth-protected-resource${path}`];
  if (path) urls.push(`${url.origin}/.well-known/oauth-protected-resource`);
  return urls;
}

/** Steps 1 and 2: the protected resource metadata of the MCP endpoint `resource`. */
export async function discoverProtectedResource(resource: string): Promise<ProtectedResource> {
  const probe = await fetch(resource, { headers: { accept: 'application/json' } });
  await probe.body?.cancel();
  if (probe.status !== 401) throw new Error(`expected 401 from ${resource}, got ${probe.status}`);
  const hint = resourceMetadataHint(probe.headers.get('www-authenticate'));
  for (const metadataUrl of hint ? [hint] : protectedResourceMetadataUrls(resource)) {
    const { status, body } = await getJson(metadataUrl);
    if (status !== 200 || !isObject(body)) continue;
    // RFC 9728 §3.3 / §7.3: the document must be about the resource being accessed.
    if (body.resource !== resource) throw new Error(`metadata at ${metadataUrl} names resource ${String(body.resource)}`);
    const servers = Array.isArray(body.authorization_servers)
      ? body.authorization_servers.filter((s): s is string => typeof s === 'string')
      : [];
    if (servers.length === 0) throw new Error(`metadata at ${metadataUrl} lists no authorization_servers`);
    const scopes = Array.isArray(body.scopes_supported)
      ? body.scopes_supported.filter((s): s is string => typeof s === 'string')
      : undefined;
    return { metadataUrl, resource, authorizationServers: servers, scopesSupported: scopes };
  }
  throw new Error(`no protected resource metadata for ${resource}`);
}

/** The authorization server metadata URLs for `issuer`, in the order MCP clients try them. */
export function authorizationServerMetadataUrls(issuer: string): string[] {
  const url = new URL(issuer);
  const path = url.pathname.replace(/\/+$/, '');
  if (!path) {
    return [
      `${url.origin}/.well-known/oauth-authorization-server`,
      `${url.origin}/.well-known/openid-configuration`,
    ];
  }
  return [
    `${url.origin}/.well-known/oauth-authorization-server${path}`,
    `${url.origin}/.well-known/openid-configuration${path}`,
    `${url.origin}${path}/.well-known/openid-configuration`,
  ];
}

/** Step 3: the first metadata document (in MCP order) whose `issuer` equals `issuer` exactly. */
export async function discoverAuthorizationServer(issuer: string): Promise<AuthorizationServer> {
  for (const metadataUrl of authorizationServerMetadataUrls(issuer)) {
    const { status, body } = await getJson(metadataUrl);
    if (status !== 200 || !isObject(body)) continue;
    if (body.issuer !== issuer) throw new Error(`${metadataUrl} names issuer ${String(body.issuer)}, not ${issuer}`);
    const methods = Array.isArray(body.code_challenge_methods_supported) ? body.code_challenge_methods_supported : [];
    if (!methods.includes('S256')) throw new Error(`${metadataUrl}: S256 is not in code_challenge_methods_supported`);
    if (typeof body.authorization_endpoint !== 'string' || typeof body.token_endpoint !== 'string') {
      throw new Error(`${metadataUrl}: authorization_endpoint or token_endpoint missing`);
    }
    return {
      issuer,
      metadataUrl,
      metadata: body,
      authorizationEndpoint: body.authorization_endpoint,
      tokenEndpoint: body.token_endpoint,
    };
  }
  throw new Error(`no authorization server metadata for ${issuer}`);
}

function callbackPage(res: ServerResponse): void {
  const html = '<!doctype html><title>MCP client</title><p id="mcp-callback">Authorization response received.</p>';
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(html);
}

/**
 * Step 4: serves this client's metadata document at `http://127.0.0.1:<port>/client.json` and
 * receives authorization responses at `/callback`.
 */
export async function startCimdClient(opts: { clientName: string; scope: string }): Promise<CimdClient> {
  const callbacks: Callback[] = [];
  const waiters: Array<() => void> = [];
  let fetches = 0;
  let document: Json = {};

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    req.resume();
    if (req.method === 'GET' && url.pathname === '/client.json') {
      fetches += 1;
      const text = JSON.stringify(document);
      res.writeHead(200, {
        'content-type': 'application/json',
        'cache-control': 'max-age=300',
        'content-length': Buffer.byteLength(text),
      });
      res.end(text);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/callback') {
      const q = url.searchParams;
      callbacks.push({
        code: q.get('code') ?? undefined,
        state: q.get('state') ?? undefined,
        iss: q.get('iss') ?? undefined,
        error: q.get('error') ?? undefined,
        errorDescription: q.get('error_description') ?? undefined,
      });
      for (const wake of waiters.splice(0)) wake();
      callbackPage(res);
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  const clientId = `http://127.0.0.1:${port}/client.json`;
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  document = {
    client_id: clientId,
    client_name: opts.clientName,
    redirect_uris: [redirectUri],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    application_type: 'native',
    scope: opts.scope,
  };

  return {
    clientId,
    redirectUri,
    document,
    callbacks,
    documentFetches: () => fetches,
    waitForCallback(timeoutMs = 15_000, seen = callbacks.length) {
      return new Promise<Callback>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('no authorization response at the redirect URI')), timeoutMs);
        const tryResolve = (): void => {
          if (callbacks.length > seen) {
            clearTimeout(timer);
            resolve(callbacks[seen]);
          } else {
            waiters.push(tryResolve);
          }
        };
        tryResolve();
      });
    },
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export interface AuthorizationRequest {
  clientId: string;
  redirectUri: string;
  scope: string;
  resource: string;
  state: string;
  challenge: string;
}

/** Step 5a: the authorization URL (code, S256, `resource`). */
export function authorizationUrl(as: AuthorizationServer, r: AuthorizationRequest): string {
  const url = new URL(as.authorizationEndpoint);
  const params = {
    response_type: 'code',
    client_id: r.clientId,
    redirect_uri: r.redirectUri,
    scope: r.scope,
    state: r.state,
    code_challenge: r.challenge,
    code_challenge_method: 'S256',
    resource: r.resource,
  };
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url.toString();
}

/** Checks an authorization response: no error, the expected `state`, `iss` equal to the issuer. */
export function checkCallback(cb: Callback, as: AuthorizationServer, state: string): string {
  if (cb.error) throw new Error(`authorization error: ${cb.error} ${cb.errorDescription ?? ''}`.trim());
  if (cb.state !== state) throw new Error('state mismatch');
  if (cb.iss !== undefined && cb.iss !== as.issuer) throw new Error(`iss ${cb.iss} is not ${as.issuer}`);
  if (as.metadata.authorization_response_iss_parameter_supported === true && cb.iss === undefined) {
    throw new Error('iss missing although the server advertises it');
  }
  if (!cb.code) throw new Error('no code in the authorization response');
  return cb.code;
}

export interface TokenResponse {
  status: number;
  body: Json;
}

/** Step 5b: exchanges `code` (public client, PKCE verifier, the same `resource`). */
export async function exchangeCode(
  as: AuthorizationServer,
  r: { code: string; verifier: string; clientId: string; redirectUri: string; resource: string },
): Promise<TokenResponse> {
  const res = await fetch(as.tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: r.code,
      redirect_uri: r.redirectUri,
      code_verifier: r.verifier,
      client_id: r.clientId,
      resource: r.resource,
    }).toString(),
  });
  const body = (await res.json()) as unknown;
  return { status: res.status, body: isObject(body) ? body : {} };
}

/** Step 6: calls the MCP endpoint with a bearer token. */
export async function callMcp(
  resource: string,
  token: string,
): Promise<{ status: number; body: unknown; wwwAuthenticate: string | null }> {
  const res = await fetch(resource, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, body, wwwAuthenticate: res.headers.get('www-authenticate') };
}

/** The decoded (unverified) claims of a compact JWT, for assertions only. */
export function jwtClaims(jwt: string): Json {
  const part = jwt.split('.')[1];
  if (!part) throw new Error('not a compact JWT');
  const claims = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as unknown;
  if (!isObject(claims)) throw new Error('JWT payload is not an object');
  return claims;
}

// Standalone: node tests/mcp/mock-mcp-client.ts <mcp-endpoint-url> [scope]
// Prints the authorization URL to open in a browser and completes the flow when the browser
// returns to the loopback redirect URI.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const resource = process.argv[2];
  const scope = process.argv[3] ?? 'openid';
  if (!resource) {
    console.error('usage: mock-mcp-client.ts <mcp-endpoint-url> [scope]');
    process.exit(2);
  }
  const prm = await discoverProtectedResource(resource);
  const as = await discoverAuthorizationServer(prm.authorizationServers[0]);
  if (as.metadata.client_id_metadata_document_supported !== true) {
    console.error(`${as.issuer} does not advertise client_id_metadata_document_supported`);
    process.exit(1);
  }
  const client = await startCimdClient({ clientName: 'Mock MCP client', scope });
  const { verifier, challenge } = pkcePair();
  const state = randomBytes(16).toString('base64url');
  console.log(`Open in a browser:\n${authorizationUrl(as, { clientId: client.clientId, redirectUri: client.redirectUri, scope, resource, state, challenge })}`);
  try {
    const code = checkCallback(await client.waitForCallback(300_000), as, state);
    const tokens = await exchangeCode(as, { code, verifier, clientId: client.clientId, redirectUri: client.redirectUri, resource });
    if (tokens.status !== 200 || typeof tokens.body.access_token !== 'string') {
      throw new Error(`token request failed: HTTP ${tokens.status} ${String(tokens.body.error ?? '')}`);
    }
    console.log(`access token aud: ${JSON.stringify(jwtClaims(tokens.body.access_token).aud)}`);
    const result = await callMcp(resource, tokens.body.access_token);
    console.log(`MCP endpoint answered HTTP ${result.status}: ${JSON.stringify(result.body)}`);
  } finally {
    await client.stop();
  }
}
