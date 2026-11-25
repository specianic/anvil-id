// Local mock identity providers for the social-login e2e tests.
//
// Zero npm dependencies (node:http, node:crypto, node:url), so the file also runs directly with
// `node --experimental-strip-types` (see mock-idp-cli.ts). Two kinds:
//
//   apple   Apple-like OIDC provider: /auth/authorize (response_mode=form_post required when the
//           scope asks for name or email; the approval page POSTs code, state, id_token and, on the
//           FIRST authorization per subject only, a `user` JSON field to redirect_uri),
//           /auth/token (client_secret is an ES256 JWT signed with the key whose public JWK the
//           test passes in; aud must be this mock's base URL), /auth/keys (JWKS). ID tokens are
//           ES256 with `email_verified` and `is_private_email` as STRINGS ("true"/"false").
//           No discovery document, as with the real provider.
//   github  GitHub-like OAuth2 provider: /login/oauth/authorize (optional PKCE S256),
//           /login/oauth/access_token (JSON only with `Accept: application/json`, form-encoded
//           otherwise; errors are HTTP 200 with an `error` member), /user and /user/emails
//           (reject requests without User-Agent with 403; /user/emails lists one primary verified
//           address, one verified non-primary and one unverified address).
//
// The server binds 127.0.0.1 on a free port. AnvilID runs on `localhost` in the e2e suite, so the
// mock is a different site and Chromium applies real SameSite rules to the callback (a Lax binding
// cookie is the only thing that survives Apple's cross-site form POST). Signing keys are generated
// at start-up and never written anywhere. All provider hostnames are local; nothing here talks to a
// real provider.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomInt, sign, verify } from 'node:crypto';
import type { JsonWebKey as NodeJsonWebKey, KeyObject } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { URL } from 'node:url';

export type MockIdpKind = 'apple' | 'github';

/** A JSON Web Key (node:crypto's shape, which createPublicKey accepts). */
export type Jwk = NodeJsonWebKey;

export interface GithubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: 'public' | 'private' | null;
}

export interface MockUser {
  /** Apple: the `sub` claim. GitHub: ignored (the numeric `id` is the subject). */
  sub: string;
  email: string;
  /** Apple: emitted as the string "true"/"false". Default true. */
  emailVerified?: boolean;
  /** Apple: emitted as the string "true"/"false". Default false. */
  isPrivateEmail?: boolean;
  /** Apple: sent in the `user` JSON on the first authorization only. */
  firstName?: string;
  lastName?: string;
  /** GitHub: numeric user id (the stable subject). */
  id?: number;
  /** GitHub: login name. */
  login?: string;
  /** GitHub: display name. */
  name?: string | null;
  /** GitHub: overrides the default /user/emails list. */
  emails?: GithubEmail[];
}

/** One request seen by the mock, for assertions. Secrets are never recorded verbatim. */
export interface AuthLog {
  endpoint: string;
  method: string;
  /** Request parameters; client_secret / code_verifier / code values are replaced by '<present>'. */
  params: Record<string, string>;
  status: number;
  error?: string;
  /** Subject the request was about (authorize/token), if known. */
  sub?: string;
  /** Apple authorize: whether the `user` JSON was included in the form POST. */
  userSent?: boolean;
  /** GitHub authorize: whether a PKCE code_challenge was sent. */
  pkce?: boolean;
  /** Whether a User-Agent header was present. */
  userAgent?: boolean;
  /** The Accept header, if any. */
  accept?: string;
}

export interface MockIdpOptions {
  kind: MockIdpKind;
  clientId: string;
  /** The only accepted redirect_uri (AnvilID's upstream callback URL). */
  redirectUri: string;
  /** GitHub: the client secret expected at the token endpoint. Default: random (see handle). */
  clientSecret?: string;
  /** Apple: public JWK of the key AnvilID signs the client-secret JWT with. Without it every token
   * request fails with invalid_client (fail closed). */
  appleClientKeyJwk?: Jwk;
  /** Apple: expected `kid` header of the client secret (default: appleClientKeyJwk.kid if set). */
  appleKeyId?: string;
  /** Apple: expected `iss` (team id) of the client secret (default: any non-empty string). */
  appleTeamId?: string;
  /** Users the mock can sign in. Default: one generated user. */
  users?: MockUser[];
}

export interface MockIdp {
  /** Base URL, e.g. http://127.0.0.1:41234 (also the Apple-like issuer). */
  url: string;
  kind: MockIdpKind;
  clientId: string;
  /** GitHub: client secret expected at the token endpoint. Apple: empty. */
  clientSecret: string;
  users: MockUser[];
  /** Every request in arrival order. */
  authorizations: AuthLog[];
  /** The user the next authorization signs in (default: the first user; login_hint overrides). */
  selectUser(subOrEmail: string): void;
  /** Public JWKS the mock signs ID tokens with (Apple). */
  jwks: { keys: Jwk[] };
  stop(): Promise<void>;
}

/** AnvilID's upstream callback URL for a connection: `{issuer}/ui/login/upstream/{slug}/callback`. */
export function mockIdpRedirectUri(anvilUrl: string, tenant: string, slug: string): string {
  const base = anvilUrl.replace(/\/+$/, '');
  const issuer = tenant === 'default' ? base : `${base}/t/${encodeURIComponent(tenant)}`;
  return `${issuer}/ui/login/upstream/${encodeURIComponent(slug)}/callback`;
}

// ---------------------------------------------------------------------------
// JOSE helpers (ES256 only, IEEE P1363 signatures).

export function b64url(data: Buffer | string): string {
  return Buffer.from(data).toString('base64url');
}

/** Signs an ES256 JWT (header {alg, kid, typ?}) with a P-256 private key. */
export function signEs256Jwt(
  privateKey: KeyObject | string,
  kid: string,
  claims: Record<string, unknown>,
  typ?: string,
): string {
  const header: Record<string, string> = { alg: 'ES256', kid };
  if (typ) header.typ = typ;
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = sign('sha256', Buffer.from(input), {
    key: typeof privateKey === 'string' ? createPrivateKey(privateKey) : privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${input}.${b64url(signature)}`;
}

export interface DecodedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
}

/** Splits and decodes a compact JWS without verifying it. Throws on malformed input. */
export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('not a compact JWS');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as unknown;
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as unknown;
  if (!isObject(header) || !isObject(claims)) throw new Error('JWS header/payload is not an object');
  return { header, claims, signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') };
}

/** Verifies an ES256 JWS against a public JWK; returns the decoded token or throws. */
export function verifyEs256Jwt(token: string, jwk: Jwk): DecodedJwt {
  const decoded = decodeJwt(token);
  if (decoded.header.alg !== 'ES256') throw new Error('alg is not ES256');
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const ok = verify('sha256', Buffer.from(decoded.signingInput), { key, dsaEncoding: 'ieee-p1363' }, decoded.signature);
  if (!ok) throw new Error('bad signature');
  return decoded;
}

/** OIDC left-half hash (at_hash / c_hash) for SHA-256 based algorithms. */
function halfHash(value: string): string {
  const digest = createHash('sha256').update(value, 'ascii').digest();
  return b64url(digest.subarray(0, digest.length / 2));
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// HTTP plumbing

const MAX_BODY = 64 * 1024;

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function html(res: ServerResponse, status: number, title: string, body: string): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head>
<body>
<h1>${escapeHtml(title)}</h1>
${body}
</body>
</html>`);
}

function json(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...extra,
  });
  res.end(JSON.stringify(body));
}

const SECRET_PARAMS = new Set(['client_secret', 'code_verifier', 'code', 'id_token', 'user']);

function redact(params: URLSearchParams): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of params) out[k] = SECRET_PARAMS.has(k) ? '<present>' : v;
  return out;
}

function token(prefix = ''): string {
  return `${prefix}${randomBytes(24).toString('base64url')}`;
}

interface PendingCode {
  clientId: string;
  redirectUri: string;
  nonce?: string;
  user: MockUser;
  scope: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  expiresAt: number;
  used: boolean;
}

const CODE_TTL_MS = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// The mock

function defaultUsers(kind: MockIdpKind): MockUser[] {
  const hex = randomBytes(4).toString('hex');
  if (kind === 'apple') {
    return [
      {
        sub: `000${randomInt(100000, 999999)}.${randomBytes(16).toString('hex')}.${randomInt(1000, 9999)}`,
        email: `apple-${hex}@privaterelay.example.test`,
        emailVerified: true,
        isPrivateEmail: true,
        firstName: 'Ada',
        lastName: 'Lovelace',
      },
    ];
  }
  const id = randomInt(1_000_000, 99_999_999);
  return [{ sub: String(id), id, login: `octo-${hex}`, name: 'Octo Cat', email: `octo-${hex}@example.test` }];
}

function githubEmails(user: MockUser): GithubEmail[] {
  if (user.emails) return user.emails;
  const local = user.email.split('@')[0] ?? 'user';
  return [
    { email: `${local}-secondary@example.test`, primary: false, verified: true, visibility: null },
    { email: user.email, primary: true, verified: true, visibility: 'private' },
    { email: `${local}-unverified@example.test`, primary: false, verified: false, visibility: null },
  ];
}

export async function startMockIdp(opts: MockIdpOptions): Promise<MockIdp> {
  const users = opts.users && opts.users.length > 0 ? opts.users : defaultUsers(opts.kind);
  const clientSecret = opts.kind === 'github' ? (opts.clientSecret ?? token('mock-secret-')) : '';
  const authorizations: AuthLog[] = [];
  const codes = new Map<string, PendingCode>();
  const accessTokens = new Map<string, MockUser>();
  const appleUserSent = new Set<string>();
  let selected: MockUser = users[0];

  // Signing key for ID tokens (Apple-like). Generated per start, held in memory only.
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signingKid = `mock-${randomBytes(6).toString('hex')}`;
  const publicJwk = { ...publicKey.export({ format: 'jwk' }), kid: signingKid, use: 'sig', alg: 'ES256' } as Jwk;
  const jwks = { keys: [publicJwk] };

  let baseUrl = '';

  const findUser = (hint: string | null): MockUser => {
    if (hint) {
      const found = users.find((u) => u.sub === hint || u.email === hint || u.login === hint);
      if (found) return found;
    }
    return selected;
  };

  const log = (entry: AuthLog): AuthLog => {
    authorizations.push(entry);
    return entry;
  };

  const issueIdToken = (user: MockUser, nonce: string | undefined, extra: Record<string, unknown>): string => {
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      iss: baseUrl,
      aud: opts.clientId,
      exp: now + 600,
      iat: now,
      sub: user.sub,
      auth_time: now,
      nonce_supported: true,
      email: user.email,
      // Apple quirk: booleans as strings.
      email_verified: String(user.emailVerified ?? true),
      is_private_email: String(user.isPrivateEmail ?? false),
      ...extra,
    };
    if (nonce !== undefined) claims.nonce = nonce;
    return signEs256Jwt(privateKey, signingKid, claims);
  };

  // ---- Apple-like -------------------------------------------------------------------------------

  const appleAuthorize = (req: IncomingMessage, res: ServerResponse, params: URLSearchParams): void => {
    const entry = log({ endpoint: '/auth/authorize', method: req.method ?? 'GET', params: redact(params), status: 200 });
    const fail = (error: string): void => {
      entry.status = 400;
      entry.error = error;
      html(res, 400, 'Authorization error', `<p id="mock-error">${escapeHtml(error)}</p>`);
    };
    if (params.get('client_id') !== opts.clientId) return fail('invalid_client_id');
    if (params.get('redirect_uri') !== opts.redirectUri) return fail('invalid_redirect_uri');
    const responseType = (params.get('response_type') ?? '').split(' ').filter(Boolean);
    if (!responseType.includes('code')) return fail('unsupported_response_type');
    const scope = (params.get('scope') ?? '').split(' ').filter(Boolean);
    // Apple requires form_post whenever name or email is requested.
    const wantsProfile = scope.includes('name') || scope.includes('email');
    if (wantsProfile && params.get('response_mode') !== 'form_post') return fail('invalid_request: response_mode must be form_post');
    const state = params.get('state') ?? '';
    const nonce = params.get('nonce') ?? undefined;
    const user = findUser(params.get('login_hint'));
    entry.sub = user.sub;

    const code = token('c.');
    codes.set(code, {
      clientId: opts.clientId,
      redirectUri: opts.redirectUri,
      nonce,
      user,
      scope: scope.join(' '),
      expiresAt: Date.now() + CODE_TTL_MS,
      used: false,
    });
    const fields: Record<string, string> = { code, state };
    // The authorization response carries an ID token with c_hash (response_type "code id_token"
    // explicitly, and Apple's form_post response in practice).
    fields.id_token = issueIdToken(user, nonce, { c_hash: halfHash(code) });
    // The user JSON is sent on the first authorization per subject only, and only if asked for.
    if (wantsProfile && !appleUserSent.has(user.sub)) {
      appleUserSent.add(user.sub);
      const userJson: Record<string, unknown> = {};
      if (scope.includes('name')) userJson.name = { firstName: user.firstName ?? '', lastName: user.lastName ?? '' };
      if (scope.includes('email')) userJson.email = user.email;
      fields.user = JSON.stringify(userJson);
      entry.userSent = true;
    } else {
      entry.userSent = false;
    }
    const mode = params.get('response_mode') ?? 'query';
    if (mode === 'form_post') {
      const inputs = Object.entries(fields)
        .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
        .join('\n');
      html(
        res,
        200,
        'Mock Apple sign-in',
        `<p>Sign in as <span id="mock-user">${escapeHtml(user.email)}</span>.</p>
<form id="mock-approve" method="post" action="${escapeHtml(opts.redirectUri)}">
${inputs}
<button type="submit" id="mock-continue">Continue</button>
</form>`,
      );
      return;
    }
    // Query / fragment response: code and state only (no profile scopes were requested).
    const target = new URL(opts.redirectUri);
    target.searchParams.set('code', code);
    if (state) target.searchParams.set('state', state);
    html(
      res,
      200,
      'Mock Apple sign-in',
      `<p>Sign in as <span id="mock-user">${escapeHtml(user.email)}</span>.</p>
<p><a id="mock-continue" href="${escapeHtml(target.href)}">Continue</a></p>`,
    );
  };

  const verifyAppleClientSecret = (secret: string): string | undefined => {
    // Returns an error description, or undefined when valid.
    const jwk = opts.appleClientKeyJwk;
    if (!jwk) return 'no client key configured';
    let decoded: DecodedJwt;
    try {
      decoded = verifyEs256Jwt(secret, jwk);
    } catch (err) {
      return `client_secret: ${(err as Error).message}`;
    }
    const expectedKid = opts.appleKeyId ?? (jwk as { kid?: string }).kid;
    if (typeof decoded.header.kid !== 'string' || decoded.header.kid === '') return 'client_secret: missing kid';
    if (expectedKid && decoded.header.kid !== expectedKid) return 'client_secret: wrong kid';
    const c = decoded.claims;
    if (typeof c.iss !== 'string' || c.iss === '') return 'client_secret: missing iss';
    if (opts.appleTeamId && c.iss !== opts.appleTeamId) return 'client_secret: wrong iss';
    if (c.sub !== opts.clientId) return 'client_secret: wrong sub';
    if (c.aud !== baseUrl) return 'client_secret: wrong aud';
    const now = Math.floor(Date.now() / 1000);
    if (typeof c.exp !== 'number' || c.exp <= now) return 'client_secret: expired';
    if (typeof c.iat !== 'number' || c.iat > now + 60) return 'client_secret: iat in the future';
    return undefined;
  };

  const appleToken = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const params = new URLSearchParams(await readBody(req));
    const entry = log({ endpoint: '/auth/token', method: 'POST', params: redact(params), status: 200 });
    const fail = (status: number, error: string, detail: string): void => {
      entry.status = status;
      entry.error = `${error}: ${detail}`;
      json(res, status, { error });
    };
    if (req.method !== 'POST') return fail(405, 'invalid_request', 'POST only');
    if (params.get('client_id') !== opts.clientId) return fail(400, 'invalid_client', 'unknown client_id');
    const problem = verifyAppleClientSecret(params.get('client_secret') ?? '');
    if (problem) return fail(400, 'invalid_client', problem);
    if (params.get('grant_type') !== 'authorization_code') return fail(400, 'unsupported_grant_type', 'grant_type');
    const code = params.get('code') ?? '';
    const pending = codes.get(code);
    if (!pending || pending.used || pending.expiresAt < Date.now()) return fail(400, 'invalid_grant', 'code unknown, used or expired');
    pending.used = true;
    if (pending.clientId !== params.get('client_id')) return fail(400, 'invalid_grant', 'client mismatch');
    if (pending.redirectUri !== params.get('redirect_uri')) return fail(400, 'invalid_grant', 'redirect_uri mismatch');
    entry.sub = pending.user.sub;
    const accessToken = token('a.');
    accessTokens.set(accessToken, pending.user);
    json(res, 200, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: token('r.'),
      id_token: issueIdToken(pending.user, pending.nonce, { at_hash: halfHash(accessToken) }),
    });
  };

  // ---- GitHub-like ------------------------------------------------------------------------------

  const githubAuthorize = (req: IncomingMessage, res: ServerResponse, params: URLSearchParams): void => {
    const entry = log({
      endpoint: '/login/oauth/authorize',
      method: req.method ?? 'GET',
      params: redact(params),
      status: 200,
      pkce: params.has('code_challenge'),
    });
    const fail = (error: string): void => {
      entry.status = 400;
      entry.error = error;
      html(res, 400, 'Authorization error', `<p id="mock-error">${escapeHtml(error)}</p>`);
    };
    if (params.get('client_id') !== opts.clientId) return fail('invalid_client_id');
    const redirectUri = params.get('redirect_uri') ?? opts.redirectUri;
    if (redirectUri !== opts.redirectUri) return fail('redirect_uri_mismatch');
    const challenge = params.get('code_challenge') ?? undefined;
    const method = params.get('code_challenge_method') ?? (challenge ? 'plain' : undefined);
    if (challenge && method !== 'S256') return fail('invalid_request: only S256 is supported');
    const user = findUser(params.get('login'));
    entry.sub = user.sub;
    const code = randomBytes(10).toString('hex');
    codes.set(code, {
      clientId: opts.clientId,
      redirectUri,
      user,
      scope: params.get('scope') ?? '',
      codeChallenge: challenge,
      codeChallengeMethod: method,
      expiresAt: Date.now() + CODE_TTL_MS,
      used: false,
    });
    const target = new URL(redirectUri);
    target.searchParams.set('code', code);
    const state = params.get('state');
    if (state !== null) target.searchParams.set('state', state);
    html(
      res,
      200,
      'Mock GitHub authorization',
      `<p>Authorize as <span id="mock-user">${escapeHtml(user.login ?? user.email)}</span>.</p>
<p><a id="mock-continue" href="${escapeHtml(target.href)}">Continue</a></p>`,
    );
  };

  const githubToken = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const params = new URLSearchParams(await readBody(req));
    const accept = req.headers.accept ?? '';
    const entry = log({
      endpoint: '/login/oauth/access_token',
      method: req.method ?? 'POST',
      params: redact(params),
      status: 200,
      accept,
      userAgent: req.headers['user-agent'] !== undefined,
    });
    const wantsJson = accept.split(',').some((t) => t.trim().split(';')[0] === 'application/json');
    const reply = (body: Record<string, string>): void => {
      if (wantsJson) {
        json(res, 200, body);
      } else {
        // GitHub's default response format is form-encoded.
        res.writeHead(200, { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8', 'cache-control': 'no-store' });
        res.end(new URLSearchParams(body).toString());
      }
    };
    // GitHub quirk: token errors are HTTP 200 with an `error` member.
    const fail = (error: string): void => {
      entry.error = error;
      reply({ error, error_description: error.replaceAll('_', ' ') });
    };
    if (req.method !== 'POST') {
      entry.status = 404;
      json(res, 404, { message: 'Not Found' });
      return;
    }
    // Client credentials in the body or via HTTP Basic.
    let clientId = params.get('client_id');
    let secret = params.get('client_secret');
    const auth = req.headers.authorization;
    if (auth?.startsWith('Basic ')) {
      const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      if (idx > 0) {
        clientId = decodeURIComponent(decoded.slice(0, idx));
        secret = decodeURIComponent(decoded.slice(idx + 1));
      }
    }
    if (clientId !== opts.clientId || secret !== clientSecret) return fail('incorrect_client_credentials');
    const code = params.get('code') ?? '';
    const pending = codes.get(code);
    if (!pending || pending.used || pending.expiresAt < Date.now()) return fail('bad_verification_code');
    pending.used = true;
    const redirectUri = params.get('redirect_uri');
    if (redirectUri !== null && redirectUri !== pending.redirectUri) return fail('redirect_uri_mismatch');
    const verifier = params.get('code_verifier');
    if (pending.codeChallenge) {
      if (!verifier) return fail('bad_verification_code');
      const computed = createHash('sha256').update(verifier, 'ascii').digest('base64url');
      if (computed !== pending.codeChallenge) return fail('bad_verification_code');
    } else if (verifier) {
      return fail('bad_verification_code');
    }
    entry.sub = pending.user.sub;
    const accessToken = token('gho_');
    accessTokens.set(accessToken, pending.user);
    reply({ access_token: accessToken, token_type: 'bearer', scope: pending.scope });
  };

  const githubApi = (req: IncomingMessage, res: ServerResponse, path: string): void => {
    const entry = log({
      endpoint: path,
      method: req.method ?? 'GET',
      params: {},
      status: 200,
      userAgent: req.headers['user-agent'] !== undefined,
      accept: req.headers.accept,
    });
    if (req.headers['user-agent'] === undefined) {
      // GitHub rejects API requests without a User-Agent.
      entry.status = 403;
      entry.error = 'missing User-Agent';
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Request forbidden by administrative rules. Please make sure your request has a User-Agent header.\n');
      return;
    }
    const auth = req.headers.authorization ?? '';
    const match = /^(?:Bearer|token) (\S+)$/i.exec(auth);
    const user = match ? accessTokens.get(match[1]) : undefined;
    if (!user) {
      entry.status = 401;
      entry.error = 'bad credentials';
      json(res, 401, { message: 'Bad credentials', status: '401' });
      return;
    }
    entry.sub = user.sub;
    if (path === '/user') {
      json(res, 200, {
        id: user.id ?? Number(user.sub),
        login: user.login ?? user.email.split('@')[0],
        name: user.name ?? null,
        // A private primary address is not shown on /user.
        email: null,
        type: 'User',
      });
      return;
    }
    json(res, 200, githubEmails(user));
  };

  // ---- Router -----------------------------------------------------------------------------------

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', baseUrl);
    const path = url.pathname;
    if (opts.kind === 'apple') {
      if (path === '/auth/authorize') {
        if (req.method === 'POST') {
          const body = new URLSearchParams(await readBody(req));
          return appleAuthorize(req, res, body);
        }
        return appleAuthorize(req, res, url.searchParams);
      }
      if (path === '/auth/token') return appleToken(req, res);
      if (path === '/auth/keys') {
        log({ endpoint: path, method: req.method ?? 'GET', params: {}, status: 200 });
        return json(res, 200, jwks, { 'cache-control': 'max-age=60' });
      }
    } else {
      if (path === '/login/oauth/authorize') return githubAuthorize(req, res, url.searchParams);
      if (path === '/login/oauth/access_token') return githubToken(req, res);
      if (path === '/user' || path === '/user/emails') return githubApi(req, res, path);
    }
    log({ endpoint: path, method: req.method ?? 'GET', params: {}, status: 404 });
    json(res, 404, { error: 'not_found' });
  };

  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (!res.headersSent) json(res, 500, { error: 'server_error', detail: (err as Error).message });
      else res.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  baseUrl = `http://127.0.0.1:${port}`;

  return {
    url: baseUrl,
    kind: opts.kind,
    clientId: opts.clientId,
    clientSecret,
    users,
    authorizations,
    jwks,
    selectUser(subOrEmail: string) {
      const found = users.find((u) => u.sub === subOrEmail || u.email === subOrEmail || u.login === subOrEmail);
      if (!found) throw new Error(`mock IdP has no user ${subOrEmail}`);
      selected = found;
    },
    stop() {
      return new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      });
    },
  };
}
