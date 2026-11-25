// Helpers for upstream (social / generic OIDC) login e2e tests.
//
// AnvilID itself serves as the generic OIDC upstream: a second tenant of the instance under test,
// provisioned through the admin API, with one user and one confidential client whose redirect URI
// is the downstream tenant's upstream callback. Connections are created through
// POST /api/admin/v1/tenants/{t}/connections. Nothing here holds a credential; everything is created
// at runtime.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { anvilUrl, createClient, createUser, randomEmail, randomPassword } from './anvil';
import { signEs256Jwt, type Jwk } from './mock-idp';

async function adminRequest<T>(
  token: string,
  method: 'POST' | 'PATCH',
  path: string,
  body: unknown,
  expected: number,
): Promise<T> {
  const res = await fetch(`${anvilUrl()}/api/admin/v1${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (res.status !== expected) {
    throw new Error(`${method} ${path} failed: HTTP ${res.status} ${await res.text()}`);
  }
  return (await res.json()) as T;
}

/** Issuer URL of a tenant of the AnvilID under test. */
export function tenantIssuer(tenant: string): string {
  return tenant === 'default' ? anvilUrl() : `${anvilUrl()}/t/${encodeURIComponent(tenant)}`;
}

/** A unique tenant slug (2-63 chars of a-z, 0-9, '-'). */
export function randomSlug(prefix = 'up'): string {
  return `${prefix}-${randomBytes(4).toString('hex')}`;
}

export interface UpstreamTenant {
  slug: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  user: { email: string; password: string };
}

/**
 * Creates tenant `slug` to act as a generic OIDC upstream: one verified user with a password and one
 * confidential client (client_secret_basic, consent skip_first_party) whose only redirect URI is
 * `downstreamRedirectUri` (the downstream tenant's `{issuer}/ui/login/upstream/{slug}/callback`).
 */
export async function createUpstreamTenant(
  token: string,
  slug: string,
  downstreamRedirectUri: string,
): Promise<UpstreamTenant> {
  await adminRequest(token, 'POST', '/tenants', { slug, display_name: `Upstream ${slug}` }, 201);
  const user = { email: randomEmail('upstream'), password: randomPassword() };
  await createUser(token, { email: user.email, password: user.password, email_verified: true }, slug);
  const client = await createClient(
    token,
    {
      name: `downstream of ${slug}`,
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [downstreamRedirectUri],
      grant_types: ['authorization_code'],
      scopes: ['openid', 'profile', 'email'],
    },
    slug,
    'skip_first_party',
  );
  if (!client.client_secret) throw new Error('upstream client was created without a secret');
  return {
    slug,
    issuer: tenantIssuer(slug),
    clientId: client.client_id,
    clientSecret: client.client_secret,
    user,
  };
}

export interface CreatedConnection {
  id?: string;
  slug?: string;
  [extra: string]: unknown;
}

/** Creates an upstream connection in `tenant` (POST /tenants/{t}/connections). */
export function createConnection(
  token: string,
  tenant: string,
  body: Record<string, unknown>,
): Promise<CreatedConnection> {
  return adminRequest<CreatedConnection>(
    token,
    'POST',
    `/tenants/${encodeURIComponent(tenant)}/connections`,
    body,
    201,
  );
}

export interface AppleKeyPair {
  /** Key id (the Apple "Key ID"). */
  keyId: string;
  /** P-256 private key, PKCS#8 PEM: what an operator pastes into the Apple connection. */
  privateKeyPem: string;
  /** Public JWK (with kid, alg ES256) for startMockIdp({ appleClientKeyJwk }). */
  publicJwk: Jwk;
}

/** A fresh P-256 key pair for the Apple-like client secret. Generated per call; never stored. */
export function appleKeyPair(keyId = `K${randomBytes(4).toString('hex').toUpperCase()}`): AppleKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    keyId,
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicJwk: { ...publicKey.export({ format: 'jwk' }), kid: keyId, alg: 'ES256', use: 'sig' } as Jwk,
  };
}

/**
 * Signs an Apple-style client secret (ES256 JWT: iss = team id, sub = services id, aud = provider
 * issuer). Used by the mock self-test; AnvilID signs its own in the real flow.
 */
export function appleClientSecret(
  pair: AppleKeyPair,
  claims: { teamId: string; clientId: string; audience: string; lifetimeSeconds?: number },
): string {
  const now = Math.floor(Date.now() / 1000);
  return signEs256Jwt(pair.privateKeyPem, pair.keyId, {
    iss: claims.teamId,
    sub: claims.clientId,
    aud: claims.audience,
    iat: now,
    exp: now + (claims.lifetimeSeconds ?? 300),
  });
}
