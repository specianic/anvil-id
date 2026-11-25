// Helpers for upstream (social / generic OIDC) login e2e tests.
//
// AnvilID itself serves as the generic OIDC upstream: a second tenant of the instance under test,
// provisioned through the admin API, with one user and one confidential client whose redirect URI
// is the downstream tenant's upstream callback. Connections are created through
// POST /api/admin/v1/tenants/{t}/connections. Nothing here holds a credential; everything is created
// at runtime.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, type Page } from '@playwright/test';
import { anvilUrl, createClient, createUser, login, randomEmail, randomPassword } from './anvil';
import { mockIdpRedirectUri, signEs256Jwt, startMockIdp, type Jwk, type MockIdp, type MockUser } from './mock-idp';

async function adminRequest<T>(
  token: string,
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  body: unknown,
  expected: number,
): Promise<T> {
  const res = await fetch(`${anvilUrl()}/api/admin/v1${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/json',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status !== expected) {
    throw new Error(`${method} ${path} failed: HTTP ${res.status} ${await res.text()}`);
  }
  if (res.status === 204) return undefined as T;
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

/**
 * Creates tenant `slug` (POST /tenants) with `settings` (NewTenantSettings fields such as
 * `auto_link` or `upstream_registration`; absent fields take the server defaults). A fresh tenant
 * per test keeps connections and login settings away from the shared default tenant.
 */
export async function createTenant(
  token: string,
  slug: string,
  settings: Record<string, unknown> = {},
): Promise<void> {
  await adminRequest(token, 'POST', '/tenants', { slug, display_name: `E2E ${slug}`, settings }, 201);
}

/** A user as listed by the admin API (the fields the upstream specs read). */
export interface TenantUser {
  id: string;
  email: string;
  email_verified: boolean;
  claims: { name?: string | null; given_name?: string | null; family_name?: string | null; [k: string]: unknown };
  [extra: string]: unknown;
}

/** The first 200 users of `tenant` (enough for the small per-test tenants). */
export async function tenantUsers(token: string, tenant: string): Promise<TenantUser[]> {
  const page = await adminRequest<{ items: TenantUser[] }>(
    token,
    'GET',
    `/tenants/${encodeURIComponent(tenant)}/users?limit=200`,
    undefined,
    200,
  );
  return page.items;
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

/** Deletes connection `id` of `tenant` (DELETE /tenants/{t}/connections/{id}). */
export async function deleteConnection(token: string, tenant: string, id: string): Promise<void> {
  await adminRequest(
    token,
    'DELETE',
    `/tenants/${encodeURIComponent(tenant)}/connections/${encodeURIComponent(id)}`,
    undefined,
    204,
  );
}

/** The connections of `tenant` (GET /tenants/{t}/connections). */
export async function listConnections(token: string, tenant: string): Promise<CreatedConnection[]> {
  const list = await adminRequest<{ items: CreatedConnection[] }>(
    token,
    'GET',
    `/tenants/${encodeURIComponent(tenant)}/connections`,
    undefined,
    200,
  );
  return list.items;
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

export interface MockConnection {
  mock: MockIdp;
  connection: CreatedConnection;
  slug: string;
}

/**
 * Starts a GitHub-like mock on 127.0.0.1 and creates a GitHub connection `slug` in `tenant` whose
 * authorization and token endpoints and API base point at it. `connection` holds extra
 * CreateConnection fields (`trust_email_verified`, `display_name`, ...). Stop the mock when done.
 */
export async function githubMockConnection(
  token: string,
  tenant: string,
  slug: string,
  users?: MockUser[],
  connection: Record<string, unknown> = {},
): Promise<MockConnection> {
  const clientId = `Iv1.${randomBytes(6).toString('hex')}`;
  const mock = await startMockIdp({
    kind: 'github',
    clientId,
    redirectUri: mockIdpRedirectUri(anvilUrl(), tenant, slug),
    users,
  });
  try {
    const created = await createConnection(token, tenant, {
      slug,
      display_name: 'GitHub',
      config: {
        type: 'social',
        provider: 'github',
        client_id: clientId,
        endpoints: {
          authorization_endpoint: `${mock.url}/login/oauth/authorize`,
          token_endpoint: `${mock.url}/login/oauth/access_token`,
          api_base_url: mock.url,
        },
      },
      secret: mock.clientSecret,
      ...connection,
    });
    return { mock, connection: created, slug };
  } catch (e) {
    await mock.stop();
    throw e;
  }
}

/**
 * Starts an Apple-like mock on 127.0.0.1 and creates an Apple connection `slug` in `tenant`: the
 * issuer, endpoints and JWKS point at the mock, the secret is a fresh .p8 key (appleKeyPair) whose
 * public half the mock checks AnvilID's ES256 client secret against. Stop the mock when done.
 */
export async function appleMockConnection(
  token: string,
  tenant: string,
  slug: string,
  users?: MockUser[],
  connection: Record<string, unknown> = {},
): Promise<MockConnection & { teamId: string; clientId: string; key: AppleKeyPair }> {
  const key = appleKeyPair();
  const teamId = `T${randomBytes(5).toString('hex').toUpperCase()}`;
  const clientId = `test.e2e.${randomBytes(4).toString('hex')}.services`;
  const mock = await startMockIdp({
    kind: 'apple',
    clientId,
    redirectUri: mockIdpRedirectUri(anvilUrl(), tenant, slug),
    appleClientKeyJwk: key.publicJwk,
    appleKeyId: key.keyId,
    appleTeamId: teamId,
    users,
  });
  try {
    const created = await createConnection(token, tenant, {
      slug,
      display_name: 'Apple',
      config: {
        type: 'social',
        provider: 'apple',
        client_id: clientId,
        endpoints: {
          issuer: mock.url,
          authorization_endpoint: `${mock.url}/auth/authorize`,
          token_endpoint: `${mock.url}/auth/token`,
          jwks_uri: `${mock.url}/auth/keys`,
        },
        apple: { team_id: teamId, key_id: key.keyId },
      },
      secret: key.privateKeyPem,
      ...connection,
    });
    return { mock, connection: created, slug, teamId, clientId, key };
  } catch (e) {
    await mock.stop();
    throw e;
  }
}

/**
 * Signs in on `tenant`'s hosted login page without an authorization request and waits for the
 * "Signed in" message page (a fresh session: account changes need a sign-in in the last 15 min).
 */
export async function signInAtTenant(
  page: Page,
  tenant: string,
  email: string,
  password: string,
): Promise<void> {
  await page.goto(`${tenantIssuer(tenant)}/ui/login`);
  await login(page, email, password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
}
