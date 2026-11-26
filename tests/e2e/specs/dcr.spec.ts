// Dynamic client registration (OIDC-17, plans 05-21/05-23) in a real browser: under the `open`
// policy a client registers itself at `{issuer}/register` (RFC 7591) and a user signs in with it
// through the consent screen; `allow_listed` needs an initial access token issued through the admin
// API (401 without one) and enforces the redirect-host allow-list; `disabled` (the default) answers
// 404 and is not advertised in discovery.
//
// Each test runs in a tenant of its own, deleted afterwards. Redirect URIs are never served:
// lib/code-flow.ts captures the callback in the browser.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import {
  adminToken,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { adminCall, tenantPath } from '../lib/admin-api';
import { authorizationCodeFlow, jwtClaims } from '../lib/code-flow';
import { deleteTenant } from '../lib/email-code';
import { createTenant, randomSlug, tenantIssuer } from '../lib/upstream';

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
});

const RP_HOST = 'dcr-rp.example.test';
const REDIRECT_URI = `https://${RP_HOST}/callback`;

interface Registered {
  client_id: string;
  client_secret?: string;
  registration_access_token: string;
  registration_client_uri: string;
  [k: string]: unknown;
}

function registrationRequest(redirectUri = REDIRECT_URI): Record<string, unknown> {
  return {
    redirect_uris: [redirectUri],
    client_name: 'E2E partner app',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
    scope: 'openid email',
  };
}

async function postRegister(slug: string, body: unknown, bearer?: string): Promise<Response> {
  return fetch(`${tenantIssuer(slug)}/register`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

async function setDcr(token: string, slug: string, dcr: Record<string, unknown>): Promise<void> {
  await adminCall(token, 'PATCH', tenantPath(slug), { settings: { dcr } });
}

async function discovery(slug: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${tenantIssuer(slug)}/.well-known/openid-configuration`);
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

async function issueIat(token: string, slug: string, uses: number): Promise<string> {
  const issued = await adminCall<{ value: string }>(
    token,
    'POST',
    tenantPath(slug, '/initial-access-tokens'),
    { description: 'e2e partner onboarding', expires_in: 3600, uses },
    201,
  );
  return issued.value;
}

test('open policy: a self-registered client signs a user in through the consent screen', async ({ page }) => {
  const token = await adminToken(creds);
  const slug = randomSlug('dcr');
  await createTenant(token, slug);
  try {
    await setDcr(token, slug, { policy: 'open' });
    expect((await discovery(slug)).registration_endpoint).toBe(`${tenantIssuer(slug)}/register`);

    const res = await postRegister(slug, registrationRequest());
    expect(res.status, await res.clone().text()).toBe(201);
    expect(res.headers.get('cache-control')).toContain('no-store');
    const client = (await res.json()) as Registered;
    expect(client.client_secret).toBeTruthy();
    expect(client.registration_access_token).toBeTruthy();
    expect(client.registration_client_uri).toBe(`${tenantIssuer(slug)}/register/${client.client_id}`);

    // RFC 7592 read with the registration access token; the secret is not returned again.
    const read = await fetch(client.registration_client_uri, {
      headers: { authorization: `Bearer ${client.registration_access_token}`, accept: 'application/json' },
    });
    expect(read.status).toBe(200);
    const info = (await read.json()) as Record<string, unknown>;
    expect(info.client_id).toBe(client.client_id);
    expect(info).not.toHaveProperty('client_secret');

    // The admin API lists it as a dynamic client.
    const view = await adminCall<{ registration_source: string }>(
      token,
      'GET',
      tenantPath(slug, `/clients/${encodeURIComponent(client.client_id)}`),
    );
    expect(view.registration_source).toBe('dynamic');

    // Sign in with the registered client: dynamic clients always ask for consent.
    const email = randomEmail('dcr');
    const password = randomPassword();
    await createUser(token, { email, password, email_verified: true }, slug);
    const tokens = await authorizationCodeFlow(
      page,
      { client_id: client.client_id, client_secret: client.client_secret, redirect_uri: REDIRECT_URI },
      'openid email',
      async (p) => {
        await login(p, email, password);
        await expect(p.locator('#consent-form')).toBeVisible();
        await expect(p.locator('#consent-cimd')).toHaveCount(0);
        await p.locator('#consent-allow').click();
      },
      tenantIssuer(slug),
    );
    if (!tokens.id_token) throw new Error('no id_token');
    const claims = jwtClaims(tokens.id_token);
    expect([claims.aud].flat()).toContain(client.client_id);
    expect(claims.iss).toBe(tenantIssuer(slug));
    // The consented `email` scope: UserInfo answers the access token with the address.
    const userinfoEndpoint = (await discovery(slug)).userinfo_endpoint as string;
    const userinfo = await fetch(userinfoEndpoint, {
      headers: { authorization: `Bearer ${tokens.access_token}`, accept: 'application/json' },
    });
    expect(userinfo.status).toBe(200);
    expect(((await userinfo.json()) as { email?: string }).email).toBe(email);
  } finally {
    await deleteTenant(token, slug);
  }
});

test('allow_listed policy: registration needs an initial access token and an allowed redirect host', async () => {
  const token = await adminToken(creds);
  const slug = randomSlug('dcr');
  await createTenant(token, slug);
  try {
    await setDcr(token, slug, { policy: 'allow_listed', allowed_redirect_hosts: [RP_HOST] });

    // No initial access token: 401 invalid_token before the body is looked at.
    const anonymous = await postRegister(slug, registrationRequest());
    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.get('www-authenticate') ?? '').toContain('invalid_token');
    const bogus = await postRegister(slug, registrationRequest(), 'not-a-real-token');
    expect(bogus.status).toBe(401);

    // A single-use token: a redirect host outside the allow-list is refused without using it up,
    // an allowed one registers, and the token is then spent.
    const iat = await issueIat(token, slug, 1);
    const wrongHost = await postRegister(slug, registrationRequest('https://elsewhere.example.test/cb'), iat);
    expect(wrongHost.status).toBe(400);
    expect(((await wrongHost.json()) as { error: string }).error).toBe('invalid_redirect_uri');

    const ok = await postRegister(slug, registrationRequest(), iat);
    expect(ok.status, await ok.clone().text()).toBe(201);
    const client = (await ok.json()) as Registered;
    expect(client.registration_access_token).not.toBe(iat);

    const spent = await postRegister(slug, registrationRequest(), iat);
    expect(spent.status).toBe(401);
  } finally {
    await deleteTenant(token, slug);
  }
});

test('disabled policy: no registration endpoint, and RFC 7592 management stops too', async () => {
  const token = await adminToken(creds);
  const slug = randomSlug('dcr');
  await createTenant(token, slug);
  try {
    // New tenants start disabled.
    expect((await discovery(slug)).registration_endpoint).toBeUndefined();
    expect((await postRegister(slug, registrationRequest())).status).toBe(404);

    // Register under `open`, then disable again: the management endpoint disappears as well.
    await setDcr(token, slug, { policy: 'open' });
    const res = await postRegister(slug, registrationRequest());
    expect(res.status).toBe(201);
    const client = (await res.json()) as Registered;
    await setDcr(token, slug, { policy: 'disabled' });
    expect((await discovery(slug)).registration_endpoint).toBeUndefined();
    expect((await postRegister(slug, registrationRequest())).status).toBe(404);
    const read = await fetch(client.registration_client_uri, {
      headers: { authorization: `Bearer ${client.registration_access_token}` },
    });
    expect(read.status).toBe(404);

    // The system tenant never offers registration.
    expect((await postRegister('system', registrationRequest())).status).toBe(404);
  } finally {
    await deleteTenant(token, slug);
  }
});
