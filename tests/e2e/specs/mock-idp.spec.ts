// Self-test of the local mock IdPs (lib/mock-idp.ts). Needs no AnvilID: a small echo server stands
// in for AnvilID's upstream callback and records what the browser delivers to it. The echo server is
// addressed as `localhost` and the mock as `127.0.0.1`, the same cross-site arrangement the social
// login specs use.

import { request as httpRequest, createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { decodeJwt, mockIdpRedirectUri, startMockIdp, verifyEs256Jwt, type Jwk, type MockIdp } from '../lib/mock-idp';
import { appleClientSecret, appleKeyPair } from '../lib/upstream';

interface Delivery {
  method: string;
  query: Record<string, string>;
  form: Record<string, string>;
}

interface Echo {
  url: string;
  deliveries: Delivery[];
  stop(): Promise<void>;
}

async function startEcho(): Promise<Echo> {
  const deliveries: Delivery[] = [];
  const server: Server = createServer((req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      deliveries.push({
        method: req.method ?? 'GET',
        query: Object.fromEntries(url.searchParams),
        form: Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8'))),
      });
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><title>callback</title><p id="echo">received</p>');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, () => resolve()));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://localhost:${port}/ui/login/upstream/mock/callback`,
    deliveries,
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** A raw HTTP GET with exactly the given headers (fetch always adds a User-Agent). */
function rawGet(url: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { method: 'GET', headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end();
  });
}

function form(params: Record<string, string>): string {
  return new URLSearchParams(params).toString();
}

test('mockIdpRedirectUri builds the upstream callback URL', () => {
  expect(mockIdpRedirectUri('http://localhost:8080/', 'default', 'apple')).toBe(
    'http://localhost:8080/ui/login/upstream/apple/callback',
  );
  expect(mockIdpRedirectUri('http://localhost:8080', 'acme', 'github')).toBe(
    'http://localhost:8080/t/acme/ui/login/upstream/github/callback',
  );
});

test.describe('apple-like mock', () => {
  let echo: Echo;
  let idp: MockIdp;
  const keys = appleKeyPair();
  const teamId = 'TEAM123456';
  const clientId = 'test.services.id';

  test.beforeEach(async () => {
    echo = await startEcho();
    idp = await startMockIdp({
      kind: 'apple',
      clientId,
      redirectUri: echo.url,
      appleClientKeyJwk: keys.publicJwk,
      appleTeamId: teamId,
    });
    expect(new URL(idp.url).hostname).toBe('127.0.0.1');
  });

  test.afterEach(async () => {
    await idp.stop();
    await echo.stop();
  });

  function authorizeUrl(nonce: string, state: string, extra: Record<string, string> = {}): string {
    const url = new URL(`${idp.url}/auth/authorize`);
    url.search = form({
      client_id: clientId,
      redirect_uri: echo.url,
      response_type: 'code',
      response_mode: 'form_post',
      scope: 'name email',
      state,
      nonce,
      ...extra,
    });
    return url.href;
  }

  async function authorize(page: import('@playwright/test').Page, nonce: string, state: string): Promise<Delivery> {
    const before = echo.deliveries.length;
    await page.goto(authorizeUrl(nonce, state));
    await page.locator('#mock-continue').click();
    await expect(page.locator('#echo')).toHaveText('received');
    expect(echo.deliveries.length).toBe(before + 1);
    return echo.deliveries[before];
  }

  async function exchange(code: string, secret: string): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await fetch(`${idp.url}/auth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form({ grant_type: 'authorization_code', code, redirect_uri: echo.url, client_id: clientId, client_secret: secret }),
    });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  }

  test('form_post callback, ES256 ID token with string email_verified, user JSON only once', async ({ page }) => {
    const user = idp.users[0];
    const first = await authorize(page, 'nonce-1', 'state-1');
    expect(first.method).toBe('POST');
    expect(first.form.state).toBe('state-1');
    expect(first.form.code).toBeTruthy();
    expect(first.form.id_token).toBeTruthy();
    const userJson = JSON.parse(first.form.user) as { name: { firstName: string; lastName: string }; email: string };
    expect(userJson.email).toBe(user.email);
    expect(userJson.name.firstName).toBe(user.firstName);

    const secret = appleClientSecret(keys, { teamId, clientId, audience: idp.url });
    const tok = await exchange(first.form.code, secret);
    expect(tok.status).toBe(200);
    const jwks = (await (await fetch(`${idp.url}/auth/keys`)).json()) as { keys: Jwk[] };
    const idToken = tok.body.id_token as string;
    const kid = decodeJwt(idToken).header.kid;
    const jwk = jwks.keys.find((k) => (k as { kid?: string }).kid === kid);
    expect(jwk).toBeTruthy();
    const { header, claims } = verifyEs256Jwt(idToken, jwk!);
    expect(header.alg).toBe('ES256');
    expect(claims.iss).toBe(idp.url);
    expect(claims.aud).toBe(clientId);
    expect(claims.sub).toBe(user.sub);
    expect(claims.nonce).toBe('nonce-1');
    expect(claims.email).toBe(user.email);
    expect(claims.email_verified).toBe('true');
    expect(typeof claims.is_private_email).toBe('string');

    // Codes are single-use.
    const replay = await exchange(first.form.code, secret);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');

    // Second authorization for the same subject: no user JSON.
    const second = await authorize(page, 'nonce-2', 'state-2');
    expect(second.form.user).toBeUndefined();
    expect(second.form.code).toBeTruthy();
    const auths = idp.authorizations.filter((a) => a.endpoint === '/auth/authorize');
    expect(auths.map((a) => a.userSent)).toEqual([true, false]);
  });

  test('client secret is checked: wrong aud, wrong signer and missing secret are invalid_client', async ({ page }) => {
    const delivery = await authorize(page, 'n', 's');
    const wrongAud = appleClientSecret(keys, { teamId, clientId, audience: 'https://issuer.example.test' });
    expect((await exchange(delivery.form.code, wrongAud)).body.error).toBe('invalid_client');
    const otherKeys = appleKeyPair(keys.keyId);
    const wrongKey = appleClientSecret(otherKeys, { teamId, clientId, audience: idp.url });
    expect((await exchange(delivery.form.code, wrongKey)).body.error).toBe('invalid_client');
    expect((await exchange(delivery.form.code, '')).body.error).toBe('invalid_client');
    const wrongTeam = appleClientSecret(keys, { teamId: 'OTHERTEAM', clientId, audience: idp.url });
    expect((await exchange(delivery.form.code, wrongTeam)).body.error).toBe('invalid_client');
    // The code was not consumed by the rejected attempts.
    const ok = appleClientSecret(keys, { teamId, clientId, audience: idp.url });
    expect((await exchange(delivery.form.code, ok)).status).toBe(200);
  });

  test('name/email scope without form_post and a foreign redirect_uri are refused', async ({ page }) => {
    await page.goto(authorizeUrl('n', 's', { response_mode: 'query' }));
    await expect(page.locator('#mock-error')).toContainText('form_post');
    await page.goto(authorizeUrl('n', 's', { redirect_uri: 'http://localhost:1/elsewhere' }));
    await expect(page.locator('#mock-error')).toHaveText('invalid_redirect_uri');
  });
});

test.describe('github-like mock', () => {
  let echo: Echo;
  let idp: MockIdp;
  const clientId = 'Iv1.testclient';

  test.beforeEach(async () => {
    echo = await startEcho();
    idp = await startMockIdp({ kind: 'github', clientId, redirectUri: echo.url });
    expect(new URL(idp.url).hostname).toBe('127.0.0.1');
  });

  test.afterEach(async () => {
    await idp.stop();
    await echo.stop();
  });

  async function authorize(
    page: import('@playwright/test').Page,
    challenge?: string,
  ): Promise<{ code: string; state: string }> {
    const before = echo.deliveries.length;
    const url = new URL(`${idp.url}/login/oauth/authorize`);
    const state = randomBytes(8).toString('hex');
    url.search = form({
      client_id: clientId,
      redirect_uri: echo.url,
      scope: 'read:user user:email',
      state,
      ...(challenge ? { code_challenge: challenge, code_challenge_method: 'S256' } : {}),
    });
    await page.goto(url.href);
    await page.locator('#mock-continue').click();
    await expect(page.locator('#echo')).toHaveText('received');
    const d = echo.deliveries[before];
    expect(d.method).toBe('GET');
    expect(d.query.state).toBe(state);
    return { code: d.query.code, state };
  }

  function tokenRequest(params: Record<string, string>, accept?: string): Promise<Response> {
    return fetch(`${idp.url}/login/oauth/access_token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        ...(accept ? { accept } : {}),
      },
      body: form({ client_id: clientId, client_secret: idp.clientSecret, redirect_uri: echo.url, ...params }),
    });
  }

  test('token endpoint answers JSON only with Accept: application/json; PKCE enforced', async ({ page }) => {
    // Without Accept: form-encoded body.
    const a = await authorize(page);
    const plain = await tokenRequest({ code: a.code });
    expect(plain.status).toBe(200);
    expect(plain.headers.get('content-type')).toContain('application/x-www-form-urlencoded');
    expect(new URLSearchParams(await plain.text()).get('access_token')).toMatch(/^gho_/);

    // With PKCE: missing verifier is an HTTP 200 error body (GitHub quirk).
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const b = await authorize(page, challenge);
    expect(idp.authorizations.filter((x) => x.endpoint === '/login/oauth/authorize').at(-1)?.pkce).toBe(true);
    const missing = await tokenRequest({ code: b.code }, 'application/json');
    expect(missing.status).toBe(200);
    expect(((await missing.json()) as { error?: string }).error).toBe('bad_verification_code');

    const c = await authorize(page, challenge);
    const res = await tokenRequest({ code: c.code, code_verifier: verifier }, 'application/json');
    expect(res.headers.get('content-type')).toContain('application/json');
    const body = (await res.json()) as { access_token?: string; token_type?: string };
    expect(body.access_token).toMatch(/^gho_/);
    expect(body.token_type).toBe('bearer');

    // Single use.
    const replay = await tokenRequest({ code: c.code, code_verifier: verifier }, 'application/json');
    expect(((await replay.json()) as { error?: string }).error).toBe('bad_verification_code');

    // Wrong client secret.
    const d = await authorize(page);
    const bad = await fetch(`${idp.url}/login/oauth/access_token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: form({ client_id: clientId, client_secret: 'wrong', code: d.code }),
    });
    expect(((await bad.json()) as { error?: string }).error).toBe('incorrect_client_credentials');

    // API: User-Agent required; one primary verified address among the emails.
    const auth = { authorization: `Bearer ${body.access_token}`, accept: 'application/vnd.github+json' };
    const noUa = await rawGet(`${idp.url}/user/emails`, auth);
    expect(noUa.status).toBe(403);
    const user = await rawGet(`${idp.url}/user`, { ...auth, 'user-agent': 'anvilid-e2e' });
    expect(user.status).toBe(200);
    const profile = JSON.parse(user.body) as { id: unknown; login: string };
    expect(typeof profile.id).toBe('number');
    expect(profile.login).toBe(idp.users[0].login);
    const emails = await rawGet(`${idp.url}/user/emails`, { ...auth, 'user-agent': 'anvilid-e2e' });
    expect(emails.status).toBe(200);
    const list = JSON.parse(emails.body) as { email: string; primary: boolean; verified: boolean }[];
    expect(list.filter((e) => e.primary && e.verified).map((e) => e.email)).toEqual([idp.users[0].email]);
    expect(list.some((e) => !e.primary && e.verified)).toBe(true);
    expect(list.some((e) => !e.verified)).toBe(true);
    const anon = await rawGet(`${idp.url}/user`, { 'user-agent': 'anvilid-e2e' });
    expect(anon.status).toBe(401);
  });
});
