// Helpers for the account security pages (/ui/account/security), the audit API, the sample relying
// party and a minimal authorization-code client, used by the passkey and TOTP specs.
//
// Every endpoint comes from the environment (ANVIL_URL); nothing here holds a credential.

import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { expect, type Page } from '@playwright/test';
import { anvilUrl, login } from './anvil';
import { totp } from './totp';

// ---------------------------------------------------------------------------------------------
// Sign-in and the account security page

/**
 * Signs in on the hosted login page without an authorization request. Ends on the "Signed in"
 * message page with a fresh browser session (account changes need a sign-in in the last 15 min).
 */
export async function signInDirect(page: Page, email: string, password: string): Promise<void> {
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, email, password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
}

/** Opens /ui/account/security (the browser must hold a session) and waits for the page. */
export async function openAccountSecurity(page: Page): Promise<void> {
  await page.goto(`${anvilUrl()}/ui/account/security`);
  await expect(page.locator('#passkeys-heading')).toBeVisible();
  await expect(page.locator('#account-reauth')).toHaveCount(0);
}

/**
 * Registers a passkey with `label` from the account security page (needs a WebAuthn
 * authenticator on the page) and waits until it is listed.
 */
export async function registerPasskey(page: Page, label: string): Promise<void> {
  await openAccountSecurity(page);
  await page.locator('#label').fill(label);
  const trigger = page.locator('#passkey-register-submit');
  await expect(trigger).toBeVisible();
  await trigger.click();
  await expect(page.locator('[data-message-key="account.passkey_registered"]')).toBeVisible();
  await expect(
    page.locator('#passkey-list .anvil-credential-label', { hasText: label }),
  ).toBeVisible();
}

export interface TotpEnrolment {
  /** The base32 shared secret shown on the enrolment page (spaces removed). */
  secret: string;
  /** The 30-second time step whose code confirmed the enrolment (that step is now used up). */
  step: number;
  /** The ten one-time recovery codes shown once after confirmation. */
  recoveryCodes: string[];
}

/**
 * Enrols an authenticator app from the account security page: reads the secret from the page,
 * confirms with the current code and collects the recovery codes. `onPage` runs on the enrolment
 * page and on the recovery-codes page (e.g. for an accessibility audit).
 */
export async function enrolTotp(
  page: Page,
  onPage?: (name: 'enrolment' | 'recovery-codes') => Promise<void>,
): Promise<TotpEnrolment> {
  await openAccountSecurity(page);
  await page.locator('#totp-begin-submit').click();
  const secretEl = page.locator('#totp-secret');
  await expect(secretEl).toBeVisible();
  await expect(page.locator('#totp-qr svg')).toBeVisible();
  const secret = ((await secretEl.textContent()) ?? '').replace(/\s+/g, '');
  expect(secret).toMatch(/^[A-Z2-7]+$/);
  if (onPage) await onPage('enrolment');

  const now = Date.now() / 1000;
  const step = Math.floor(now / 30);
  await page.locator('#code').fill(totp(secret, now));
  await page.locator('#totp-confirm-submit').click();

  await expect(page.locator('#account-msg-1')).toHaveAttribute(
    'data-message-key',
    'account.totp_enrolled',
  );
  const recoveryCodes = (await page.locator('#recovery-codes li code').allTextContents()).map((c) =>
    c.trim(),
  );
  expect(recoveryCodes).toHaveLength(10);
  if (onPage) await onPage('recovery-codes');
  return { secret, step, recoveryCodes };
}

// ---------------------------------------------------------------------------------------------
// Admin audit API

export interface AuditEvent {
  id: string;
  at: string;
  action: string;
  target?: string | null;
  outcome: string;
  details: Record<string, unknown>;
}

/** One page (newest first) of the default tenant's audit log filtered by `query`. */
export async function auditEvents(
  token: string,
  query: Record<string, string>,
  tenant = 'default',
): Promise<AuditEvent[]> {
  const res = await fetch(
    `${anvilUrl()}/api/admin/v1/tenants/${encodeURIComponent(tenant)}/audit-events?${new URLSearchParams(query)}`,
    { headers: { authorization: `Bearer ${token}`, accept: 'application/json' } },
  );
  if (res.status !== 200) {
    throw new Error(`audit query failed: HTTP ${res.status} ${await res.text()}`);
  }
  return ((await res.json()) as { items: AuditEvent[] }).items;
}

// ---------------------------------------------------------------------------------------------
// The sample relying party (examples/node-rp), started on a free loopback port

const RP_SERVER = fileURLToPath(new URL('../../../examples/node-rp/server.js', import.meta.url));

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => {
        if (addr && typeof addr === 'object') resolve(addr.port);
        else reject(new Error('no port'));
      });
    });
  });
}

export interface SampleRp {
  /** Base URL, e.g. http://localhost:43123 (redirect URI `${base}/callback`). */
  base: string;
  stop(): Promise<void>;
}

/**
 * Starts examples/node-rp for a client registered with redirect URI `${base}/callback`.
 * `register` creates that client and returns its id and secret.
 */
export async function startSampleRp(
  register: (redirectUri: string) => Promise<{ client_id: string; client_secret?: string }>,
): Promise<SampleRp> {
  const port = await freePort();
  const base = `http://localhost:${port}`;
  const client = await register(`${base}/callback`);
  let log = '';
  const proc: ChildProcess = spawn(process.execPath, [RP_SERVER], {
    env: {
      ...process.env,
      ISSUER: anvilUrl(),
      CLIENT_ID: client.client_id,
      CLIENT_SECRET: client.client_secret ?? '',
      PORT: String(port),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  proc.stdout?.on('data', (d: Buffer) => (log += d.toString()));
  proc.stderr?.on('data', (d: Buffer) => (log += d.toString()));

  const deadline = Date.now() + 15_000;
  for (;;) {
    try {
      if ((await fetch(`${base}/healthz`)).ok) break;
    } catch {
      // not listening yet
    }
    if (proc.exitCode !== null) throw new Error(`sample RP exited (${proc.exitCode}):\n${log}`);
    if (Date.now() > deadline) throw new Error(`sample RP did not start:\n${log}`);
    await new Promise((r) => setTimeout(r, 200));
  }

  return {
    base,
    async stop() {
      if (proc.exitCode === null) {
        const exited = new Promise((r) => proc.once('exit', r));
        proc.kill('SIGTERM');
        await exited;
      }
    },
  };
}

// ---------------------------------------------------------------------------------------------
// A minimal authorization-code client, for assertions on the ID token (the sample RP does not
// show it). The redirect URI is never served: the browser request carrying the code is captured
// and answered by Playwright.

export interface CodeClient {
  client_id: string;
  client_secret: string;
  redirect_uri: string;
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
}

const b64url = (buf: Buffer) => buf.toString('base64url');

/**
 * Runs an authorization request in `page`, lets `signIn` complete the hosted login, exchanges
 * the code and returns the ID token claims (nonce checked). `issuer` defaults to the default
 * tenant; pass `{ANVIL_URL}/t/{slug}` for a client of another tenant.
 */
export async function signInForIdToken(
  page: Page,
  client: CodeClient,
  signIn: (page: Page) => Promise<void>,
  issuer: string = anvilUrl(),
): Promise<Record<string, unknown>> {
  const discoveryRes = await fetch(`${issuer}/.well-known/openid-configuration`);
  const discovery = (await discoveryRes.json()) as Discovery;
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const state = b64url(randomBytes(16));
  const nonce = b64url(randomBytes(16));
  const authorize = new URL(discovery.authorization_endpoint);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uri,
    scope: 'openid email',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();

  await page.route(`${client.redirect_uri}**`, (route) =>
    route.fulfill({ status: 200, contentType: 'text/plain', body: 'callback captured' }),
  );
  try {
    const callback = page.waitForRequest((r) => r.url().startsWith(client.redirect_uri));
    await page.goto(authorize.href);
    await signIn(page);
    const params = new URL((await callback).url()).searchParams;
    expect(params.get('state')).toBe(state);
    const code = params.get('code');
    if (!code) throw new Error(`no code in the callback: ${params}`);

    const basic = Buffer.from(
      `${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`,
    ).toString('base64');
    const res = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: {
        authorization: `Basic ${basic}`,
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: client.redirect_uri,
        code_verifier: verifier,
      }).toString(),
    });
    if (res.status !== 200) {
      throw new Error(`token request failed: HTTP ${res.status} ${await res.text()}`);
    }
    const { id_token: idToken } = (await res.json()) as { id_token?: string };
    if (!idToken) throw new Error('token response has no id_token');
    // Received directly from the token endpoint over the back channel, so the payload is read
    // without verifying the signature (the protocol suites cover ID token validation).
    const claims = JSON.parse(
      Buffer.from(idToken.split('.')[1] ?? '', 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    expect(claims.nonce).toBe(nonce);
    return claims;
  } finally {
    await page.unroute(`${client.redirect_uri}**`);
  }
}
