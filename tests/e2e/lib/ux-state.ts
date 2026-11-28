// Shared state and helpers for the user-journey specs (07.1): a few first-party test clients created
// once per run, a PKCE authorization URL builder and a tiny fake relying party that answers the
// redirect, so a spec can drive /authorize directly and assert on what the client received.
//
// The clients are cached next to the management credential (`${E2E_STATE_FILE}.ux.json`), the same
// single-worker state-file mechanism lib/anvil.ts sharedManagementCredential uses, so repeated specs
// of one run reuse them instead of creating new clients.
//
// The fake RP listens on 127.0.0.1:E2E_FAKE_RP_PORT (default 18199). Redirect URIs use `localhost`
// (loopback http is allowed for registered redirect URIs). Call fakeRp() in a beforeAll and close the
// returned handle in an afterAll.

import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { Browser, Page } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createClient,
  createUser,
  randomEmail,
  randomPassword,
  requireEnv,
  sharedManagementCredential,
  type ConsentMode,
  type ManagementCredential,
} from './anvil';

/** The fake RP port (E2E_FAKE_RP_PORT, default 18199). */
export function fakeRpPort(): number {
  const port = Number(process.env.E2E_FAKE_RP_PORT ?? 18199);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`E2E_FAKE_RP_PORT must be a TCP port, got ${process.env.E2E_FAKE_RP_PORT}`);
  }
  return port;
}

/** The fake RP origin as registered in redirect URIs (`http://localhost:{port}`). */
export function fakeRpOrigin(): string {
  return `http://localhost:${fakeRpPort()}`;
}

/** A client registered against the fake RP. `client_secret` is absent for public clients. */
export interface UxClient {
  client_id: string;
  client_secret?: string;
  redirect_uri: string;
}

export interface UxClients {
  /** Confidential web client (client_secret_basic), first party: consent skipped. */
  web: UxClient;
  /** Public browser client (auth method none, PKCE), first party: consent skipped. */
  spa: UxClient;
  /** Confidential web client with consent required, for consent-screen journeys. */
  thirdParty: UxClient;
}

export interface UxState {
  creds: ManagementCredential;
  clients: UxClients;
}

function uxStateFile(): string {
  return `${requireEnv('E2E_STATE_FILE')}.ux.json`;
}

async function makeClient(
  token: string,
  name: string,
  path: string,
  kind: 'confidential' | 'public',
  consent: ConsentMode,
): Promise<UxClient> {
  const redirect_uri = `${fakeRpOrigin()}/${path}`;
  const created = await createClient(
    token,
    {
      name,
      client_type: kind,
      application_type: 'web',
      auth_method: kind === 'confidential' ? 'client_secret_basic' : 'none',
      redirect_uris: [redirect_uri],
      grant_types: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile', 'email', 'offline_access'],
    },
    'default',
    consent,
  );
  if (kind === 'confidential' && !created.client_secret) {
    throw new Error(`client ${name} was created without a client_secret`);
  }
  return { client_id: created.client_id, client_secret: created.client_secret, redirect_uri };
}

/**
 * The run's management credential plus the cached journey clients of the default tenant. The first
 * call creates the clients (and completes /setup if no spec has yet); later calls read the cache.
 */
export async function uxState(browser: Browser): Promise<UxState> {
  const creds = await sharedManagementCredential(browser);
  const file = uxStateFile();
  if (existsSync(file) && readFileSync(file, 'utf8').trim() !== '') {
    const cached = JSON.parse(readFileSync(file, 'utf8')) as { origin: string; clients: UxClients };
    // A different E2E_FAKE_RP_PORT within one run would leave clients with unreachable redirects.
    if (cached.origin === fakeRpOrigin()) return { creds, clients: cached.clients };
  }
  const token = await adminToken(creds);
  const clients: UxClients = {
    web: await makeClient(token, 'UX journeys web app', 'callback', 'confidential', 'skip_first_party'),
    spa: await makeClient(token, 'UX journeys browser app', 'spa-callback', 'public', 'skip_first_party'),
    thirdParty: await makeClient(token, 'UX journeys third-party app', 'cb3', 'confidential', 'required'),
  };
  writeFileSync(file, JSON.stringify({ origin: fakeRpOrigin(), clients }), { mode: 0o600 });
  return { creds, clients };
}

/** A fresh admin API access token for the run's management credential. */
export function token(s: UxState): Promise<string> {
  return adminToken(s.creds);
}

export interface AuthorizeRequest {
  /** The full authorization URL to navigate to. */
  url: string;
  /** PKCE code_verifier matching the S256 code_challenge in `url`. */
  verifier: string;
  /** The `state` value in `url` (unless overridden through `extra`). */
  state: string;
  /** The `nonce` value in `url` (unless overridden through `extra`). */
  nonce: string;
}

/**
 * Builds a PKCE (S256) authorization request for `client` with fresh state and nonce. `extra`
 * adds or replaces parameters (prompt, scope, ui_locales, ...); `issuer` defaults to the default
 * tenant.
 */
export function authorizeUrl(
  client: Pick<UxClient, 'client_id' | 'redirect_uri'>,
  extra: Record<string, string> = {},
  issuer: string = anvilUrl(),
): AuthorizeRequest {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(12).toString('base64url');
  const nonce = randomBytes(12).toString('base64url');
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uri,
    scope: 'openid profile email',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  });
  return { url: `${issuer.replace(/\/+$/, '')}/authorize?${query}`, verifier, state, nonce };
}

export interface FakeRp {
  /** `http://localhost:{port}`. */
  origin: string;
  /** Stops the server (idempotent). */
  close(): Promise<void>;
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

let server: Server | undefined;

/**
 * Starts the fake RP: an HTTP server on 127.0.0.1:E2E_FAKE_RP_PORT that answers every request with
 * a small page listing the received query parameters (`#rp-params`). Playwright routes do not see
 * redirect targets, so a real server is needed to land on the callback. Fails if the port is taken.
 * A second call while running returns the same server.
 */
export async function fakeRp(): Promise<FakeRp> {
  const origin = fakeRpOrigin();
  const handle: FakeRp = {
    origin,
    async close() {
      const s = server;
      server = undefined;
      if (s) await new Promise<void>((resolve) => s.close(() => resolve()));
    },
  };
  if (server) return handle;
  const s = createServer((req, res) => {
    const url = new URL(req.url ?? '/', origin);
    const rows = [...url.searchParams]
      .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd>`)
      .join('');
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    res.end(
      `<!doctype html><html lang="en"><title>Fake RP</title><main><h1>Fake RP callback</h1>` +
        `<p id="rp-path">${escapeHtml(url.pathname)}</p><dl id="rp-params">${rows}</dl></main></html>`,
    );
  });
  await new Promise<void>((resolve, reject) => {
    s.once('error', reject);
    s.listen(fakeRpPort(), '127.0.0.1', () => {
      s.off('error', reject);
      resolve();
    });
  });
  server = s;
  return handle;
}

export interface UxUser {
  id: string;
  email: string;
  password: string;
}

/** Creates a verified user with a random password in `tenant`; `extra` is merged into the body. */
export async function newUser(
  s: UxState,
  prefix = 'ux',
  tenant = 'default',
  extra: Record<string, unknown> = {},
): Promise<UxUser> {
  const email = randomEmail(prefix);
  const password = randomPassword();
  const user = await createUser(await token(s), { email, password, email_verified: true, ...extra }, tenant);
  if (!user.id) throw new Error(`POST /tenants/${tenant}/users returned no user id`);
  return { id: user.id, email, password };
}

/** Waits until the browser lands on the fake RP and returns the callback's query parameters. */
export async function atRp(page: Page): Promise<URLSearchParams> {
  const origin = fakeRpOrigin();
  await page.waitForURL((url) => url.origin === origin);
  return new URL(page.url()).searchParams;
}

/** Navigates to `url` and returns the HTTP status of the final response. */
export async function visit(page: Page, url: string): Promise<number> {
  const response = await page.goto(url);
  if (!response) throw new Error(`navigation to ${url} produced no response`);
  return response.status();
}
