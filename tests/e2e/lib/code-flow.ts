// A minimal OAuth 2.0 authorization-code client (PKCE S256, state, nonce) that returns the whole
// token response, for specs that assert on access-token claims, refresh behaviour or a client
// registered at runtime (attributes, DCR, RBAC claims). lib/account.ts signInForIdToken covers the
// ID-token-only case with a fixed scope.
//
// The redirect URI is never served: Playwright captures the browser request carrying the code and
// answers it, so any https or loopback redirect URI works. Tokens arrive directly from the token
// endpoint over the back channel, so JWT payloads are read without verifying the signature (the
// Rust protocol suites cover token validation).

import { createHash, randomBytes } from 'node:crypto';
import { expect, type Page } from '@playwright/test';
import { anvilUrl } from './anvil';

export interface CodeFlowClient {
  client_id: string;
  /** client_secret_basic when set; a public client (`none`) otherwise. */
  client_secret?: string;
  redirect_uri: string;
}

export interface TokenSet {
  access_token: string;
  token_type: string;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
  [extra: string]: unknown;
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
}

async function discover(issuer: string): Promise<Discovery> {
  const res = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (res.status !== 200) throw new Error(`discovery failed for ${issuer}: HTTP ${res.status}`);
  return (await res.json()) as Discovery;
}

async function tokenRequest(
  endpoint: string,
  client: CodeFlowClient,
  params: Record<string, string>,
): Promise<TokenSet> {
  const headers: Record<string, string> = {
    'content-type': 'application/x-www-form-urlencoded',
    accept: 'application/json',
  };
  const body = new URLSearchParams(params);
  if (client.client_secret !== undefined) {
    headers.authorization = `Basic ${Buffer.from(
      `${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`,
    ).toString('base64')}`;
  } else {
    body.set('client_id', client.client_id);
  }
  const res = await fetch(endpoint, { method: 'POST', headers, body: body.toString() });
  if (res.status !== 200) {
    throw new Error(`token request failed: HTTP ${res.status} ${await res.text()}`);
  }
  return (await res.json()) as TokenSet;
}

/** The payload of a compact JWT (not verified; see the module comment). */
export function jwtClaims(token: string): Record<string, unknown> {
  const payload = token.split('.')[1];
  if (!payload) throw new Error('not a compact JWT');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/**
 * Runs an authorization request with `scope` in `page`, lets `signIn` complete the hosted pages
 * (login, consent, ...), exchanges the code and returns the token response. The ID token's nonce
 * is checked when one is returned. `issuer` defaults to the default tenant.
 */
export async function authorizationCodeFlow(
  page: Page,
  client: CodeFlowClient,
  scope: string,
  signIn: (page: Page) => Promise<void>,
  issuer: string = anvilUrl(),
): Promise<TokenSet> {
  const discovery = await discover(issuer);
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(16).toString('base64url');
  const nonce = randomBytes(16).toString('base64url');
  const authorize = new URL(discovery.authorization_endpoint);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uri,
    scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();

  const pattern = `${client.redirect_uri}**`;
  await page.route(pattern, (route) =>
    route.fulfill({ status: 200, contentType: 'text/plain', body: 'callback captured' }),
  );
  try {
    const callback = page.waitForRequest((r) => r.url().startsWith(client.redirect_uri));
    try {
      await page.goto(authorize.href);
    } catch (e) {
      // A browser session that already satisfies the request redirects straight to the redirect
      // URI. Playwright routes only the first request of a redirect chain, so that navigation
      // fails (the host does not exist) although the request carrying the code was made.
      const reached = await Promise.race([
        callback.then(() => true),
        new Promise<boolean>((r) => setTimeout(() => r(false), 5_000)),
      ]);
      if (!reached) throw e;
    }
    await signIn(page);
    const params = new URL((await callback).url()).searchParams;
    expect(params.get('state')).toBe(state);
    const code = params.get('code');
    if (!code) throw new Error(`no code in the callback: ${params}`);
    const tokens = await tokenRequest(discovery.token_endpoint, client, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: client.redirect_uri,
      code_verifier: verifier,
    });
    if (tokens.id_token) expect(jwtClaims(tokens.id_token).nonce).toBe(nonce);
    return tokens;
  } finally {
    await page.unroute(pattern);
  }
}

/** Runs a refresh-token grant and returns the new token response. */
export async function refreshTokens(
  client: CodeFlowClient,
  refreshToken: string,
  issuer: string = anvilUrl(),
): Promise<TokenSet> {
  const discovery = await discover(issuer);
  return tokenRequest(discovery.token_endpoint, client, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });
}
