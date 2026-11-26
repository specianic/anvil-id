// AGT-01 / AGT-02 in a browser: an MCP client authorizes against AnvilID with a Client ID
// Metadata Document and an RFC 8707 resource indicator, and the MCP server accepts the token.
//
// - A fresh path tenant with the CIMD policy `open` and the mock MCP server's URL in
//   `dcr.allowed_resources` (CIMD clients take their resources from that list), set through the
//   admin API.
// - The mock MCP server (tests/mcp/mock-mcp-server.ts) answers 401 with `resource_metadata`; its
//   RFC 9728 document names the tenant issuer. The mock client (tests/mcp/mock-mcp-client.ts)
//   finds the authorization server through RFC 8414 path insertion
//   (`/.well-known/oauth-authorization-server/t/{slug}`), serves its metadata document on
//   127.0.0.1 and builds the PKCE authorization URL with `resource`.
// - The browser signs in and approves the consent screen, which names the client by its host and
//   lists the MCP server. The code exchange (with the same `resource`) gives an access token with
//   `aud` = the MCP server; the mock server verifies signature (JWKS), `iss`, `aud`, `exp` and
//   answers 200. A second MCP server refuses the same token (audience).
// - With the tenant CIMD policy `disabled`, the same authorization URL shows the error page: no
//   redirect to the client and no document fetch.
//
// The metadata document is served over plain http on loopback, which AnvilID accepts only in
// development mode (the e2e server's public URL is http://localhost). Production CIMD URLs must
// be https.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';
import { deleteTenant } from '../lib/email-code';
import {
  authorizationUrl,
  callMcp,
  checkCallback,
  discoverAuthorizationServer,
  discoverProtectedResource,
  exchangeCode,
  jwtClaims,
  pkcePair,
  setAgentPolicies,
  startCimdClient,
  startMockMcpServer,
  type CimdClient,
  type MockMcpServer,
} from '../lib/mcp';
import { createTenant, randomSlug, tenantIssuer } from '../lib/upstream';

const CLIENT_NAME = 'E2E MCP agent';
const SCOPE = 'openid profile';

test.describe.configure({ mode: 'serial' });

let token = '';
let slug = '';
let issuer = '';
let user = { email: '', password: '' };
let mcp: MockMcpServer | undefined;
let client: CimdClient | undefined;

test.beforeAll(async ({ browser }) => {
  token = await adminToken(await sharedManagementCredential(browser));
  slug = randomSlug('mcp');
  issuer = tenantIssuer(slug);
  await createTenant(token, slug);
  user = { email: randomEmail('mcp'), password: randomPassword() };
  await createUser(token, { ...user, email_verified: true }, slug);
  mcp = await startMockMcpServer({ issuer });
  const settings = await setAgentPolicies(token, slug, { cimd: 'open', allowedResources: [mcp.resource] });
  expect(settings.cimd.policy).toBe('open');
  expect(settings.dcr.allowed_resources).toEqual([mcp.resource]);
  client = await startCimdClient({ clientName: CLIENT_NAME, scope: SCOPE });
});

test.afterAll(async () => {
  await client?.stop();
  await mcp?.stop();
  if (slug && token) await deleteTenant(token, slug);
});

function state(): string {
  return randomBytes(16).toString('base64url');
}

test('an MCP client authorizes with a client ID metadata document and a resource indicator', async ({ page }) => {
  if (!mcp || !client) throw new Error('setup failed');

  // The MCP server's 401 points at its RFC 9728 document, which names the tenant issuer.
  const prm = await discoverProtectedResource(mcp.resource);
  expect(prm.metadataUrl).toBe(mcp.metadataUrl);
  expect(prm.authorizationServers).toEqual([issuer]);
  expect(mcp.requests.at(-1)).toEqual({ method: 'GET', status: 401, reason: 'missing' });

  // RFC 8414 path insertion answers first, with the tenant issuer and CIMD support.
  const as = await discoverAuthorizationServer(prm.authorizationServers[0]);
  expect(as.metadataUrl).toBe(`${anvilUrl()}/.well-known/oauth-authorization-server/t/${slug}`);
  expect(as.metadata.client_id_metadata_document_supported).toBe(true);
  expect(as.authorizationEndpoint).toBe(`${issuer}/authorize`);

  const { verifier, challenge } = pkcePair();
  const st = state();
  const seen = client.callbacks.length;
  await page.goto(
    authorizationUrl(as, {
      clientId: client.clientId,
      redirectUri: client.redirectUri,
      scope: SCOPE,
      resource: mcp.resource,
      state: st,
      challenge,
    }),
  );
  await expect(page.locator('#identifier')).toBeVisible();
  await login(page, user.email, user.password);

  // Consent: the client is named by its client_id host; its self-asserted name is unverified;
  // the MCP server is listed as the resource.
  await expect(page.locator('#consent-form')).toBeVisible();
  const host = new URL(client.clientId).host;
  await expect(page.locator('#consent-client')).toHaveText(host);
  await expect(page.locator('#consent-cimd')).toBeVisible();
  await expect(page.locator('#consent-client-name')).toContainText(CLIENT_NAME);
  await expect(page.locator('#consent-cimd-unverified')).toBeVisible();
  await expect(page.locator('#consent-resource-1')).toHaveAttribute('data-resource', mcp.resource);
  await expect(page.locator('img')).toHaveCount(0);
  await page.locator('#consent-allow').click();

  const callback = await client.waitForCallback(15_000, seen);
  await expect(page.locator('#mcp-callback')).toBeVisible();
  const code = checkCallback(callback, as, st);
  expect(callback.iss).toBe(issuer);
  expect(client.documentFetches()).toBeGreaterThanOrEqual(1);

  // Code exchange with the same resource: the access token's audience is the MCP server.
  const tokens = await exchangeCode(as, {
    code,
    verifier,
    clientId: client.clientId,
    redirectUri: client.redirectUri,
    resource: mcp.resource,
  });
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
  const accessToken = tokens.body.access_token;
  if (typeof accessToken !== 'string') throw new Error('no access_token');
  const claims = jwtClaims(accessToken);
  expect(claims.aud).toBe(mcp.resource);
  expect(claims.iss).toBe(issuer);
  expect(claims.client_id).toBe(client.clientId);

  // The MCP server verifies signature, iss, aud and exp and accepts the token.
  const ok = await callMcp(mcp.resource, accessToken);
  expect(ok.status, JSON.stringify(ok.body)).toBe(200);
  expect(ok.body).toMatchObject({ ok: true, client_id: client.clientId });

  // Another MCP server refuses it: its URL is not in aud.
  const other = await startMockMcpServer({ issuer });
  try {
    const refused = await callMcp(other.resource, accessToken);
    expect(refused.status).toBe(401);
    expect(refused.wwwAuthenticate).toContain('error="invalid_token"');
    expect(refused.wwwAuthenticate).toContain(`resource_metadata="${other.metadataUrl}"`);
    expect(other.requests.at(-1)?.reason).toBe('aud');
  } finally {
    await other.stop();
  }
});

test('with the tenant CIMD policy disabled the same client gets the error page, no redirect', async ({ page }) => {
  if (!mcp || !client) throw new Error('setup failed');
  const settings = await setAgentPolicies(token, slug, { cimd: 'disabled' });
  expect(settings.cimd.policy).toBe('disabled');

  const as = await discoverAuthorizationServer(issuer);
  expect(as.metadata.client_id_metadata_document_supported).toBeUndefined();

  const seen = client.callbacks.length;
  const fetches = client.documentFetches();
  const { challenge } = pkcePair();
  const response = await page.goto(
    authorizationUrl(as, {
      clientId: client.clientId,
      redirectUri: client.redirectUri,
      scope: SCOPE,
      resource: mcp.resource,
      state: state(),
      challenge,
    }),
  );
  expect(response?.status()).toBe(400);
  await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', 'unknown_client');
  expect(new URL(page.url()).origin).toBe(new URL(anvilUrl()).origin);
  expect(client.callbacks.length).toBe(seen);
  expect(client.documentFetches()).toBe(fetches);
});
