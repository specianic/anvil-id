// Roles and permissions in tokens (ORG-05, plan 05-12): roles defined and assigned through the
// admin API reach the relying party through the tenant's default claim mapping (`roles` in every
// token when the `roles` scope is granted, `permissions` in the access token only), and a role
// change shows up at the next refresh.
//
// The test runs in a tenant of its own, deleted afterwards. The sample RP shows no tokens, so the
// authorization-code client of lib/code-flow.ts reads the token response directly.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import {
  adminToken,
  createClient,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { adminCall, tenantPath } from '../lib/admin-api';
import { authorizationCodeFlow, jwtClaims, refreshTokens, type CodeFlowClient } from '../lib/code-flow';
import { deleteTenant } from '../lib/email-code';
import { createTenant, randomSlug, tenantIssuer } from '../lib/upstream';

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
});

const REDIRECT_URI = 'https://rbac-rp.example.test/callback';

test('roles and permissions reach the tokens and follow role changes on refresh', async ({ page }) => {
  const token = await adminToken(creds);
  const slug = randomSlug('rbac');
  await createTenant(token, slug);
  try {
    await adminCall(
      token,
      'POST',
      tenantPath(slug, '/roles'),
      { name: 'editor', description: 'Edits documents', permissions: ['docs:write', 'docs:read'] },
      201,
    );
    await adminCall(
      token,
      'POST',
      tenantPath(slug, '/roles'),
      { name: 'viewer', description: 'Reads documents', permissions: ['docs:read'] },
      201,
    );

    const email = randomEmail('rbac');
    const password = randomPassword();
    const user = await createUser(token, { email, password, email_verified: true }, slug);
    if (!user.id) throw new Error('created user has no id');
    const roleOf = (role: string) => tenantPath(slug, `/users/${user.id}/roles/${role}`);
    await adminCall(token, 'PUT', roleOf('editor'));

    const created = await createClient(
      token,
      {
        name: 'rbac RP',
        client_type: 'confidential',
        application_type: 'web',
        auth_method: 'client_secret_basic',
        redirect_uris: [REDIRECT_URI],
        grant_types: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'email', 'roles'],
      },
      slug,
    );
    if (!created.client_secret) throw new Error('client created without a secret');
    const client: CodeFlowClient = {
      client_id: created.client_id,
      client_secret: created.client_secret,
      redirect_uri: REDIRECT_URI,
    };
    const issuer = tenantIssuer(slug);

    // With the `roles` scope: roles in the access and ID tokens, permissions in the access token.
    const tokens = await authorizationCodeFlow(
      page,
      client,
      'openid email roles',
      (p) => login(p, email, password),
      issuer,
    );
    const at = jwtClaims(tokens.access_token);
    expect(at.roles).toEqual(['editor']);
    expect(at.permissions).toEqual(['docs:read', 'docs:write']);
    if (!tokens.id_token) throw new Error('no id_token');
    const id = jwtClaims(tokens.id_token);
    expect(id.roles).toEqual(['editor']);
    expect(id).not.toHaveProperty('permissions');
    if (!tokens.refresh_token) throw new Error('no refresh_token');

    // A role change is reflected at the next refresh.
    await adminCall(token, 'PUT', roleOf('viewer'));
    await adminCall(token, 'DELETE', roleOf('editor'), undefined, 204);
    const refreshed = await refreshTokens(client, tokens.refresh_token, issuer);
    const at2 = jwtClaims(refreshed.access_token);
    expect(at2.roles).toEqual(['viewer']);
    expect(at2.permissions).toEqual(['docs:read']);
    if (refreshed.id_token) expect(jwtClaims(refreshed.id_token).roles).toEqual(['viewer']);

    // Without the `roles` scope (same browser session): no roles claim, permissions still mapped.
    const withoutRoles = await authorizationCodeFlow(page, client, 'openid email', async () => {}, issuer);
    const at3 = jwtClaims(withoutRoles.access_token);
    expect(at3).not.toHaveProperty('roles');
    expect(at3.permissions).toEqual(['docs:read']);
    if (withoutRoles.id_token) expect(jwtClaims(withoutRoles.id_token)).not.toHaveProperty('roles');
  } finally {
    await deleteTenant(token, slug);
  }
});
