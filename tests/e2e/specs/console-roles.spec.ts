// ORG-05 from the console (05-24): an operator defines a role with permissions, assigns it to a
// user on the user page, maps the roles claim in Login settings, and the user's ID token carries
// the role. Removing the assignment works from the same page. Client-side permission syntax
// checks refuse bad input before anything is sent.
//
// The sample RP shows no tokens and requests a fixed scope, so the user signs in through the
// authorization-code client of lib/account.ts (signInForIdToken) with the `roles` scope added by
// lib/authorize.ts. Runs in a tenant of its own, deleted afterwards.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { signInForIdToken } from '../lib/account';
import { anvilUrl, createClient, createUser, login, randomEmail, randomPassword } from '../lib/anvil';
import { addAuthorizeParams } from '../lib/authorize';
import { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v04';
import { tenantIssuer } from '../lib/upstream';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

test('console: define a role, assign it, map the claim and see it in the ID token', async ({ page, browser }) => {
  test.setTimeout(120_000);
  tenant = await setUpConsoleTenant(browser, page, 'croles');
  const { token, slug } = tenant;

  await test.step('the Roles page is in the navigation and starts empty', async () => {
    await openTenantPage(page, slug, 'users');
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Roles' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/roles`);
    await expect(page.getByRole('heading', { level: 1, name: 'Roles' })).toBeVisible();
    await expect(page.getByText('No roles defined yet.')).toBeVisible();
    await expectNoA11yViolations(page);
  });

  await test.step('bad permission syntax is refused in the form', async () => {
    await page.getByTestId('new-role').click();
    await expect(page.getByRole('heading', { level: 1, name: 'New role' })).toBeVisible();
    await page.getByTestId('role-permission-input').fill('docs:read bad#perm');
    await page.getByTestId('role-permission-add').click();
    await expect(page.getByTestId('role-form')).toContainText('“bad#perm” is not a valid permission');
    await expect(page.getByTestId('role-permissions')).toHaveCount(0);
    // A bad name is refused before anything is sent.
    await page.getByTestId('role-name').fill('Editor!');
    await page.getByTestId('role-submit').click();
    await expect(page.getByTestId('role-form')).toContainText('starting with a letter or digit');
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/roles/new`);
  });

  await test.step('create the editor role with two permissions', async () => {
    await page.getByTestId('role-name').fill('editor');
    await page.getByLabel('Description').fill('Edits documents');
    await page.getByTestId('role-permission-input').fill('docs:write docs:read');
    await page.getByTestId('role-permission-input').press('Enter');
    const tags = page.getByTestId('role-permissions');
    await expect(tags).toContainText('docs:read');
    await expect(tags).toContainText('docs:write');
    await expectNoA11yViolations(page);
    await page.getByTestId('role-submit').click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/roles/editor`);
    await expect(page.getByRole('heading', { level: 1, name: 'editor' })).toBeVisible();
    await expect(page.getByText('No user holds this role.')).toBeVisible();
    await expectNoA11yViolations(page);
  });

  const email = randomEmail('croles-user');
  const password = randomPassword();
  const user = await createUser(token, { email, password, email_verified: true }, slug);
  if (!user.id) throw new Error('created user has no id');

  await test.step('assign the role on the user page', async () => {
    await openTenantPage(page, slug, `users/${user.id}`);
    await page.getByRole('tab', { name: 'Roles' }).click();
    await expect(page.getByText('No roles assigned.')).toBeVisible();
    await page.getByTestId('assign-role-select').selectOption('editor');
    await page.getByTestId('assign-role').click();
    await expect(page.getByRole('status').filter({ hasText: 'Role editor assigned.' })).toBeVisible();
    await expect(page.getByTestId('user-role-editor')).toContainText('docs:read docs:write');
    await expectNoA11yViolations(page);

    const res = await fetch(`${anvilUrl()}/api/admin/v1/tenants/${slug}/users/${user.id}/roles`, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
    });
    expect(res.status).toBe(200);
    const roles = (await res.json()) as { items: { name: string }[] };
    expect(roles.items.map((r) => r.name)).toEqual(['editor']);
  });

  await test.step('the role page lists the holder', async () => {
    await openTenantPage(page, slug, 'roles/editor');
    await expect(page.getByRole('link', { name: email })).toBeVisible();
  });

  await test.step('map roles into the app_roles claim in Login settings', async () => {
    await openTenantPage(page, slug, 'settings');
    const rule = page.getByTestId('claim-rule-roles');
    await expect(rule.getByLabel('Put roles into tokens')).toBeChecked();
    await rule.getByLabel('Claim name').fill('app_roles');
    await page.getByTestId('save-claim-mapping').click();
    await expect(page.getByTestId('claim-mapping-form').getByRole('status')).toHaveText('Token claims saved.');
    await expectNoA11yViolations(page);
  });

  await test.step('the user signs in and the ID token carries the role', async () => {
    const redirectUri = 'https://croles-rp.example.test/callback';
    const client = await createClient(
      token,
      {
        name: 'console roles RP',
        client_type: 'confidential',
        application_type: 'web',
        auth_method: 'client_secret_basic',
        redirect_uris: [redirectUri],
        grant_types: ['authorization_code'],
        scopes: ['openid', 'email', 'roles'],
      },
      slug,
    );
    const context = await browser.newContext();
    try {
      const userPage = await context.newPage();
      const issuer = tenantIssuer(slug);
      await addAuthorizeParams(userPage, { scope: 'openid email roles' }, issuer);
      const claims = await signInForIdToken(
        userPage,
        { client_id: client.client_id, client_secret: client.client_secret ?? '', redirect_uri: redirectUri },
        (p) => login(p, email, password),
        issuer,
      );
      expect(claims.app_roles).toEqual(['editor']);
      expect(claims).not.toHaveProperty('roles');
    } finally {
      await context.close();
    }
  });

  await test.step('remove the role from the user', async () => {
    await openTenantPage(page, slug, `users/${user.id}?tab=roles`);
    await page.getByRole('button', { name: 'Remove role editor' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Remove role?' });
    await dialog.getByRole('button', { name: 'Remove role' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Role editor removed.' })).toBeVisible();
    await expect(page.getByText('No roles assigned.')).toBeVisible();
  });
});
