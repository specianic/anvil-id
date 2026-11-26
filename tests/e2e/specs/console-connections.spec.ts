// AUTH-07, ADM-04: managing an upstream connection in the admin console (/console/t/default/connections).
// An admin of the system tenant creates a Google connection with a client secret, sees the secret
// as "Configured" and the redirect URI to register at the provider, edits the display name,
// rotates the secret and deletes the connection. The secret is write-only: it never appears on a
// console page nor in any admin API response the console receives. Every console page visited
// passes the axe WCAG 2.2 AA audit (console spec precedent: console.spec.ts).
//
// The connection is created in the default tenant (/console/t/default/...), so it briefly exists there; it is deleted
// at the end of the test (and in afterAll if the test fails half way). No provider is contacted:
// a connection is only configuration until someone signs in with it.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createUser,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type AdminAccount,
} from '../lib/anvil';
import { consoleLogin } from '../lib/console';
import { deleteConnection, listConnections } from '../lib/upstream';

const slug = `google-${randomBytes(4).toString('hex')}`;
let cleanupToken: string | undefined;

test.afterAll(async () => {
  if (!cleanupToken) return;
  for (const c of await listConnections(cleanupToken, 'default')) {
    if (c.slug === slug && typeof c.id === 'string') await deleteConnection(cleanupToken, 'default', c.id);
  }
});

/** Records every admin API response body the console receives, to prove secrets never come back. */
function recordAdminResponses(page: Page): string[] {
  const bodies: string[] = [];
  page.on('response', async (resp) => {
    if (!new URL(resp.url()).pathname.startsWith('/api/admin/')) return;
    try {
      bodies.push(await resp.text());
    } catch {
      // Body not available (redirect or aborted request).
    }
  });
  return bodies;
}

test('admin console: create, edit, rotate and delete a connection', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const tok = await adminToken(await sharedManagementCredential(browser));
  cleanupToken = tok;
  const admin: AdminAccount = { email: randomEmail('conn-admin'), password: randomPassword() };
  await createUser(tok, { ...admin, email_verified: true }, 'system');

  const secret = `e2e-first-${randomBytes(18).toString('base64url')}`;
  const rotated = `e2e-rotated-${randomBytes(18).toString('base64url')}`;
  const displayName = `Google ${slug}`;
  const renamed = `Google (renamed) ${slug}`;
  const responses = recordAdminResponses(page);

  const expectSecretsHidden = async () => {
    const html = await page.content();
    expect(html).not.toContain(secret);
    expect(html).not.toContain(rotated);
  };

  await test.step('sign in and open Connections', async () => {
    await consoleLogin(page, admin);
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Connections' }).click();
    await expect(page).toHaveURL((url) => url.pathname === '/console/t/default/connections');
    await expect(page.getByRole('heading', { level: 1, name: 'Connections' })).toBeVisible();
    await expect(page.getByRole('table')).toHaveAttribute('aria-busy', 'false');
    await expectNoA11yViolations(page);
  });

  await test.step('create a Google connection with a secret', async () => {
    await page.getByTestId('new-connection').click();
    await expect(page.getByRole('heading', { level: 1, name: 'New connection' })).toBeVisible();
    await expect(page.getByTestId('connection-kind-picker')).toBeVisible();
    await page.getByTestId('connection-kind-google').check();
    const form = page.getByTestId('connection-form');
    await expect(form).toBeVisible();
    await expectNoA11yViolations(page);

    await form.getByLabel('Display name').fill(displayName);
    await form.getByLabel('Slug').fill(slug);
    await form.getByLabel('Client ID').fill('e2e-client.apps.example.test');
    const secretInput = form.getByTestId('connection-secret-input');
    await expect(secretInput).toHaveAttribute('type', 'password');
    await secretInput.fill(secret);
    await page.getByTestId('connection-submit').click();
  });

  await test.step('the connection page shows the redirect URI and a configured secret', async () => {
    await expect(page).toHaveURL((url) => url.pathname.startsWith('/console/t/default/connections/') && !url.pathname.endsWith('/new'));
    await expect(page.getByRole('heading', { level: 1, name: displayName })).toBeVisible();
    await expect(page.getByTestId('connection-redirect-uri')).toHaveText(
      `${anvilUrl()}/ui/login/upstream/${slug}/callback`,
    );
    await expect(page.getByTestId('copy-redirect-uri')).toBeVisible();
    await expect(page.getByTestId('connection-secret-status')).toContainText('Configured');
    // The edit form has no secret field and the slug is fixed.
    const form = page.getByTestId('connection-form');
    await expect(form.getByLabel('Slug')).toBeDisabled();
    await expect(form.getByTestId('connection-secret-input')).toHaveCount(0);
    // The rotate field starts empty.
    await expect(page.getByLabel('New client secret')).toHaveValue('');
    await expectSecretsHidden();
    await expectNoA11yViolations(page);
  });

  await test.step('edit the display name', async () => {
    const form = page.getByTestId('connection-form');
    await form.getByLabel('Display name').fill(renamed);
    await form.getByRole('button', { name: 'Save changes' }).click();
    await expect(form.getByRole('status')).toHaveText('Connection saved.');
    await expect(page.getByRole('heading', { level: 1, name: renamed })).toBeVisible();
    await expect(page.getByTestId('connection-secret-status')).toContainText('Configured');
  });

  await test.step('rotate the secret', async () => {
    await page.getByLabel('New client secret').fill(rotated);
    await page.getByTestId('rotate-connection-secret').click();
    const rotate = page.getByRole('form', { name: 'Rotate secret' });
    await expect(rotate.getByRole('status')).toHaveText('Secret saved.');
    await expect(page.getByLabel('New client secret')).toHaveValue('');
    await expect(page.getByTestId('connection-secret-status')).toContainText('Configured');
    await expectSecretsHidden();
    await expectNoA11yViolations(page);
  });

  await test.step('the list shows the renamed connection with a configured secret', async () => {
    await page.getByRole('link', { name: '← Connections' }).click();
    await expect(page).toHaveURL((url) => url.pathname === '/console/t/default/connections');
    const row = page.getByRole('row').filter({ has: page.getByRole('link', { name: renamed }) });
    await expect(row).toBeVisible();
    await expect(row).toContainText(slug);
    await expect(row).toContainText('Configured');
    await expectSecretsHidden();
    await row.getByRole('link', { name: renamed }).click();
    await expect(page.getByRole('heading', { level: 1, name: renamed })).toBeVisible();
  });

  await test.step('delete the connection', async () => {
    await page.getByTestId('delete-connection').click();
    const dialog = page.getByRole('alertdialog', { name: 'Delete this connection?' });
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Delete connection' }).click();
    await expect(page).toHaveURL((url) => url.pathname === '/console/t/default/connections');
    await expect(page.getByRole('table')).toHaveAttribute('aria-busy', 'false');
    await expect(page.getByRole('link', { name: renamed })).toHaveCount(0);
    expect((await listConnections(tok, 'default')).some((c) => c.slug === slug)).toBe(false);
  });

  // No admin API response carried either secret.
  expect(responses.length).toBeGreaterThan(0);
  for (const body of responses) {
    expect(body).not.toContain(secret);
    expect(body).not.toContain(rotated);
  }
});
