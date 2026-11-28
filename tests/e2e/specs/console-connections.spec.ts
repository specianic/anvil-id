// AUTH-07, ADM-04: managing an upstream connection in the admin console (/console/t/{tenant}/connections).
// A console administrator creates a Google connection with a client secret, sees the secret as
// "Configured" and the redirect URI to register at the provider, enables the connection (new
// connections are saved disabled, 07.1-09), edits the display name, rotates
// the secret, removes it (status "Not set"), sets it again and deletes the connection. The secret
// is write-only: it never appears on a console page nor in any admin API response the console
// receives. The secret card is the shared SecretRotation component (06-29), the same one the org
// connections panel uses. Every console page visited passes the axe WCAG 2.2 AA audit.
//
// Runs in a fresh tenant of its own (deleted afterwards), signed in as a console administrator
// created with createConsoleAdmin. No provider is contacted: a connection is only configuration
// until someone signs in with it.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v10';
import { listConnections, tenantIssuer } from '../lib/upstream';

const slug = `google-${randomBytes(4).toString('hex')}`;
let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
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
  tenant = await setUpConsoleTenant(browser, page, 'cconn');
  const { token: tok, slug: tenantSlug } = tenant;
  expect(tenantSlug).not.toBe('default');
  const base = `/console/t/${tenantSlug}/connections`;

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

  await test.step('open the tenant\'s Connections', async () => {
    await openTenantPage(page, tenantSlug, 'connections');
    await expect(page).toHaveURL((url) => url.pathname === base);
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
    await expect(page).toHaveURL((url) => url.pathname.startsWith(`${base}/`) && !url.pathname.endsWith('/new'));
    await expect(page.getByRole('heading', { level: 1, name: displayName })).toBeVisible();
    await expect(page.getByTestId('connection-redirect-uri')).toHaveText(
      `${tenantIssuer(tenantSlug)}/ui/login/upstream/${slug}/callback`,
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

  await test.step('the new connection is disabled until it is enabled', async () => {
    // Created disabled (07.1-09): register the redirect URI at the provider first, then enable.
    await expect(page.getByTestId('connection-status-badges')).toContainText('Disabled');
    expect((await listConnections(tok, tenantSlug)).find((c) => c.slug === slug)?.enabled).toBe(false);
    await page.getByTestId('enable-connection').click();
    await expect(page.getByText('Connection enabled.')).toBeVisible();
    await expect(page.getByTestId('connection-status-badges')).toContainText('Enabled');
    expect((await listConnections(tok, tenantSlug)).find((c) => c.slug === slug)?.enabled).toBe(true);
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

  await test.step('remove the secret after confirming, then set it again', async () => {
    await page.getByRole('button', { name: 'Remove secret' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Remove the client secret?' });
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Remove secret' }).click();
    await expect(dialog).toHaveCount(0);
    const rotate = page.getByRole('form', { name: 'Rotate secret' });
    await expect(rotate.getByRole('status')).toHaveText('Secret removed.');
    await expect(page.getByTestId('connection-secret-status')).toContainText('Not set');
    await expect(page.getByRole('button', { name: 'Remove secret' })).toHaveCount(0);
    expect((await listConnections(tok, tenantSlug)).find((c) => c.slug === slug)?.secret_configured).toBe(false);

    await page.getByLabel('New client secret').fill(rotated);
    await page.getByTestId('rotate-connection-secret').click();
    await expect(rotate.getByRole('status')).toHaveText('Secret saved.');
    await expect(page.getByTestId('connection-secret-status')).toContainText('Configured');
    await expectSecretsHidden();
  });

  await test.step('the list shows the renamed connection with a configured secret', async () => {
    await page.getByRole('link', { name: '← Connections' }).click();
    await expect(page).toHaveURL((url) => url.pathname === base);
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
    await expect(page).toHaveURL((url) => url.pathname === base);
    await expect(page.getByRole('table')).toHaveAttribute('aria-busy', 'false');
    await expect(page.getByRole('link', { name: renamed })).toHaveCount(0);
    expect((await listConnections(tok, tenantSlug)).some((c) => c.slug === slug)).toBe(false);
  });

  // No admin API response carried either secret.
  expect(responses.length).toBeGreaterThan(0);
  for (const body of responses) {
    expect(body).not.toContain(secret);
    expect(body).not.toContain(rotated);
  }
});
