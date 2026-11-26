// ORG-01: the multi-tenant console (05-04). An admin of the system tenant reaches the tenant
// switcher by keyboard, lists the tenants (the system tenant is marked), creates a tenant from the
// console, switches between tenants (the section is kept), creates a client in the new tenant only,
// reads the tenant's issuer and discovery URL from the list and checks it against the published
// discovery document, checks that a pre-0.4 deep link shows the not-found page and deletes
// the tenant again. Every console page visited passes the axe audit and the console CSP holds.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { tenantSettings } from '../lib/admin';
import {
  adminToken,
  anvilUrl,
  createConsoleAdmin,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type AdminAccount,
} from '../lib/anvil';
import { consoleLogin, consoleUrl, expectConsoleHome, findInPagedTable } from '../lib/console';
import { randomSlug, tenantIssuer } from '../lib/upstream';

const slug = randomSlug('console');
let cleanupToken: string | undefined;

/** Status of an admin API GET (the console's own requests are checked through the UI). */
async function adminStatus(token: string, path: string): Promise<number> {
  const res = await fetch(`${anvilUrl()}/api/admin/v1${path}`, {
    headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
  });
  await res.body?.cancel();
  return res.status;
}

test.afterAll(async () => {
  if (!cleanupToken) return;
  // The test deletes the tenant itself; this only runs the deletion if it failed half way.
  const res = await fetch(`${anvilUrl()}/api/admin/v1/tenants/${slug}`, {
    method: 'DELETE',
    headers: { authorization: `Bearer ${cleanupToken}` },
  });
  await res.body?.cancel();
});

/** Collects CSP violations reported by the browser on this page. */
function watchCsp(page: Page): string[] {
  const violations: string[] = [];
  page.on('console', (msg) => {
    if (/Content[- ]Security[- ]Policy/i.test(msg.text())) violations.push(msg.text());
  });
  return violations;
}

test('admin console: create, switch to and delete a tenant', async ({ page, browser }) => {
  test.setTimeout(150_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  cleanupToken = token;
  const admin: AdminAccount = { email: randomEmail('tenants-admin'), password: randomPassword() };
  await createConsoleAdmin(token, admin);

  const csp = watchCsp(page);
  const switcher = page.getByLabel('Tenant', { exact: true });
  const mainNav = page.getByRole('navigation', { name: 'Main' });

  await test.step('sign in; the switcher shows the default tenant and is reachable by keyboard', async () => {
    await consoleLogin(page, admin);
    await expect(switcher).toHaveValue('default');
    await page.locator('body').click({ position: { x: 1, y: 1 } });
    let focused = false;
    for (let i = 0; i < 6 && !focused; i++) {
      await page.keyboard.press('Tab');
      focused = await switcher.evaluate((el) => el === document.activeElement);
    }
    expect(focused, 'the tenant switcher is reachable with Tab').toBe(true);
    await expectNoA11yViolations(page);
  });

  await test.step('tenant list: the system tenant is listed and marked', async () => {
    await page.getByTestId('all-tenants-link').click();
    await expect(page).toHaveURL((url) => url.pathname === '/console/tenants');
    await expect(page.getByRole('heading', { level: 1, name: 'Tenants' })).toBeVisible();
    const system = page.getByRole('row').filter({ has: page.getByRole('link', { name: 'system', exact: true }) });
    await findInPagedTable(page, system);
    await expect(system).toContainText('System');
    await expect(system.getByTestId('tenant-issuer-system')).toHaveText(tenantIssuer('system'));
    await expectNoA11yViolations(page);
  });

  await test.step('create a tenant: the slug is checked, then the console opens the new tenant', async () => {
    // Back to the first page of the list (findInPagedTable may have paged).
    await page.goto(consoleUrl('tenants'));
    await page.getByTestId('new-tenant').click();
    await expect(page).toHaveURL((url) => url.pathname === '/console/tenants/new');
    await expect(page.getByRole('heading', { level: 1, name: 'New tenant' })).toBeVisible();
    await expectNoA11yViolations(page);

    // One character is below the slug rule (2-63 of a-z, 0-9, '-'): refused before any request.
    await page.getByLabel('Slug').fill('a');
    await page.getByLabel('Display name').fill(`Console ${slug}`);
    await page.getByTestId('create-tenant').click();
    await expect(page.getByText('The tenant was not created. Fix the errors below.')).toBeVisible();
    await expect(page.getByLabel('Slug')).toHaveAttribute('aria-invalid', 'true');
    await expectNoA11yViolations(page);

    await page.getByLabel('Slug').fill(slug);
    await page.getByLabel('Registration').selectOption('invite_only');
    await page.getByTestId('create-tenant').click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/users`);
    await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible();
    await expect(switcher).toHaveValue(slug);
    expect((await tenantSettings(token, slug)).registration).toBe('invite_only');
    await expectNoA11yViolations(page);
  });

  await test.step('switching tenants keeps the section', async () => {
    await mainNav.getByRole('link', { name: 'Clients' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/clients`);
    await switcher.selectOption('default');
    await expect(page).toHaveURL((url) => url.pathname === '/console/t/default/clients');
    await expect(page.getByRole('heading', { level: 1, name: 'Clients' })).toBeVisible();
    await switcher.selectOption(slug);
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/clients`);
    await expect(page.getByText('No clients registered yet.')).toBeVisible();
  });

  await test.step('a client created in the new tenant exists only there', async () => {
    await page.getByRole('link', { name: 'New client' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/clients/new`);
    await page.getByLabel('Name', { exact: true }).fill(`e2e ${slug} client`);
    await page.getByLabel('Redirect URIs', { exact: true }).fill('https://rp.example.test/callback');
    await page.getByRole('button', { name: 'Create client' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Client created' })).toBeVisible();
    const clientId = ((await page.getByTestId('created-client-id').textContent()) ?? '').trim();
    expect(clientId).not.toBe('');
    expect(await adminStatus(token, `/tenants/${slug}/clients/${encodeURIComponent(clientId)}`)).toBe(200);
    expect(await adminStatus(token, `/tenants/default/clients/${encodeURIComponent(clientId)}`)).toBe(404);

    await page.getByRole('link', { name: 'Back to clients' }).click();
    await expect(page.getByRole('link', { name: clientId })).toBeVisible();
    await expectNoA11yViolations(page);
  });

  await test.step("the tenant list shows the tenant's own issuer and discovery URL", async () => {
    await page.getByTestId('all-tenants-link').click();
    const row = page.getByRole('row').filter({ has: page.getByRole('link', { name: slug, exact: true }) });
    await findInPagedTable(page, row);
    await expect(row).toContainText(`Console ${slug}`);
    const issuer = tenantIssuer(slug);
    await expect(row.getByTestId(`tenant-issuer-${slug}`)).toHaveText(issuer);
    const discovery = ((await row.getByTestId(`tenant-discovery-${slug}`).textContent()) ?? '').trim();
    expect(discovery).toBe(`${issuer}/.well-known/openid-configuration`);

    const res = await fetch(discovery, { headers: { accept: 'application/json' } });
    expect(res.status).toBe(200);
    const doc = (await res.json()) as { issuer?: string };
    expect(doc.issuer).toBe(issuer);
    expect(doc.issuer).not.toBe(tenantIssuer('default'));
    await expectNoA11yViolations(page);
  });

  await test.step('/console/ reopens the last used tenant; unknown tenants show a not-found panel', async () => {
    await page.goto(consoleUrl());
    await expectConsoleHome(page, slug);

    await page.goto(consoleUrl('t/no-such-tenant-e2e/users'));
    await expect(page.getByTestId('tenant-not-found')).toBeVisible();
    await expect(page.getByRole('heading', { level: 1, name: 'Tenant not found' })).toBeVisible();
    await expectNoA11yViolations(page);
  });

  await test.step('pre-0.4 deep links show the not-found page (removed in 1.0)', async () => {
    await page.goto(consoleUrl('clients'));
    await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();
    await expect(page).toHaveURL((url) => url.pathname === '/console/clients');

    await page.goto(consoleUrl('audit?action=session_revoked'));
    await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();

    // The default tenant cannot be deleted; its settings page says so.
    await page.goto(consoleUrl('t/default/settings'));
    await expect(page.getByTestId('tenant-undeletable')).toBeVisible();
    await expect(page.getByTestId('delete-tenant')).toHaveCount(0);
  });

  await test.step('delete the tenant from its settings page', async () => {
    await switcher.selectOption(slug);
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/settings`);
    await page.getByTestId('delete-tenant').click();
    const dialog = page.getByRole('alertdialog', { name: 'Delete this tenant?' });
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Delete tenant' }).click();
    await expect(page).toHaveURL((url) => url.pathname === '/console/tenants');
    await expect(page.getByRole('heading', { level: 1, name: 'Tenants' })).toBeVisible();

    expect(await adminStatus(token, `/tenants/${slug}`)).toBe(404);
    const res = await fetch(`${tenantIssuer(slug)}/.well-known/openid-configuration`);
    await res.body?.cancel();
    expect(res.status).toBe(404);
    await expect(switcher.locator(`option[value="${slug}"]`)).toHaveCount(0);

    // The deleted tenant is no longer remembered: /console/ opens the default tenant.
    await page.goto(consoleUrl());
    await expectConsoleHome(page);
  });

  expect(csp, 'CSP violations in the console').toEqual([]);
});
