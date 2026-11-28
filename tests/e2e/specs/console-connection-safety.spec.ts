// Upstream connection safety in the console (07.1-09, C-H6, C-M11, C-M12): a new connection is
// saved disabled, so an incomplete one never puts a "Continue with ..." button on the sign-in page;
// the redirect URI ({issuer}/ui/login/upstream/{slug}/callback) is shown before saving and equals the
// saved connection's URI; the slug follows the display name until edited; enabling a connection
// without its client secret shows the server's refusal; leaving the dirty form asks first.
//
// Runs in a fresh tenant of its own (deleted afterwards), signed in as a console administrator. No
// provider is contacted: the server refuses to enable before any discovery fetch when the secret is
// missing.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v10';
import { listConnections, tenantIssuer } from '../lib/upstream';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

function leaveDialog(page: Page) {
  return page.getByRole('alertdialog', { name: 'Leave without saving?' });
}

/** Opens the new-connection form for a generic OpenID Connect provider. */
async function openNewOidcForm(page: Page, tenantSlug: string) {
  await openTenantPage(page, tenantSlug, 'connections/new');
  await expect(page.getByRole('heading', { level: 1, name: 'New connection' })).toBeVisible();
  await page.getByTestId('connection-kind-oidc').check();
  const form = page.getByTestId('connection-form');
  await expect(form).toBeVisible();
  return form;
}

test('console: connections start disabled, show the redirect URI first and refuse to enable while incomplete', async ({
  page,
  browser,
}) => {
  test.setTimeout(150_000);
  tenant = await setUpConsoleTenant(browser, page, 'cconnsafe');
  const { token, slug: tenantSlug } = tenant;
  const suffix = randomBytes(3).toString('hex');
  const displayName = `Acme Corp ${suffix} SSO`;
  const expectedSlug = `acme-corp-${suffix}-sso`;
  const expectedUri = `${tenantIssuer(tenantSlug)}/ui/login/upstream/${expectedSlug}/callback`;

  await test.step('the slug follows the display name until it is edited', async () => {
    const form = await openNewOidcForm(page, tenantSlug);
    const name = form.getByLabel('Display name');
    const slugField = form.getByLabel('Slug');
    await name.fill('Globex Login');
    await expect(slugField).toHaveValue('globex-login');
    await slugField.fill('my-own-slug');
    await name.fill('Globex Login Renamed');
    await expect(slugField).toHaveValue('my-own-slug');
    // Clearing the slug hands it back to the name.
    await slugField.fill('');
    await name.fill(displayName);
    await expect(slugField).toHaveValue(expectedSlug);
  });

  await test.step('the redirect URI is visible before saving and the connection starts disabled', async () => {
    const form = page.getByTestId('connection-form');
    await expect(form.getByLabel('Enabled', { exact: true })).not.toBeChecked();
    await expect(form.getByText('Turn on after you registered the redirect URI at the provider.')).toBeVisible();
    await expect(form.getByLabel('Redirect URI', { exact: true })).toHaveValue(expectedUri);
    await expectNoA11yViolations(page);
  });

  await test.step('leaving the dirty form asks first', async () => {
    await page.getByRole('link', { name: '← Connections' }).click();
    const dialog = leaveDialog(page);
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Stay' }).click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByTestId('connection-form').getByLabel('Display name')).toHaveValue(displayName);
  });

  await test.step('save without a client secret: created disabled with the same redirect URI', async () => {
    const form = page.getByTestId('connection-form');
    await form.getByLabel('Issuer').fill('https://idp.example.test');
    await form.getByLabel('Client ID').fill('e2e-oidc-client');
    await page.getByTestId('connection-submit').click();
    await expect(page.getByRole('heading', { level: 1, name: displayName })).toBeVisible();
    // No unsaved-changes prompt after a successful save.
    await expect(leaveDialog(page)).toHaveCount(0);
    await expect(page.getByTestId('connection-redirect-uri')).toHaveText(expectedUri);
    await expect(page.getByTestId('redirect-uri-mismatch')).toHaveCount(0);
    await expect(page.getByTestId('connection-status-badges')).toContainText('Disabled');
    await expect(page.getByTestId('connection-status-badges')).toContainText('Incomplete');
    const stored = (await listConnections(token, tenantSlug)).find((c) => c.slug === expectedSlug);
    expect(stored?.enabled).toBe(false);
    expect(stored?.secret_configured).toBe(false);
    await expectNoA11yViolations(page);
  });

  await test.step('enabling without the client secret shows the server\'s reason', async () => {
    await page.getByTestId('enable-connection').click();
    const refusal = page.getByTestId('enable-connection-error');
    await expect(refusal).toBeVisible();
    await expect(refusal).toContainText('Client secret');
    await expect(refusal).toContainText('a client secret is required before the connection can be enabled');
    await expect(page.getByTestId('connection-enabled-status')).toContainText('Disabled.');
    expect((await listConnections(token, tenantSlug)).find((c) => c.slug === expectedSlug)?.enabled).toBe(false);
    await expectNoA11yViolations(page);
  });

  await test.step('the sign-in page does not offer the incomplete connection', async () => {
    await page.goto(`${tenantIssuer(tenantSlug)}/ui/login`);
    await expect(page.locator('form').first()).toBeVisible();
    await expect(page.getByText(`Continue with ${displayName}`)).toHaveCount(0);
    await expect(page.locator(`#upstream-${expectedSlug}`)).toHaveCount(0);
  });

  await test.step('the list shows the connection as disabled and incomplete', async () => {
    await openTenantPage(page, tenantSlug, 'connections');
    const row = page.getByRole('row').filter({ has: page.getByRole('link', { name: displayName }) });
    await expect(row).toBeVisible();
    await expect(row).toContainText('Disabled');
    await expect(row).toContainText('Incomplete');
    await expectNoA11yViolations(page);
  });
});
