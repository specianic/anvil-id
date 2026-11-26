// ADM-02 "keys" from the console (06-16): an operator opens a tenant's Signing keys page, rotates
// the RS256 key with "Activate immediately", sees the new kid active and the previous key retired,
// and the tenant's JWKS publishes the new kid (and no longer the old one). The page and the open
// rotate dialog pass the axe audit.
//
// Runs in a fresh tenant of its own, deleted afterwards, signed in as a console administrator
// created with createConsoleAdmin. The default tenant's keys are never rotated here (other specs and
// the sample RP depend on them); the spec checks they are unchanged.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  listTenantKeys,
  openSectionFromNav,
  openTenantPage,
  setUpConsoleTenant,
  tenantJwksKids,
  type ConsoleTenant,
} from '../lib/console-v10';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

test('console: rotate a tenant signing key immediately and see it in the JWKS', async ({ page, browser }) => {
  test.setTimeout(120_000);
  tenant = await setUpConsoleTenant(browser, page, 'ckeys');
  const { token, slug } = tenant;
  expect(slug).not.toBe('default');

  const defaultKeysBefore = await listTenantKeys(token, 'default');
  const keysBefore = await listTenantKeys(token, slug);
  const kidsBefore = new Set(keysBefore.map((k) => k.kid));
  // A tenant gets its RS256 key when it is created.
  const activeBefore = keysBefore.find((k) => k.alg === 'RS256' && k.state === 'active');
  if (!activeBefore) throw new Error(`tenant ${slug} has no active RS256 key: ${JSON.stringify(keysBefore)}`);

  await test.step('the Signing keys page is in the navigation and lists the tenant keys', async () => {
    await openTenantPage(page, slug, 'users');
    await openSectionFromNav(page, slug, 'Signing keys', 'keys');
    const table = page.getByRole('table', { name: 'Signing keys' });
    for (const key of keysBefore) {
      await expect(table.getByRole('row').filter({ hasText: key.kid })).toBeVisible();
    }
    await expect(
      table.getByRole('row').filter({ hasText: activeBefore.kid }).getByTestId('key-state'),
    ).toHaveText('Active');
    // Lifecycle data only: nothing that looks like key material is rendered.
    const html = await page.content();
    expect(html).not.toContain('PRIVATE KEY');
    expect(html).not.toMatch(/"(d|p|q|dp|dq|qi)"\s*:/);
    await expectNoA11yViolations(page);
  });

  await test.step('the rotate dialog offers the enabled algorithms and passes axe', async () => {
    await page.getByTestId('rotate-key').click();
    const dialog = page.getByRole('alertdialog', { name: 'Rotate signing key?' });
    await expect(dialog).toBeVisible();
    // A fresh tenant enables RS256 only.
    await expect(dialog.getByTestId('rotate-key-alg').locator('option')).toHaveText(['RS256']);
    await expect(dialog.getByTestId('rotate-key-immediate')).not.toBeChecked();
    await dialog.getByTestId('rotate-key-immediate').check();
    await expect(dialog).toContainText('tokens it signed stop verifying');
    await expectNoA11yViolations(page);
  });

  let newKid = '';
  await test.step('rotating immediately activates a new key and retires the old one', async () => {
    const dialog = page.getByRole('alertdialog', { name: 'Rotate signing key?' });
    await dialog.getByTestId('rotate-key-alg').selectOption('RS256');
    await dialog.getByRole('button', { name: 'Rotate key' }).click();
    await expect(dialog).toBeHidden();
    const status = page.getByRole('status').filter({ hasText: 'is active' });
    await expect(status).toBeVisible();

    const keysAfter = await listTenantKeys(token, slug);
    const fresh = keysAfter.filter((k) => !kidsBefore.has(k.kid));
    expect(fresh).toHaveLength(1);
    expect(fresh[0].alg).toBe('RS256');
    expect(fresh[0].state).toBe('active');
    newKid = fresh[0].kid;
    await expect(status).toContainText(newKid);

    const table = page.getByRole('table', { name: 'Signing keys' });
    await expect(table.getByRole('row').filter({ hasText: newKid }).getByTestId('key-state')).toHaveText('Active');
    await expect(
      table.getByRole('row').filter({ hasText: activeBefore.kid }).getByTestId('key-state'),
    ).toHaveText('Retired');
    await expectNoA11yViolations(page);
  });

  await test.step('the tenant JWKS publishes the new kid and drops the old one', async () => {
    const kids = await tenantJwksKids(slug);
    expect(kids).toContain(newKid);
    expect(kids).not.toContain(activeBefore.kid);
  });

  await test.step('the default tenant keys are untouched', async () => {
    expect(await listTenantKeys(token, 'default')).toEqual(defaultKeysBefore);
  });
});
