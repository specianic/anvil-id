// C-M8 (07.1-15): a readable audit log. The action filter lists labelled actions grouped by area
// (optgroups from lib/audit-labels.ts); cells show the label with the raw action name; actors and
// targets resolve to the administrator's email, the user's email or the client's name, each linked
// to its page. Ids that do not resolve stay shortened, with the full id and a copy button in the
// event details.
//
// Runs in a tenant of its own, deleted afterwards. After consoleLogin the spec opens pages by URL
// and never asserts the console's landing page.
//
// Console test ids (admin-ui, 07.1-15): `audit-action-filter`, `audit-ref` (`data-resolved`),
// `audit-details`.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { createUser, findUserByEmail, randomEmail, randomPassword } from '../lib/anvil';
import { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v10';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

test('console: audit log with grouped action labels and resolved actors and targets', async ({ page, browser }) => {
  test.setTimeout(120_000);
  tenant = await setUpConsoleTenant(browser, page, 'caud');
  const { token, slug, admin } = tenant;
  const consoleCreated = randomEmail('aud-console');
  const apiCreated = randomEmail('aud-api');

  await test.step('generate events: one user created in the console, one through the API', async () => {
    await openTenantPage(page, slug, 'users');
    await page.getByTestId('create-user').click();
    const dialog = page.getByRole('dialog', { name: 'Create user' });
    await dialog.getByTestId('user-form-email').fill(consoleCreated);
    await dialog.getByTestId('user-form-password').fill(randomPassword());
    await dialog.getByTestId('user-form-save').click();
    await expect(page.getByTestId('user-created-status')).toContainText(consoleCreated);
    await createUser(token, { email: apiCreated, password: randomPassword() }, slug);
  });

  await test.step('the action filter shows grouped, labelled actions', async () => {
    await openTenantPage(page, slug, 'audit');
    await expect(page.getByRole('heading', { level: 1, name: 'Audit log' })).toBeVisible();
    const filter = page.getByTestId('audit-action-filter');
    const groups = await filter.locator('optgroup').evaluateAll((els) => els.map((e) => e.getAttribute('label')));
    expect(groups).toEqual(['Sign-in', 'Users', 'Clients', 'Connections', 'Organizations', 'Settings', 'Keys', 'Webhooks', 'System']);
    await expect(filter.locator('optgroup[label="Users"] option[value="user_created"]')).toHaveText('User created');
    await expect(filter.locator('optgroup[label="Users"] option[value="user_deleted"]')).toHaveText('User deleted');
    await expect(filter.locator('optgroup[label="Keys"] option[value="key_generated"]')).toHaveText('Signing key generated');
    await filter.selectOption({ label: 'User created' });
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(page).toHaveURL((url) => url.searchParams.get('action') === 'user_created');
  });

  const consoleUser = await findUserByEmail(token, consoleCreated, slug);
  const apiUser = await findUserByEmail(token, apiCreated, slug);
  const me = await findUserByEmail(token, admin.email, 'system');
  if (!consoleUser || !apiUser || !me) throw new Error('users of the audit spec not found');

  await test.step('a console change shows the administrator email and the target user, linked', async () => {
    const row = page.getByRole('row').filter({ hasText: consoleCreated });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText('User created');
    await expect(row).toContainText('user_created');
    const actor = row.getByRole('link', { name: admin.email });
    await expect(actor).toHaveAttribute('href', `/console/t/system/users/${me.id}`);
    const target = row.getByRole('link', { name: consoleCreated });
    await expect(target).toHaveAttribute('href', `/console/t/${slug}/users/${consoleUser.id}`);
    await expectNoA11yViolations(page);
  });

  await test.step('an API change names the management client, linked to its page', async () => {
    const row = page.getByRole('row').filter({ hasText: apiCreated });
    await expect(row).toHaveCount(1);
    await expect(row.locator('[data-testid="audit-ref"][data-resolved="true"]').first().getByRole('link')).toHaveAttribute(
      'href',
      /^\/console\/t\/system\/clients\//,
    );
  });

  await test.step('the details show full ids with copy buttons', async () => {
    const row = page.getByRole('row').filter({ hasText: consoleCreated });
    await row.getByRole('button', { name: /^Details of User created/ }).click();
    const details = page.getByRole('dialog', { name: 'Audit event' });
    await expect(details.getByLabel('Target id', { exact: true })).toHaveValue(consoleUser.id);
    await expect(details.getByLabel('Actor id', { exact: true })).toHaveValue(me.id);
    await expect(details.getByRole('button', { name: 'Copy Target id' })).toBeVisible();
    await expectNoA11yViolations(page);
    await details.getByRole('button', { name: 'Close' }).click();
  });
});
