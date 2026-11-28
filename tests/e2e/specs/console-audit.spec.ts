// C-M8 (07.1-15): a readable audit log. The action filter lists labelled actions grouped by area
// (optgroups from lib/audit-labels.ts); cells show the label with the raw action name; actors and
// targets resolve to the administrator's email, the user's email or the client's name, each linked
// to its page. Ids that do not resolve stay shortened, with the full id and a copy button in the
// event details. The lookups are paced (started at least 100 ms apart) and each unique id is
// fetched once, so a page of events does not burst past the admin API rate limit.
//
// Runs in a tenant of its own, deleted afterwards. After consoleLogin the spec opens pages by URL
// and never asserts the console's landing page.
//
// Console test ids (admin-ui, 07.1-15): `audit-action-filter`, `audit-ref` (`data-resolved`),
// `audit-details`.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Request } from '@playwright/test';
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
  // Every actor/target lookup the console starts (GET users/{id} or clients/{id}).
  const lookups: Request[] = [];
  page.on('request', (req) => {
    if (/\/api\/admin\/v1\/tenants\/[^/]+\/(users|clients)\/[^/?]+$/.test(new URL(req.url()).pathname)) {
      lookups.push(req);
    }
  });
  const consoleCreated = randomEmail('aud-console');
  const apiCreated = randomEmail('aud-api');
  let apiUserId: string | undefined;

  await test.step('generate events: one user created in the console, one through the API', async () => {
    await openTenantPage(page, slug, 'users');
    await page.getByTestId('create-user').click();
    const dialog = page.getByRole('dialog', { name: 'Create user' });
    await dialog.getByTestId('user-form-email').fill(consoleCreated);
    await dialog.getByTestId('user-form-password').fill(randomPassword());
    await dialog.getByTestId('user-form-save').click();
    await expect(page.getByTestId('user-created-status')).toContainText(consoleCreated);
    apiUserId = (await createUser(token, { email: apiCreated, password: randomPassword() }, slug)).id;
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

  let me: { id: string } | undefined;
  let consoleUserId = '';
  await test.step('a console change shows the administrator email and the target user, linked', async () => {
    const row = page.getByRole('row').filter({ hasText: consoleCreated });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText('User created');
    await expect(row).toContainText('user_created');
    const actor = row.getByRole('link', { name: admin.email });
    await expect(actor).toBeVisible();
    const consoleUser = await findUserByEmail(token, consoleCreated, slug);
    me = await findUserByEmail(token, admin.email, 'system');
    if (!consoleUser || !me || !apiUserId) throw new Error('users of the audit spec not found');
    consoleUserId = consoleUser.id;
    await expect(actor).toHaveAttribute('href', `/console/t/system/users/${me.id}`);
    const target = row.getByRole('link', { name: consoleCreated });
    await expect(target).toHaveAttribute('href', `/console/t/${slug}/users/${consoleUserId}`);
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
    await expect(details.getByLabel('Target id', { exact: true })).toHaveValue(consoleUserId);
    await expect(details.getByLabel('Actor id', { exact: true })).toHaveValue(me!.id);
    await expect(details.getByRole('button', { name: 'Copy Target id' })).toBeVisible();
    await expectNoA11yViolations(page);
    await details.getByRole('button', { name: 'Close' }).click();
  });

  await test.step('lookups are paced under the rate limit and each id is fetched once', async () => {
    expect(lookups.length).toBeGreaterThan(0);
    // The console schedules lookups 100 ms apart (at most 10/s, half of the default admin limit).
    // A burst would start them within a few ms of each other; the margin covers the async work
    // (access token) between a lookup's scheduled time and its network start.
    const starts = await Promise.all(
      lookups.map(async (req) => {
        await req.response();
        return req.timing().startTime;
      }),
    );
    starts.sort((a, b) => a - b);
    for (let i = 1; i < starts.length; i += 1) {
      expect(starts[i] - starts[i - 1], 'gap between lookup starts (ms)').toBeGreaterThanOrEqual(50);
    }
    // An id is requested again only after a 429 (retried after a pause), never after an answer.
    const answered = new Set<string>();
    for (const req of lookups) {
      expect(answered.has(req.url()), `${req.url()} looked up again`).toBe(false);
      if ((await req.response())?.status() !== 429) answered.add(req.url());
    }
  });
});
