// ADM-04, AUTH-10, UI-07: the admin console (/console/, embedded in the tested release binary) end
// to end. An admin of the system tenant signs in with authorization code + PKCE as anvil-console,
// reviews users, revokes a user's session (the relying party's next refresh fails), finds the
// session_revoked event in the audit log, creates an opaque client (its secret shown once, then
// rotated), edits an email template (line-numbered validation error, customized badge, reset),
// sends an SMTP test email to Mailpit and signs out. Every console page passes the axe audit, and nothing violates the console's CSP
// (script-src 'self'; style-src 'self').
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createConsoleAdmin,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type AdminAccount,
} from '../lib/anvil';
import { consoleLogin, consoleUrl, findInPagedTable, startSampleRp, type SampleRp } from '../lib/console';
import { takeOneTimeSecret } from '../lib/console-v04';
import { latestMessageTo } from '../lib/mailpit';

let rp: SampleRp | undefined;

test.afterAll(async () => {
  await rp?.stop();
});

/** Collects CSP violations reported by the browser on this page. */
function watchCsp(page: Page): string[] {
  const violations: string[] = [];
  page.on('console', (msg) => {
    if (/Content[- ]Security[- ]Policy/i.test(msg.text())) violations.push(msg.text());
  });
  return violations;
}

test('admin console: users, sessions, audit, clients, email and SMTP', async ({ page, browser }) => {
  test.setTimeout(180_000);
  const creds = await sharedManagementCredential(browser);
  const token = await adminToken(creds);

  // Admins are users of the system tenant holding the administrator role.
  const admin: AdminAccount = { email: randomEmail('console-admin'), password: randomPassword() };
  await createConsoleAdmin(token, admin);

  // A default-tenant user signed in at a relying party in a separate browser context.
  const userEmail = randomEmail('console-user');
  const userPassword = randomPassword();
  const user = await createUser(token, { email: userEmail, password: userPassword, email_verified: true });
  const userId = user.id ?? '';
  expect(userId).not.toBe('');
  rp = await startSampleRp(token, 'e2e console sample RP');
  const rpContext = await browser.newContext();
  const rpPage = await rpContext.newPage();
  await rpPage.goto(`${rp.base}/login`);
  await login(rpPage, userEmail, userPassword);
  await expect(rpPage).toHaveURL(`${rp.base}/me`);
  await expect(rpPage.locator('#sub')).toHaveText(userId);

  const csp = watchCsp(page);

  await test.step('sign in through the system tenant login page', async () => {
    await consoleLogin(page, admin);
    // Tokens stay in this tab's sessionStorage; nothing in localStorage or cookies for the console.
    expect(await page.evaluate(() => window.localStorage.length)).toBe(0);
    await expectNoA11yViolations(page);
  });

  await test.step('header names the admin by email; the navigation is grouped', async () => {
    // The console requests profile + email and loads UserInfo, so the header shows the email, not a UUID.
    await expect(page.getByTestId('console-admin')).toHaveText(admin.email);
    const mainNav = page.getByRole('navigation', { name: 'Main' });
    for (const group of ['Applications', 'Users and access', 'Branding and email', 'Security', 'Advanced']) {
      await expect(mainNav.getByRole('heading', { level: 2, name: group })).toBeVisible();
    }
    await expect(mainNav.getByRole('link', { name: 'Overview', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Menu' })).toBeHidden();
  });

  await test.step('at 390px the navigation collapses behind a menu button', async () => {
    const desktop = page.viewportSize();
    await page.setViewportSize({ width: 390, height: 844 });
    const mainNav = page.getByRole('navigation', { name: 'Main' });
    const menu = page.getByRole('button', { name: 'Menu' });
    await expect(menu).toBeVisible();
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await expect(menu).toHaveAttribute('aria-controls', 'main-nav');
    await expect(mainNav).toBeHidden();

    // Keyboard: the button opens the menu, Escape closes it and returns focus to the button.
    await menu.focus();
    await page.keyboard.press('Enter');
    await expect(menu).toHaveAttribute('aria-expanded', 'true');
    await expect(mainNav).toBeVisible();
    await expectNoA11yViolations(page);
    await mainNav.getByRole('link', { name: 'Users', exact: true }).focus();
    await page.keyboard.press('Escape');
    await expect(mainNav).toBeHidden();
    await expect(menu).toBeFocused();

    // Following a link closes the menu.
    await menu.click();
    await mainNav.getByRole('link', { name: 'Clients', exact: true }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Clients' })).toBeVisible();
    await expect(mainNav).toBeHidden();
    await expect(menu).toHaveAttribute('aria-expanded', 'false');

    if (desktop) await page.setViewportSize(desktop);
    await page.goto(consoleUrl('t/default/users'));
    await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible();
  });

  await test.step('the footer shows the running version to the signed-in admin only', async () => {
    const info = await fetch(`${anvilUrl()}/api/admin/v1/system/info`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(info.status).toBe(200);
    const { version } = (await info.json()) as { version: string };
    expect(version).not.toBe('');
    await expect(page.getByTestId('console-version')).toHaveText(`AnvilID ${version}`);
    // The unauthenticated console shell and the public API never carry it.
    const shell = await fetch(`${anvilUrl()}/console/`);
    expect(await shell.text()).not.toContain(version);
    expect((await fetch(`${anvilUrl()}/api/admin/v1/system/info`)).status).toBe(401);
  });

  await test.step('users list shows the created user', async () => {
    const link = page.getByRole('link', { name: userEmail });
    await findInPagedTable(page, link);
    await link.click();
    await expect(page.getByRole('heading', { level: 1, name: userEmail })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
    await expectNoA11yViolations(page);
  });

  let sessionId = '';
  await test.step('user sessions tab: revoke the RP session', async () => {
    await page.getByRole('tab', { name: 'Sessions' }).click();
    await expect(page).toHaveURL(/tab=sessions/);
    const rows = page.locator('tr[data-session-id]');
    await expect(rows).toHaveCount(1);
    sessionId = (await rows.first().getAttribute('data-session-id')) ?? '';
    expect(sessionId).not.toBe('');
    await expectNoA11yViolations(page);

    await rows.first().getByRole('button', { name: /Revoke session/ }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Revoke session?' });
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Revoke session' }).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('status').filter({ hasText: 'Session revoked.' })).toBeVisible();
    await expect(rows).toHaveCount(0);
    await expect(page.getByText('No active sessions.')).toBeVisible();
  });

  await test.step("the RP's next refresh fails", async () => {
    await rpPage.goto(`${rp!.base}/refresh`);
    await expect(rpPage.locator('#error')).toContainText('invalid_grant');
    await rpContext.close();
  });

  await test.step('credentials tab lists the password', async () => {
    await page.getByRole('tab', { name: 'Credentials' }).click();
    await expect(page.getByRole('cell', { name: 'Password', exact: true })).toBeVisible();
    await expectNoA11yViolations(page);
  });

  await test.step('audit log filtered by action shows session_revoked', async () => {
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Audit log' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Audit log' })).toBeVisible();
    await expectNoA11yViolations(page);
    await page.getByLabel('Action').selectOption('session_revoked');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(page).toHaveURL(/action=session_revoked/);
    // Session ids do not resolve to a record: the cell shows the id shortened, with the full value
    // as its title (07.1-15) and in the details.
    const row = page.getByRole('row').filter({ has: page.locator(`[title="${sessionId}"]`) });
    await expect(row).toBeVisible();
    await expect(row).toContainText('Session revoked');
    await expect(row).toContainText('session_revoked');
    // The actor resolves to the signed-in administrator.
    await expect(row.getByRole('link', { name: admin.email })).toBeVisible();
    // Every row matches the filter (each action cell shows the label and the raw action name).
    const actions = await page.locator('tbody tr td:nth-child(2)').allTextContents();
    expect(actions.length).toBeGreaterThan(0);
    expect(actions.every((a) => a === 'Session revokedsession_revoked')).toBe(true);

    await row.getByRole('button', { name: /^Details of Session revoked/ }).click();
    const drawer = page.getByRole('dialog', { name: 'Audit event' });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByTestId('audit-details')).toBeVisible();
    await expect(drawer.getByLabel('Target id', { exact: true })).toHaveValue(sessionId);
    await expectNoA11yViolations(page);
    await drawer.getByRole('button', { name: 'Close' }).click();
    await expect(drawer).toBeHidden();

    // The filter survives a reload (it lives in the URL).
    await page.reload();
    await expect(page.getByLabel('Action')).toHaveValue('session_revoked');
  });

  await test.step('tenant-wide sessions page', async () => {
    await page.goto(consoleUrl('t/default/sessions'));
    await expect(page.getByRole('heading', { level: 1, name: 'Sessions' })).toBeVisible();
    await expect(page.getByRole('table')).toHaveAttribute('aria-busy', 'false');
    await expect(page.getByRole('link', { name: userId })).toHaveCount(0);
    await expectNoA11yViolations(page);
  });

  const clientName = `e2e opaque ${randomPassword().slice(3, 11)}`;
  await test.step('create an opaque client and find it in the list', async () => {
    await page.goto(consoleUrl('t/default/clients'));
    await page.getByRole('link', { name: 'New client' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'New client' })).toBeVisible();
    await expectNoA11yViolations(page);

    // A validation error is shown at the field.
    await page.getByRole('button', { name: 'Create client' }).click();
    await expect(page.getByText('The client was not saved. Fix the errors below.')).toBeVisible();

    // The type picker comes first; Web app is preselected (confidential, consent skipped).
    await expect(page.getByTestId('app-type-picker').getByRole('radio', { name: 'Web app' })).toBeChecked();
    await page.getByLabel('Name', { exact: true }).fill(clientName);
    await page.getByLabel('Redirect URIs', { exact: true }).fill('https://rp.example.test/callback');
    await page.getByTestId('client-advanced-toggle').click();
    await page.getByLabel('Access token format').selectOption('opaque');
    await expect(page.getByLabel('Consent', { exact: true })).toHaveValue('skip_first_party');
    await page.getByRole('button', { name: 'Create client' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Client created' })).toBeVisible();
    await expect(page.getByTestId('created-client-secret')).not.toBeEmpty();
    const clientId = ((await page.getByTestId('created-client-id').textContent()) ?? '').trim();
    expect(clientId).not.toBe('');
    await expectNoA11yViolations(page);
    // The secret is shown once: after "I have stored it" it is gone from the page, the client id
    // stays.
    await takeOneTimeSecret(page, 'created-client-secret', false);
    await expect(page.getByTestId('created-client-secret-gone')).toBeVisible();
    await expect(page.getByTestId('created-client-id')).toHaveText(clientId);

    await page.getByRole('link', { name: 'Back to clients' }).click();
    const link = page.getByRole('link', { name: clientId });
    await findInPagedTable(page, link);
    await link.click();
    await expect(page.getByRole('heading', { level: 1, name: clientName })).toBeVisible();
    await expect(page.getByTestId('integration-card')).toBeVisible();
    await page.getByTestId('client-advanced-toggle').click();
    await expect(page.getByLabel('Access token format')).toHaveValue('opaque');
    await expectNoA11yViolations(page);

    // Rotating the secret shows the new one once, with the same dismissal.
    await page.getByRole('button', { name: 'Rotate secret' }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Rotate secret' }).click();
    await expect(page.getByTestId('rotated-client-secret')).not.toBeEmpty();
    await expectNoA11yViolations(page);
    await takeOneTimeSecret(page, 'rotated-client-secret', false);
  });

  await test.step("the sample RP's client page shows its logout, resource and MFA settings", async () => {
    // The sample RP registers no logout URIs, resources or MFA policy: the form shows the defaults.
    await page.goto(consoleUrl('t/default/clients'));
    const row = page.getByRole('row').filter({ hasText: 'e2e console sample RP' }).first();
    await findInPagedTable(page, row);
    await row.getByRole('link').click();
    await expect(page.getByRole('heading', { level: 1, name: 'e2e console sample RP' })).toBeVisible();
    const form = page.getByRole('form', { name: 'Edit client' });
    await expect(form.getByLabel('Post-logout redirect URIs')).toHaveValue('');
    await expect(form.getByLabel('Multi-factor authentication')).toHaveValue('inherit');
    await form.getByTestId('client-advanced-toggle').click();
    await expect(form.getByLabel('Back-channel logout URI')).toHaveValue('');
    await expect(form.getByLabel('Allowed resources')).toHaveValue('');
    await expectNoA11yViolations(page);
  });

  await test.step('email template: line error, customize, reset', async () => {
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Email' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Email' })).toBeVisible();
    const row = page.locator('tr[data-kind="invitation"]');
    await expect(row).toContainText('Default');
    await expectNoA11yViolations(page);

    await row.getByRole('link', { name: 'Invitation' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Invitation' })).toBeVisible();
    await expectNoA11yViolations(page);
    const text = page.getByLabel('Text body');
    const original = await text.inputValue();

    await text.fill('Hello\n{{ not_a_variable }}');
    await page.getByRole('button', { name: 'Save template' }).click();
    await expect(page.getByText('The template was not saved. Fix the errors below.')).toBeVisible();
    await expect(page.locator('[data-field-error]')).toContainText('Line 2');
    await expect(text).toHaveAttribute('aria-invalid', 'true');
    await expectNoA11yViolations(page);

    await text.fill(`${original}\nCustomized by the e2e suite.`);
    await page.getByRole('button', { name: 'Save template' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Template saved.' })).toBeVisible();
    await expect(page.getByTestId('template-status')).toHaveText('Customized');

    await page.getByRole('link', { name: '← Email' }).click();
    await expect(page.locator('tr[data-kind="invitation"]')).toContainText('Customized');
    await page.locator('tr[data-kind="invitation"]').getByRole('link', { name: 'Invitation' }).click();

    await page.getByRole('button', { name: 'Reset to default' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Reset template?' });
    await dialog.getByRole('button', { name: 'Reset to default' }).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByTestId('template-status')).toHaveText('Default');
    await expect(text).toHaveValue(original);
  });

  await test.step('SMTP settings and a test send delivered to Mailpit', async () => {
    await page.goto(consoleUrl('t/default/email/smtp'));
    await expect(page.getByRole('heading', { level: 1, name: 'SMTP settings' })).toBeVisible();
    await expect(page.getByTestId('smtp-source')).toBeVisible();
    await expectNoA11yViolations(page);

    const mailpit = new URL(process.env.MAILPIT_URL ?? 'http://127.0.0.1:8025');
    await page.getByLabel('Host').fill(mailpit.hostname);
    await page.getByLabel('Port').fill('1025');
    await page.getByLabel('TLS').selectOption('none');
    await page.getByLabel('From address').fill('AnvilID e2e <noreply@example.test>');
    await page.getByRole('button', { name: 'Save SMTP settings' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'SMTP settings saved.' })).toBeVisible();

    const to = randomEmail('smtp-test');
    await page.getByLabel('Recipient').fill(to);
    await page.getByRole('button', { name: 'Send test email' }).click();
    await expect(page.getByTestId('smtp-test-result')).toContainText('Test email delivered');
    const message = await latestMessageTo(to);
    expect(message.From.Address).toBe('noreply@example.test');
    await expectNoA11yViolations(page);

    // Back to the installation SMTP so later specs are unaffected.
    await page.getByRole('button', { name: 'Use installation SMTP' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Remove tenant SMTP settings?' });
    await dialog.getByRole('button', { name: 'Remove settings' }).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByTestId('smtp-source')).toBeVisible();
  });

  await test.step('sign-out returns to the login screen', async () => {
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL((url) => url.pathname.startsWith('/t/system/ui/login'));
    await expect(page.locator('form#login')).toBeVisible();
    expect(new URL(page.url()).origin).toBe(new URL(anvilUrl()).origin);
  });

  expect(csp, 'CSP violations in the console').toEqual([]);
});
