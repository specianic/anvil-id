// C-H2 (07.1-15): a second console administrator from the console. In the system tenant the Users
// page offers "Add administrator": an invitation by email plus the `administrator` role in one
// action. The invited person sets a password from the email and signs in to the console. For an
// address that already has a system-tenant account the dialog offers to assign the role instead.
// Removing your own administrator role asks first and explains the last-admin rule before any
// request is sent (Cancel keeps the role).
//
// (The "anvil-console has no Delete" assertion lives in 07.1-16's client spec.)
//
// After consoleLogin the spec opens pages by URL and never asserts the console's landing page.
//
// Console test ids (admin-ui, 07.1-15): `add-administrator` (dialog "Add administrator"),
// `add-administrator-form`, `add-administrator-email`, `add-administrator-existing`,
// `add-administrator-submit`; user page roles tab `own-admin-warning`, `no-assignable-roles`.
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { adminCall, tenantPath } from '../lib/admin-api';
import {
  adminToken,
  createConsoleAdmin,
  createUser,
  findUserByEmail,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type AdminAccount,
} from '../lib/anvil';
import { consoleLogin, consoleUrl } from '../lib/console';
import { latestMessageTo } from '../lib/mailpit';

/** The first /ui/recovery?token= link of an email (the invitation link). */
function recoveryLink(text: string): string {
  const match = text.match(/https?:\/\/[^\s"'<>]+\/ui\/recovery\?token=[^\s"'<>]+/);
  if (!match) throw new Error('no /ui/recovery?token= link in the email');
  return match[0].replaceAll('&amp;', '&');
}

async function systemRoles(token: string, userId: string): Promise<string[]> {
  const body = await adminCall<{ items: Array<{ name: string }> }>(
    token,
    'GET',
    tenantPath('system', `/users/${encodeURIComponent(userId)}/roles`),
  );
  return body.items.map((r) => r.name);
}

test('console: add a second administrator by invitation; own role removal warns first', async ({ page, browser }) => {
  test.setTimeout(150_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  const admin: AdminAccount = { email: randomEmail('adm-owner'), password: randomPassword() };
  await createConsoleAdmin(token, admin);
  await consoleLogin(page, admin);

  const invitedEmail = randomEmail('adm-invited');
  const invitedPassword = randomPassword();
  const existingEmail = randomEmail('adm-existing');
  const cleanup: string[] = [];

  try {
    await test.step('Add administrator invites by email and assigns the role', async () => {
      await page.goto(consoleUrl('t/system/users'));
      await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible();
      await page.getByTestId('add-administrator').click();
      const dialog = page.getByRole('dialog', { name: 'Add administrator' });
      await expect(dialog).toBeVisible();
      await expectNoA11yViolations(page);
      await dialog.getByTestId('add-administrator-email').fill(invitedEmail);
      await dialog.getByTestId('add-administrator-submit').click();
      await expect(dialog).toBeHidden();
      await expect(page.getByRole('status').filter({ hasText: `Invitation sent to ${invitedEmail}.` })).toBeVisible();

      const invited = await findUserByEmail(token, invitedEmail, 'system');
      if (!invited) throw new Error(`invited administrator ${invitedEmail} not found`);
      cleanup.push(invited.id);
      expect(await systemRoles(token, invited.id)).toContain('administrator');
    });

    await test.step('the invited administrator sets a password and signs in to the console', async () => {
      const message = await latestMessageTo(invitedEmail);
      const link = recoveryLink(message.Text || message.HTML);
      const context = await browser.newContext();
      try {
        const newAdmin = await context.newPage();
        await newAdmin.goto(link);
        await newAdmin.locator('input[type="password"]').first().fill(invitedPassword);
        const confirm = newAdmin.locator('input[type="password"]').nth(1);
        if ((await confirm.count()) > 0) await confirm.fill(invitedPassword);
        await newAdmin.locator('button[type="submit"]').click();
        await expect(newAdmin.locator('#message-body')).toBeVisible();

        await newAdmin.goto(consoleUrl());
        await expect(newAdmin).toHaveURL((url) => url.pathname.startsWith('/t/system/ui/login'));
        await login(newAdmin, invitedEmail, invitedPassword);
        await expect(newAdmin.getByRole('navigation', { name: 'Main' })).toBeVisible();
        await expect(newAdmin.getByTestId('console-admin')).toHaveText(invitedEmail);
        // The new administrator's token reaches the admin API: the system tenant's users load.
        await newAdmin.goto(consoleUrl('t/system/users'));
        await expect(newAdmin.getByTestId('add-administrator')).toBeVisible();
        await expect(newAdmin.getByRole('table', { name: 'Users' })).toBeVisible();
      } finally {
        await context.close();
      }
    });

    await test.step('an existing system user is offered the role instead of an invitation', async () => {
      const existing = await createUser(token, { email: existingEmail, password: randomPassword(), email_verified: true }, 'system');
      if (!existing.id) throw new Error('no id for the existing system user');
      cleanup.push(existing.id);

      await page.getByTestId('add-administrator').click();
      const dialog = page.getByRole('dialog', { name: 'Add administrator' });
      await dialog.getByTestId('add-administrator-email').fill(existingEmail);
      await dialog.getByTestId('add-administrator-submit').click();
      await expect(dialog.getByTestId('add-administrator-existing')).toContainText(existingEmail);
      await expect(dialog.getByTestId('add-administrator-submit')).toHaveText('Assign administrator role');
      await expectNoA11yViolations(page);
      await dialog.getByTestId('add-administrator-submit').click();
      await expect(page.getByRole('status').filter({ hasText: `${existingEmail} is now an administrator.` })).toBeVisible();
      expect(await systemRoles(token, existing.id)).toContain('administrator');
    });

    await test.step('removing your own administrator role explains the last-admin rule first', async () => {
      const me = await findUserByEmail(token, admin.email, 'system');
      if (!me) throw new Error('signed-in administrator not found');
      await page.goto(consoleUrl(`t/system/users/${me.id}?tab=roles`));
      await page.getByRole('button', { name: 'Remove role administrator' }).click();
      const confirm = page.getByRole('alertdialog', { name: 'Remove your own administrator role?' });
      await expect(confirm).toBeVisible();
      await expect(confirm.getByTestId('own-admin-warning')).toContainText('admin:write');
      await expect(confirm.getByTestId('own-admin-warning')).toContainText('Add another administrator first');
      await expectNoA11yViolations(page);
      await confirm.getByRole('button', { name: 'Cancel' }).click();
      await expect(confirm).toBeHidden();
      expect(await systemRoles(token, me.id)).toContain('administrator');
    });
  } finally {
    for (const id of cleanup) {
      await adminCall(token, 'DELETE', tenantPath('system', `/users/${encodeURIComponent(id)}`), undefined, [204, 404]);
    }
  }
});
