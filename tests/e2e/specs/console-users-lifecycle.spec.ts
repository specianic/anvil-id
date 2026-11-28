// C-H1 (07.1-15): the whole user lifecycle from the console. An administrator creates a user with
// a password (it appears in the list and is found by the exact email search), invites a second
// user (the invitation arrives in Mailpit), edits the first user's email, marks it verified, blocks
// the account (the end user's sign-in is refused with the generic message), unblocks it (sign-in
// works), resets MFA (the TOTP the user enrolled is gone), sends a password reset (Mailpit message
// with a /ui/recovery?token= link) and deletes the user behind a typed confirmation. The audit log
// then shows the labelled "User deleted" event with the administrator's email as the actor.
//
// Runs in the default tenant with unique addresses (the default tenant's account pages are the
// ones lib/account.ts drives). After consoleLogin the spec opens each page by URL and never asserts
// the console's landing page (07.1-17 owns it).
//
// Console test ids (admin-ui, 07.1-15):
// - users list: `create-user` (dialog "Create user"), `user-created-status`, `user-search`,
//   `user-search-submit`, `user-search-clear`, `users-empty`, `create-user-empty`
// - UserForm: `user-form`, `user-form-email`, `user-form-username`, `user-form-method-password`,
//   `user-form-method-invite`, `user-form-password`, `user-form-verified`, `user-form-save`,
//   `no-smtp-warning`
// - user page: `user-account-actions`, `user-edit` (dialog "Edit account"), `user-mark-verified`,
//   `user-block` (confirm "Block this user?"), `user-unblock`, `user-send-reset`, `user-reset-mfa`
//   (confirm "Reset MFA?"), `danger-zone` + `danger-zone-confirm-input`
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { enrolTotp, signInDirect } from '../lib/account';
import { adminCall, tenantPath } from '../lib/admin-api';
import {
  adminToken,
  anvilUrl,
  createConsoleAdmin,
  findUserByEmail,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type AdminAccount,
} from '../lib/anvil';
import { consoleLogin, consoleUrl } from '../lib/console';
import { latestMessageTo } from '../lib/mailpit';

/** The first /ui/recovery?token= link of an email (invitation and reset emails both use it). */
function recoveryLink(text: string): string {
  const match = text.match(/https?:\/\/[^\s"'<>]+\/ui\/recovery\?token=[^\s"'<>]+/);
  if (!match) throw new Error('no /ui/recovery?token= link in the email');
  return match[0].replaceAll('&amp;', '&');
}

/** Signs in on the default tenant's login page and expects the generic refusal. */
async function expectSignInRefused(page: Page, email: string, password: string): Promise<void> {
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, email, password);
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
}

interface CredentialView {
  id: string;
  kind: 'password' | 'webauthn' | 'totp';
}

test('console: create, invite, search, edit, verify, block, reset and delete a user', async ({ page, browser }) => {
  test.setTimeout(180_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  const admin: AdminAccount = { email: randomEmail('ulc-admin'), password: randomPassword() };
  await createConsoleAdmin(token, admin);
  await consoleLogin(page, admin);

  const email = randomEmail('ulc-user');
  const changedEmail = randomEmail('ulc-changed');
  const invitedEmail = randomEmail('ulc-invited');
  const password = randomPassword();

  await test.step('create a user with a password; it is listed and found by email search', async () => {
    await page.goto(consoleUrl('t/default/users'));
    await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible();
    await page.getByTestId('create-user').click();
    const dialog = page.getByRole('dialog', { name: 'Create user' });
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    await dialog.getByTestId('user-form-email').fill(email);
    await expect(dialog.getByTestId('user-form-method-password')).toBeChecked();
    await dialog.getByTestId('user-form-password').fill(password);
    await dialog.getByTestId('user-form-save').click();
    await expect(dialog).toBeHidden();
    await expect(page.getByTestId('user-created-status')).toContainText(`User created: ${email}`);

    await page.getByTestId('user-search').fill(email.toUpperCase());
    await page.getByTestId('user-search-submit').click();
    const table = page.getByRole('table', { name: `Users with the email ${email.toUpperCase()}` });
    await expect(table.getByRole('link', { name: email })).toBeVisible();
    await expect(table.locator('tbody tr')).toHaveCount(1);
    await expectNoA11yViolations(page);

    await page.getByTestId('user-search').fill(randomEmail('nobody'));
    await page.getByTestId('user-search-submit').click();
    await expect(page.getByText(/No user has the email/)).toBeVisible();
    await page.getByTestId('user-search-clear').click();
    await expect(page.getByTestId('user-search')).toHaveValue('');
  });

  await test.step('invite a user: the invitation email arrives with a recovery link', async () => {
    await page.getByTestId('create-user').click();
    const dialog = page.getByRole('dialog', { name: 'Create user' });
    await dialog.getByTestId('user-form-email').fill(invitedEmail);
    await dialog.getByTestId('user-form-method-invite').check();
    await expect(dialog.getByTestId('user-form-password')).toHaveCount(0);
    await expectNoA11yViolations(page);
    await dialog.getByTestId('user-form-save').click();
    await expect(page.getByTestId('user-created-status')).toContainText(`Invitation sent to ${invitedEmail}`);
    const message = await latestMessageTo(invitedEmail);
    expect(recoveryLink(message.Text || message.HTML)).toContain('/ui/recovery?token=');
  });

  const user = await findUserByEmail(token, email);
  if (!user) throw new Error(`created user ${email} not found`);
  const userPath = `/tenants/default/users/${encodeURIComponent(user.id)}`;

  await test.step('edit the email; the changed address is unverified until marked', async () => {
    await page.goto(consoleUrl(`t/default/users/${user.id}`));
    await expect(page.getByRole('heading', { level: 1, name: email })).toBeVisible();
    await expect(page.getByTestId('user-account-actions')).toBeVisible();
    await expectNoA11yViolations(page);

    await page.getByTestId('user-edit').click();
    const dialog = page.getByRole('dialog', { name: 'Edit account' });
    await expect(dialog.getByTestId('user-form-email')).toHaveValue(email);
    await dialog.getByTestId('user-form-email').fill(changedEmail);
    await dialog.getByTestId('user-form-save').click();
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('heading', { level: 1, name: changedEmail })).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: 'Account saved.' })).toBeVisible();

    await page.getByTestId('user-mark-verified').click();
    await expect(page.getByRole('status').filter({ hasText: 'Email marked as verified.' })).toBeVisible();
    await expect(page.getByTestId('user-mark-verified')).toHaveCount(0);
    const saved = await adminCall<{ email: string; email_verified: boolean }>(token, 'GET', userPath);
    expect(saved).toMatchObject({ email: changedEmail, email_verified: true });
  });

  await test.step('block: the end user cannot sign in; unblock: sign-in works again', async () => {
    await page.getByTestId('user-block').click();
    const confirm = page.getByRole('alertdialog', { name: 'Block this user?' });
    await expect(confirm).toBeVisible();
    await expectNoA11yViolations(page);
    await confirm.getByRole('button', { name: 'Block user' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'User blocked.' })).toBeVisible();
    await expect(page.getByTestId('user-unblock')).toBeVisible();

    const blocked = await browser.newContext();
    try {
      await expectSignInRefused(await blocked.newPage(), changedEmail, password);
    } finally {
      await blocked.close();
    }

    await page.getByTestId('user-unblock').click();
    await expect(page.getByRole('status').filter({ hasText: 'User unblocked.' })).toBeVisible();
    await expect(page.getByTestId('user-block')).toBeVisible();
  });

  await test.step('reset MFA removes the authenticator app the user enrolled', async () => {
    const context = await browser.newContext();
    try {
      const userPage = await context.newPage();
      await signInDirect(userPage, changedEmail, password);
      await enrolTotp(userPage);
    } finally {
      await context.close();
    }
    const before = await adminCall<{ items: CredentialView[] }>(token, 'GET', `${userPath}/credentials`);
    expect(before.items.some((c) => c.kind === 'totp')).toBe(true);

    await page.getByTestId('user-reset-mfa').click();
    const confirm = page.getByRole('alertdialog', { name: 'Reset MFA?' });
    await expect(confirm).toBeVisible();
    await confirm.getByRole('button', { name: 'Reset MFA' }).click();
    await expect(page.getByRole('status').filter({ hasText: /MFA reset: removed the authenticator app/ })).toBeVisible();

    const after = await adminCall<{ items: CredentialView[] }>(token, 'GET', `${userPath}/credentials`);
    expect(after.items.some((c) => c.kind === 'totp')).toBe(false);
    expect(after.items.some((c) => c.kind === 'password')).toBe(true);
  });

  await test.step('send a password reset: the email links to /ui/recovery?token=', async () => {
    await page.getByTestId('user-send-reset').click();
    await expect(page.getByRole('status').filter({ hasText: `Reset email sent to ${changedEmail}.` })).toBeVisible();
    const message = await latestMessageTo(changedEmail);
    expect(recoveryLink(message.Text || message.HTML)).toContain('/ui/recovery?token=');
  });

  await test.step('delete needs the email typed exactly', async () => {
    const zone = page.getByTestId('danger-zone');
    await zone.getByRole('button', { name: 'Delete user' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Delete this user?' });
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    const submit = dialog.getByRole('button', { name: 'Delete user' });
    await dialog.getByTestId('danger-zone-confirm-input').fill(changedEmail.toUpperCase());
    await expect(submit).toBeDisabled();
    await dialog.getByTestId('danger-zone-confirm-input').fill(changedEmail);
    await expect(submit).toBeEnabled();
    await submit.click();
    await expect(page).toHaveURL((url) => url.pathname.replace(/\/+$/, '') === '/console/t/default/users');
    await adminCall(token, 'GET', userPath, undefined, 404);
  });

  await test.step('the audit log shows "User deleted" with the administrator as actor', async () => {
    await page.goto(consoleUrl(`t/default/audit?action=user_deleted&target=${user.id}`));
    await expect(page.getByRole('heading', { level: 1, name: 'Audit log' })).toBeVisible();
    const row = page.getByRole('row').filter({ hasText: 'User deleted' });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText('user_deleted');
    await expect(row.getByRole('link', { name: admin.email })).toBeVisible();
    // The deleted user no longer resolves: its id is shown shortened (full id in the details).
    await expect(row.locator('[data-testid="audit-ref"][data-resolved="false"]')).toContainText(user.id.slice(0, 8));
    await expectNoA11yViolations(page);
  });

  // The invited user stays in the default tenant (no password yet); remove it.
  const invited = await findUserByEmail(token, invitedEmail);
  if (invited) await adminCall(token, 'DELETE', tenantPath('default', `/users/${invited.id}`), undefined, 204);
});
