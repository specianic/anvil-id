// ORG-02 invitations in a browser (06-20, 06-31): an administrator invites a new address to an
// organization; the org_invitation email arrives in Mailpit; the invitee opens the link (the GET
// only shows the offer, nothing is used), accepts, registers through the signed-out form (the
// address comes from the invitation and is verified), is signed in and a member of the org (the
// account page opens without a password prompt); the same link then shows the one invalid page.
// The new account signs in with its password. A second journey: an existing account follows the
// signed-out page's sign-in link, signs in and lands back on the invitation, then accepts with one
// click. axe runs on the offer, registration, registered and invalid pages.
//
// Runs in a tenant of its own (deleted afterwards). Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE,
// MAILPIT_URL (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  createUser,
  findUserByEmail,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';
import { extractLink, latestMessageTo } from '../lib/mailpit';
import { createInvitation, createOrg, createOrgTenant, orgInvitations, orgMembers, type OrgTenant } from '../lib/org';
import { signInAtTenant, tenantIssuer } from '../lib/upstream';

let tenant: OrgTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

test('an invited address registers through the emailed link and joins the org', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  tenant = await createOrgTenant(token, 'invite');
  const { slug } = tenant;
  expect(slug).not.toBe('default');
  const org = await createOrg(token, slug, { slug: 'acme', display_name: 'Acme Corp' });
  const invitee = randomEmail('invitee');
  const password = randomPassword();

  let link = '';
  await test.step('the invitation email arrives in Mailpit', async () => {
    const invitation = await createInvitation(token, slug, org.id, invitee);
    expect(invitation.status).toBe('open');
    expect(JSON.stringify(invitation)).not.toMatch(/token/i);
    const message = await latestMessageTo(invitee);
    expect(message.Subject).toContain('Acme Corp');
    expect(message.Text).toContain(invitee);
    link = extractLink(message.Text, `/t/${slug}/ui/invitation`);
    expect(new URL(link).searchParams.get('token')).toBeTruthy();
  });

  await test.step('the link shows the offer; accepting while signed out offers registration', async () => {
    await page.goto(link);
    await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.offer');
    await expect(page.locator('#invitation-message')).toContainText('Acme Corp');
    await expectNoA11yViolations(page);
    // Opening the link used nothing.
    expect((await orgInvitations(token, slug, org.id)).find((i) => i.email === invitee)?.status).toBe('open');

    await page.locator('#invitation-accept-submit').click();
    await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.signed_out');
    await expect(page.locator('form#invitation-register-form')).toBeVisible();
    // The address comes from the invitation, read-only and not a form field.
    await expect(page.locator('#invitation-email')).toHaveValue(invitee);
    await expect(page.locator('#invitation-email')).toHaveAttribute('readonly', '');
    await expect(page.locator('#invitation-email')).not.toHaveAttribute('name');
    await expectNoA11yViolations(page);
  });

  await test.step('registering creates a verified account that is a member of the org and signs in', async () => {
    await page.locator('#password').fill(password);
    await page.locator('#name').fill('Ivy Invitee');
    await page.locator('#invitation-register-submit').click();
    await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.registered');
    await expect(page.locator('#invitation-continue')).toBeVisible();
    await expect(page.locator('#invitation-sign-in')).toHaveCount(0);
    await expectNoA11yViolations(page);

    const user = await findUserByEmail(token, invitee, slug);
    expect(user).toBeDefined();
    expect(user?.email_verified).toBe(true);
    const members = await orgMembers(token, slug, org.id);
    expect(members.map((m) => m.user_id)).toContain(user?.id);
    const invitation = (await orgInvitations(token, slug, org.id)).find((i) => i.email === invitee);
    expect(invitation?.status).toBe('accepted');

    // Signed in: the account page opens without a password prompt.
    await page.locator('#invitation-continue').click();
    await expect(page).toHaveURL(new RegExp(`/t/${slug}/ui/account/profile`));
    await expect(page.locator('form#profile-form')).toBeVisible();
    await expect(page.locator('#identifier')).toHaveCount(0);
  });

  await test.step('a second use of the link shows the invalid page', async () => {
    await page.goto(link);
    await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.invalid');
    await expect(page.locator('#invitation-accept-submit')).toHaveCount(0);
    await expect(page.locator('form#invitation-register-form')).toHaveCount(0);
    await expectNoA11yViolations(page);
  });

  await test.step('the new account signs in with its password', async () => {
    await page.context().clearCookies();
    await signInAtTenant(page, slug, invitee, password);
  });
});

test('an existing account signs in from the invitation and comes back to accept it', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  const own = await createOrgTenant(token, 'invite-signin');
  try {
    const { slug } = own;
    const org = await createOrg(token, slug, { slug: 'globex', display_name: 'Globex Corp' });
    const email = randomEmail('member');
    const password = randomPassword();
    const user = await createUser(token, { email, password, email_verified: true }, slug);
    expect(user.id).toBeTruthy();

    await createInvitation(token, slug, org.id, email);
    const message = await latestMessageTo(email);
    const link = extractLink(message.Text, `/t/${slug}/ui/invitation`);

    await test.step('signed out, the invitation links to a sign-in that returns here', async () => {
      await page.goto(link);
      await page.locator('#invitation-accept-submit').click();
      await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.signed_out');
      await expect(page.locator('#invitation-sign-in-hint')).toBeVisible();
      await page.locator('#invitation-sign-in').click();
      await expect(page).toHaveURL(new RegExp(`^${tenantIssuer(slug)}/ui/login\\?return_to=`));
      await login(page, email, password);
      // Back on the invitation of the same tenant, not the signed-in page.
      await expect(page).toHaveURL(new RegExp(`^${tenantIssuer(slug)}/ui/invitation\\?token=`));
      await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.offer');
      expect((await orgInvitations(token, slug, org.id)).find((i) => i.email === email)?.status).toBe('open');
    });

    await test.step('one click accepts', async () => {
      await page.locator('#invitation-accept-submit').click();
      await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.accepted');
      await expect(page.locator('#invitation-message')).toContainText('Globex Corp');
      const members = await orgMembers(token, slug, org.id);
      expect(members.map((m) => m.user_id)).toContain(user.id);
    });
  } finally {
    await own.cleanup();
  }
});
