// Helpers for email one-time code and magic link sign-in (AUTH-06, plan 04-24), shared by
// specs/email-code.spec.ts and specs/nojs-email-code.spec.ts.
//
// The specs run in a tenant of their own, created with `email_otp` and `magic_link` on (both need
// SMTP; the e2e instance has ANVILID_SMTP_URL pointing at Mailpit), so the shared default tenant's
// sign-in page (keyboard and a11y specs) is not changed. The tenant is deleted afterwards.
//
// Selectors (themes/default/templates/login.html, email_code.html, magic_link.html): the sign-in
// field `identifier` and the button `email-code-request-submit` in the sign-in form; "Check your email" form `email-code` (input `code`, button
// `email-code-submit`); magic link form `magic-link` (button `magic-link-submit`).

import { expect, type Page } from '@playwright/test';
import { anvilUrl } from './anvil';
import { extractLink, latestMessageTo, type MailpitMessage } from './mailpit';
import { randomSlug, tenantIssuer } from './upstream';

/** A tenant with email sign-in enabled. */
export interface EmailSignInTenant {
  slug: string;
  /** `{ANVIL_URL}/t/{slug}`: the issuer and the base of the tenant's pages. */
  base: string;
}

async function adminFetch(
  token: string,
  method: 'POST' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<Response> {
  return fetch(`${anvilUrl()}/api/admin/v1${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/json',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Creates a tenant with `email_otp` and `magic_link` enabled. */
export async function createEmailSignInTenant(
  token: string,
  prefix = 'email',
): Promise<EmailSignInTenant> {
  const slug = randomSlug(prefix);
  const res = await adminFetch(token, 'POST', '/tenants', {
    slug,
    display_name: `Email sign-in ${slug}`,
    settings: { email_otp: true, magic_link: true },
  });
  if (res.status !== 201) {
    throw new Error(`creating tenant ${slug} failed: HTTP ${res.status} ${await res.text()}`);
  }
  return { slug, base: tenantIssuer(slug) };
}

/** Deletes the tenant (best effort: a failure here must not hide the test's own result). */
export async function deleteTenant(token: string, slug: string): Promise<void> {
  const res = await adminFetch(token, 'DELETE', `/tenants/${encodeURIComponent(slug)}`);
  if (res.status !== 204 && res.status !== 404) {
    console.warn(`deleting tenant ${slug}: HTTP ${res.status} ${await res.text()}`);
  }
}

/**
 * On the tenant's sign-in page (already open): enters `email` in the sign-in field, presses "Email
 * me a way to sign in" and waits for the "Check your email" page. Returns the confirmation text
 * shown there (the same for every address). `beforeSubmit` runs before the button is pressed
 * (e.g. an axe audit).
 */
export async function requestEmailCode(
  page: Page,
  email: string,
  beforeSubmit?: () => Promise<void>,
): Promise<string> {
  // One address field (U-M7, plan 07.1-13): the sign-in field `identifier`; the button
  // `email-code-request-submit` in the sign-in form posts it to the email-code route.
  const input = page.locator('#identifier');
  await expect(input).toBeVisible();
  await input.fill(email);
  if (beforeSubmit) await beforeSubmit();
  await page.locator('#email-code-request-submit').click();
  await expect(page.locator('form#email-code')).toBeVisible();
  const sent = page.locator('form#email-code [data-message-key="email_code.sent"]');
  await expect(sent).toBeVisible();
  return ((await sent.textContent()) ?? '').trim();
}

/** The newest sign-in email to `email` (polls Mailpit). */
export function signInEmail(email: string): Promise<MailpitMessage> {
  return latestMessageTo(email);
}

/** The 6-digit code of a sign-in email (an indented line of its own in the text part). */
export function codeFrom(message: MailpitMessage): string {
  const match = /^\s+(\d{6})\s*$/m.exec(message.Text);
  if (!match) throw new Error(`no 6-digit code in the sign-in email "${message.Subject}"`);
  return match[1];
}

/** The magic link of a sign-in email (`{base}/ui/login/email-link?flow=…&token=…`). */
export function magicLinkFrom(message: MailpitMessage, tenant: EmailSignInTenant): string {
  return extractLink(message.Text || message.HTML, `/t/${tenant.slug}/ui/login/email-link`);
}

/** On the "Check your email" page: types the code and submits it. */
export async function submitEmailCode(page: Page, code: string): Promise<void> {
  await page.locator('#code').fill(code);
  await page.locator('#email-code-submit').click();
}

/** Asserts that no mail to `address` arrives within `waitMs`. */
export async function expectNoMailTo(address: string, waitMs = 3_000): Promise<void> {
  let arrived = false;
  try {
    await latestMessageTo(address, { timeoutMs: waitMs });
    arrived = true;
  } catch {
    // nothing arrived: expected
  }
  expect(arrived, `no mail is sent to ${address}`).toBe(false);
}

/** The browser has no session in the tenant: its account page sends it to the sign-in page. */
export async function expectNoSession(page: Page, tenant: EmailSignInTenant): Promise<void> {
  await page.goto(`${tenant.base}/ui/account/sessions`);
  await expect(page).toHaveURL((url) => url.pathname.endsWith(`/t/${tenant.slug}/ui/login`));
  await expect(page.locator('form#login')).toBeVisible();
}

/** The browser has a session in the tenant: its sessions page opens (no redirect to sign-in). */
export async function expectSession(page: Page, tenant: EmailSignInTenant): Promise<void> {
  await page.goto(`${tenant.base}/ui/account/sessions`);
  await expect(page.locator('#session-list')).toBeVisible();
}
