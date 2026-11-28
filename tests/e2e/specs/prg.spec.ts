// Post/Redirect/Get on the end-user flow pages (U-M1, plan 07.1-07): after a failed sign-in or
// registration the error page is a GET, so browser Back never lands on a POST answer
// (ERR_CACHE_MISS) and reload never posts the credentials again.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { anvilUrl, login, randomEmail, randomPassword, register } from '../lib/anvil';
import { newUser, uxState } from '../lib/ux-state';

/** Counts the form POSTs the page sends to `path` from now on. */
function countPosts(page: Page, path: string): () => number {
  let n = 0;
  page.on('request', (req) => {
    if (req.method() === 'POST' && new URL(req.url()).pathname.endsWith(path)) n += 1;
  });
  return () => n;
}

test('failed sign-in: reload does not re-post and Back works', async ({ page, browser }) => {
  const s = await uxState(browser);
  const user = await newUser(s, 'prg');
  const posts = countPosts(page, '/ui/login');

  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, user.email, randomPassword());
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
  await expect(page).toHaveURL(/\/ui\/login\?flow=/);
  await expect(page.locator('#identifier')).toHaveValue(user.email);
  await expect(page.locator('#password')).toHaveValue('');
  expect(posts()).toBe(1);

  // Reload: a GET of the same step, no second POST, the one-shot message is gone.
  const reloaded = await page.reload();
  expect(reloaded?.request().method()).toBe('GET');
  expect(reloaded?.status()).toBe(200);
  await expect(page.locator('form#login')).toBeVisible();
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toHaveCount(0);
  expect(posts()).toBe(1);

  // Back: the sign-in page the form was opened on, loaded with GET (no cache-miss error page).
  // (A page restored from the back/forward cache has no new response.)
  const back = await page.goBack();
  if (back) expect(back.request().method()).toBe('GET');
  await expect(page).toHaveURL(`${anvilUrl()}/ui/login`);
  await expect(page.locator('form#login')).toBeVisible();
  expect(page.url()).not.toContain('chrome-error://');
  expect(posts()).toBe(1);

  // Forward to the redirected page: it is a GET again and its form signs in.
  await page.goForward();
  await expect(page).toHaveURL(/\/ui\/login\?flow=/);
  await login(page, user.email, user.password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
});

test('failed registration: reload does not re-post and Back works', async ({ page }) => {
  const posts = countPosts(page, '/ui/registration');
  const email = randomEmail('prg-reg');

  await page.goto(`${anvilUrl()}/ui/registration`);
  await register(page, email, 'short');
  await expect(page).toHaveURL(/\/ui\/registration\?flow=/);
  await expect(page.locator('#password-msg-1')).toBeVisible();
  await expect(page.locator('#email')).toHaveValue(email);
  expect(posts()).toBe(1);

  const reloaded = await page.reload();
  expect(reloaded?.request().method()).toBe('GET');
  await expect(page.locator('form#registration')).toBeVisible();
  expect(posts()).toBe(1);

  const back = await page.goBack();
  if (back) expect(back.request().method()).toBe('GET');
  await expect(page).toHaveURL(`${anvilUrl()}/ui/registration`);
  await expect(page.locator('form#registration')).toBeVisible();
  expect(page.url()).not.toContain('chrome-error://');
  expect(posts()).toBe(1);

  // Forward to the redirected page: it is a GET again and a good password there registers.
  await page.goForward();
  await expect(page).toHaveURL(/\/ui\/registration\?flow=/);
  await register(page, email, randomPassword());
  await expect(page.locator('#message-body')).toBeVisible();
});
