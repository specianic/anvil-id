// Smoke test for the 07.1 journey helpers (lib/ux-state.ts, lib/layout.ts): the fake RP receives a
// code for a cached client, and the overflow helper passes on the sign-in page at 390px.

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { anvilUrl, login } from '../lib/anvil';
import { expectNoHorizontalOverflow } from '../lib/layout';
import { atRp, authorizeUrl, fakeRp, newUser, uxState, type FakeRp } from '../lib/ux-state';

test.describe('UX journey helpers', () => {
  let rp: FakeRp | undefined;

  test.beforeAll(async () => {
    rp = await fakeRp();
  });

  test.afterAll(async () => {
    await rp?.close();
  });

  test('a cached first-party client signs a new user in and the fake RP receives the code', async ({
    page,
    browser,
  }) => {
    const s = await uxState(browser);
    // A second call reads the cache instead of creating new clients.
    expect((await uxState(browser)).clients.web.client_id).toBe(s.clients.web.client_id);

    const user = await newUser(s, 'uxhelpers');
    const request = authorizeUrl(s.clients.web);
    await page.goto(request.url);
    await login(page, user.email, user.password);

    const params = await atRp(page);
    expect(params.get('error')).toBeNull();
    expect(params.get('code')).toBeTruthy();
    expect(params.get('state')).toBe(request.state);
    await expect(page.locator('#rp-path')).toHaveText('/callback');
  });

  test('the sign-in page does not overflow at 390px and passes axe', async ({ page }) => {
    await page.goto(`${anvilUrl()}/ui/login`);
    await expect(page.locator('#identifier')).toBeVisible();
    await expectNoHorizontalOverflow(page, 390);
    await expectNoA11yViolations(page);
  });
});
