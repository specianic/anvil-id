// ADM-05 from the console (05-24): an operator creates a webhook endpoint pointing at a local sink,
// copies the signing secret shown once, sends a test event and sees it Delivered in the delivery
// log; the sink verifies the Standard Webhooks signature with node:crypto (lib/webhook-sink.ts).
// Redelivery, secret rotation (the new secret signs; the old one is gone from the page),
// disable/enable and deletion are driven from the same pages.
//
// The e2e instance runs in development mode (loopback public URL), so the outbound policy lets
// the endpoint point at http://127.0.0.1. Runs in a tenant of its own, deleted afterwards.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  allowClipboard,
  openTenantPage,
  setUpConsoleTenant,
  takeOneTimeSecret,
  type ConsoleTenant,
} from '../lib/console-v04';
import { startWebhookSink, type WebhookSink } from '../lib/webhook-sink';

let tenant: ConsoleTenant | undefined;
let sink: WebhookSink | undefined;

test.afterAll(async () => {
  await sink?.stop();
  await tenant?.cleanup();
});

test('console: webhook endpoint, signed test delivery, redelivery, rotation and removal', async ({
  page,
  browser,
}) => {
  test.setTimeout(150_000);
  sink = await startWebhookSink();
  tenant = await setUpConsoleTenant(browser, page, 'chooks');
  const { slug } = tenant;
  await allowClipboard(page);
  const testDeliveries = () => sink!.deliveries().filter((d) => d.payload?.type === 'test');

  await test.step('the Webhooks page is in the navigation and starts empty', async () => {
    await openTenantPage(page, slug, 'users');
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Webhooks' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/webhooks`);
    await expect(page.getByText('No webhook endpoints yet.')).toBeVisible();
    await expectNoA11yViolations(page);
  });

  await test.step('the form refuses an endpoint without events', async () => {
    await page.getByTestId('new-webhook').click();
    await expect(page.getByRole('heading', { level: 1, name: 'New webhook endpoint' })).toBeVisible();
    await page.getByTestId('webhook-name').fill('sink');
    await page.getByTestId('webhook-url').fill(sink!.url);
    await page.getByTestId('webhook-submit').click();
    await expect(page.getByTestId('webhook-form')).toContainText('Choose at least one event.');
    await expectNoA11yViolations(page);
  });

  let secret = '';
  await test.step('create the endpoint; the secret is shown once and copied', async () => {
    await page.getByRole('checkbox', { name: 'user.created' }).check();
    await page.getByRole('checkbox', { name: 'session.created' }).check();
    await page.getByTestId('webhook-submit').click();
    await expect(page.getByRole('heading', { level: 1, name: 'Endpoint created' })).toBeVisible();
    await expectNoA11yViolations(page);
    secret = await takeOneTimeSecret(page, 'webhook-secret');
    expect(secret).toMatch(/^whsec_/);
    sink!.setSecret(secret);
    await page.getByTestId('open-webhook').click();
    await expect(page.getByRole('heading', { level: 1, name: 'sink' })).toBeVisible();
    await expect(page.getByTestId('webhook-status')).toContainText('Enabled');
    expect(await page.content()).not.toContain(secret);
  });

  await test.step('send a test event: Delivered in the log, signature verified by the sink', async () => {
    await page.getByTestId('send-webhook-test').click();
    await expect(page.getByRole('status').filter({ hasText: 'Test event queued.' })).toBeVisible();
    const row = page.getByTestId('delivery-log').locator('tr[data-event="test"]').first();
    await expect(row).toHaveAttribute('data-status', 'delivered', { timeout: 30_000 });
    await expect(row).toContainText('Delivered');
    await expect(row).toContainText('HTTP 204');
    const delivery = await sink!.waitFor((d) => d.payload?.type === 'test');
    expect(delivery.verified).toBe(true);
    await expectNoA11yViolations(page);
  });

  await test.step('redeliver the test event', async () => {
    const row = page.getByTestId('delivery-log').locator('tr[data-event="test"]').first();
    await row.getByRole('button', { name: /^Redeliver/ }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Redelivery queued.' })).toBeVisible();
    await expect.poll(() => testDeliveries().length, { timeout: 30_000 }).toBeGreaterThanOrEqual(2);
    expect(testDeliveries().every((d) => d.verified)).toBe(true);
    await expect(page.getByTestId('delivery-log').locator('tr[data-event="test"][data-status="delivered"]')).toHaveCount(
      2,
      { timeout: 30_000 },
    );
  });

  await test.step('rotate the secret; the new one signs the next delivery', async () => {
    await page.getByTestId('rotate-webhook-secret').click();
    await page.getByRole('alertdialog', { name: 'Rotate the signing secret?' }).getByRole('button', { name: 'Rotate secret' }).click();
    const rotated = await takeOneTimeSecret(page, 'webhook-secret');
    expect(rotated).toMatch(/^whsec_/);
    expect(rotated).not.toBe(secret);
    expect(await page.content()).not.toContain(secret);
    sink!.setSecret(rotated);
    const before = testDeliveries().length;
    await page.getByTestId('send-webhook-test').click();
    await expect.poll(() => testDeliveries().length, { timeout: 30_000 }).toBeGreaterThan(before);
    expect(testDeliveries().at(-1)?.verified).toBe(true);
  });

  await test.step('disable and enable the endpoint', async () => {
    await page.getByTestId('toggle-webhook').click();
    await expect(page.getByTestId('webhook-status')).toContainText('Disabled');
    await page.getByTestId('toggle-webhook').click();
    await expect(page.getByTestId('webhook-status')).toContainText('Enabled');
  });

  await test.step('delete the endpoint', async () => {
    await page.getByTestId('delete-webhook').click();
    await page.getByRole('alertdialog', { name: 'Delete this endpoint?' }).getByRole('button', { name: 'Delete endpoint' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/webhooks`);
    await expect(page.getByText('No webhook endpoints yet.')).toBeVisible();
  });
});
