// Lifecycle webhooks end to end (AGT-01, plans 05-14/05-23): an endpoint registered through the
// admin API points at a local sink (lib/webhook-sink.ts) that verifies every Standard Webhooks v1
// signature with node:crypto. A user registers through the hosted registration page and signs in;
// the sink receives `user.created` and `session.created` deliveries that carry ids only.
//
// The test runs in a tenant of its own (open registration, no verified email required), deleted
// afterwards. The e2e instance runs in development mode, where the outbound policy allows plain
// http to loopback destinations such as the sink.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import {
  adminToken,
  findUserByEmail,
  login,
  randomEmail,
  randomPassword,
  register,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { adminCall, tenantPath } from '../lib/admin-api';
import { deleteTenant } from '../lib/email-code';
import { createTenant, randomSlug, tenantIssuer } from '../lib/upstream';
import { startWebhookSink, type WebhookDelivery } from '../lib/webhook-sink';

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
});

interface CreatedEndpoint {
  endpoint: { id: string; secret_configured: boolean; [k: string]: unknown };
  secret: string;
}

/** Delivery ids-only payload: no address, name or other personal data anywhere in the body. */
function expectIdsOnly(d: WebhookDelivery, email: string): void {
  expect(d.verified, `signature of ${d.payload?.type}`).toBe(true);
  expect(d.body).not.toContain('@');
  expect(d.body.toLowerCase()).not.toContain(email.toLowerCase());
  expect(d.body).not.toContain('127.0.0.1');
  const data = d.payload?.data ?? {};
  for (const key of Object.keys(data)) {
    expect(['tenant', 'user_id', 'session_id', 'client_id', 'actor']).toContain(key);
  }
}

test('sign-up and sign-in deliver signed, ids-only webhooks to the endpoint', async ({ page }) => {
  test.setTimeout(90_000);
  const token = await adminToken(creds);
  const slug = randomSlug('hook');
  await createTenant(token, slug, { registration: 'open', require_verified_email: false });
  const sink = await startWebhookSink();
  try {
    const created = await adminCall<CreatedEndpoint>(
      token,
      'POST',
      tenantPath(slug, '/webhooks'),
      { name: 'e2e-sink', url: sink.url, events: ['user.created', 'session.created'], enabled: true },
      201,
    );
    expect(created.secret).toMatch(/^whsec_/);
    sink.setSecret(created.secret);

    // The secret is shown once: the endpoint view only says that one is configured.
    const view = await adminCall<Record<string, unknown>>(
      token,
      'GET',
      tenantPath(slug, `/webhooks/${created.endpoint.id}`),
    );
    expect(view.secret_configured).toBe(true);
    expect(JSON.stringify(view)).not.toContain(created.secret);

    // Sign up through the hosted registration page.
    const email = randomEmail('hook');
    const password = randomPassword();
    await page.goto(`${tenantIssuer(slug)}/ui/registration`);
    await expect(page.locator('form#registration')).toBeVisible();
    await register(page, email, password);
    await expect(page.locator('#message-body')).toBeVisible();
    const user = await findUserByEmail(token, email, slug);
    if (!user) throw new Error('registered user not found');

    const userCreated = await sink.waitFor((d) => d.payload?.type === 'user.created');
    expectIdsOnly(userCreated, email);
    expect(userCreated.payload?.data?.user_id).toBe(user.id);
    expect(typeof userCreated.payload?.timestamp).toBe('string');

    // Sign in on the tenant's hosted login page.
    await page.context().clearCookies();
    await page.goto(`${tenantIssuer(slug)}/ui/login`);
    await login(page, email, password);
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');

    const sessionCreated = await sink.waitFor(
      (d) => d.payload?.type === 'session.created' && d.payload?.data?.user_id === user.id,
    );
    expectIdsOnly(sessionCreated, email);
    expect(sessionCreated.id).not.toBe(userCreated.id);

    // Every delivery verified, and the endpoint never received an unsubscribed event type.
    for (const d of sink.deliveries()) {
      expectIdsOnly(d, email);
      expect(['user.created', 'session.created']).toContain(d.payload?.type);
    }

    // The delivery log shows both deliveries as delivered, without payloads.
    await expect
      .poll(
        async () => {
          const log = await adminCall<{ items: { event_type: string; status: string }[] }>(
            token,
            'GET',
            tenantPath(slug, `/webhooks/${created.endpoint.id}/deliveries`),
          );
          return log.items
            .filter((i) => i.status === 'delivered')
            .map((i) => i.event_type)
            .sort();
        },
        { timeout: 15_000 },
      )
      .toEqual(expect.arrayContaining(['session.created', 'user.created']));
  } finally {
    await sink.stop();
    await deleteTenant(token, slug);
  }
});
