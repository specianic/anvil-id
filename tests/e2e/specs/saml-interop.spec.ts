// ORG-03 real-IdP SAML interop (07-28). AnvilID signs in through Keycloak, SimpleSAMLphp and
// Shibboleth IdP running from the pinned images in tests/saml-interop/compose.yml. Run it with
// tests/saml-interop/run.sh (`just saml-interop`), which provisions the IdPs from committed
// templates with per-run keys and passwords, then hands over to tests/e2e/run.sh with this spec
// only. The regular e2e run excludes it. Env: see lib/saml-interop.ts.
//
// Tenant `interop` (the IdP templates register its SP values) has registration disabled and
// upstream registration off, so only the organization-trusted JIT exception can create accounts.
// Per IdP: one org (with a default role), one connection per IdP-side setup, each created from
// the IdP metadata imported BY URL through AnvilID's guarded outbound client, and each with a
// verified domain `<slug>.interop.example.com` (mock DNS) routed to it.
//
// Scenarios, per IdP, with the rows of the "Real-IdP interop checklist" in docs/SAML.md:
//   setup  metadata import by https URL, SP metadata matches the IdP template (row 2)
//   1      SP-initiated sign-in from the email-first page: the AuthnRequest (Issuer, ACS,
//          NameIDPolicy persistent, no ForceAuthn), the response (assertion signed, SHA-256+,
//          NameID format), JIT user with the mapped profile, verified email, membership with the
//          default role, org_id in the token, audit saml_login_succeeded (rows 1, 3, 4, 5, 6, 16)
//   2      second sign-in in a fresh browser: same link, same sub, no new user (row 7)
//   3      prompt=login: ForceAuthn="true" and the IdP asks for credentials again (row 8)
//   4      other accepted signing setups (Keycloak: Response + assertion; SimpleSAMLphp: assertion
//          only) (row 3)
//   5      IdP-initiated SSO from the IdP's own unsolicited endpoint: generic error, no session,
//          audit reason relay_state (row 9, decision Q4)
//   6      the captured response of scenario 1 replayed: generic error, audited (row 10)
//   7      refusals produced by real IdP configuration: response-only signing (row 14),
//          encrypted assertion (row 13), unsigned response and RSA-SHA1 (Keycloak), each with its
//          exact audit reason and no account created
//   8      (Keycloak) the JIT rule: an asserted address outside the org's verified domains gets
//          no account and no membership under closed registration
//   9      (Keycloak) the org MFA policy applies after a SAML sign-in (row 15)
//   10     (Keycloak) certificate rollover in the checklist order, and a connection pinned only
//          to the retired key is refused (row 12)
//
// Not automated here: clock skew (row 11; none of the images can shift its clock). Wrong
// audience, wrong recipient, expired assertions, XML signature wrapping and the other D4 shapes
// cannot be produced by a correctly configured IdP; crates/anvil-web/tests/security_saml.rs and
// specs/saml.spec.ts (mock IdP) cover them.
//
// Every scenario appends its outcome to SAML_INTEROP_RESULTS (no messages, keys or passwords).

import { randomBytes } from 'node:crypto';
import { expect, test, type Browser, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { auditEvents, type AuditEvent } from '../lib/account';
import { adminCall, tenantPath } from '../lib/admin-api';
import { adminToken, sharedManagementCredential } from '../lib/anvil';
import { authorizationCodeFlow, jwtClaims, type TokenSet } from '../lib/code-flow';
import { deleteTenant } from '../lib/email-code';
import { removeTxt } from '../lib/mock-dns';
import {
  addVerifiedDomain,
  chooseSso,
  createOrg,
  createOrgClient,
  createOrgSamlConnection,
  orgMemberRoles,
  orgMembers,
  patchDomainRouting,
  type OrgConnectionView,
  type OrgView,
} from '../lib/org';
import {
  captureSaml,
  domainOf,
  INTEROP_TENANT,
  interopIdps,
  KeycloakAdmin,
  observedFacts,
  pemOf,
  recordResult,
  replayResponse,
  STRONG_DIGEST_METHODS,
  STRONG_SIGNATURE_METHODS,
  type IdpUser,
  type InteropIdp,
  type ResponseFacts,
} from '../lib/saml-interop';
import { createTenant, tenantIssuer, tenantUsers } from '../lib/upstream';
import { totp } from '../lib/totp';

// Screenshots on failure show which IdP or AnvilID page a journey stopped on (test data only).
test.use({ ignoreHTTPSErrors: true, screenshot: 'only-on-failure' });

const IDPS = interopIdps();
const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
const UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
const issuer = tenantIssuer(INTEROP_TENANT);

let token = '';
let client: { client_id: string; client_secret: string; redirect_uri: string };
const dnsRecords: string[] = [];

test.beforeAll(async ({ browser }) => {
  token = await adminToken(await sharedManagementCredential(browser));
  // A tenant left over by an interrupted worker (Playwright restarts the worker after a failure).
  await deleteTenant(token, INTEROP_TENANT);
  await createTenant(token, INTEROP_TENANT, { registration: 'disabled', upstream_registration: false });
  // `required`: a JIT member's only membership is put in the token.
  client = await createOrgClient(token, INTEROP_TENANT, 'https://interop-rp.example.test/callback', 'required');
});

test.afterAll(async () => {
  for (const name of dnsRecords.splice(0)) await removeTxt(name).catch(() => undefined);
  if (token) await deleteTenant(token, INTEROP_TENANT);
});

// ---------------------------------------------------------------------------------------------
// helpers

const spEntityId = (slug: string) => `${issuer}/saml/${slug}`;
const acsUrl = (slug: string) => `${issuer}/ui/login/saml/${slug}/acs`;
const connPath = (org: string, rest = '') => tenantPath(INTEROP_TENANT, `/organizations/${encodeURIComponent(org)}${rest}`);

/** Runs `fn` as one results-file scenario: pass with its observed facts, or fail (and rethrow). */
async function scenario(
  idp: InteropIdp,
  name: string,
  connection: string,
  rows: number[],
  fn: () => Promise<Record<string, unknown> | undefined>,
): Promise<void> {
  try {
    const observed = await fn();
    recordResult(idp, { scenario: name, connection, rows, result: 'pass', observed });
  } catch (e) {
    recordResult(idp, { scenario: name, connection, rows, result: 'fail' });
    throw e;
  }
}

/** Polls the tenant's audit log for `action` on connection `slug` since `since`. */
async function auditFor(action: string, slug: string, since: string, reason?: string): Promise<AuditEvent> {
  let found: AuditEvent | undefined;
  await expect
    .poll(
      async () => {
        const events = await auditEvents(token, { action, from: since, limit: '200' }, INTEROP_TENANT);
        found = events.find((e) => e.details.connection === slug && (reason === undefined || e.details.reason === reason));
        return found !== undefined;
      },
      { message: `audit ${action} for ${slug}${reason ? ` (${reason})` : ''}`, timeout: 10_000 },
    )
    .toBe(true);
  if (!found) throw new Error('unreachable');
  return found;
}

/** The newest audit event of `action` on `slug` since `since`, whatever its reason. */
async function latestAudit(action: string, slug: string, since: string): Promise<AuditEvent> {
  return auditFor(action, slug, since);
}

function since(): string {
  return new Date(Date.now() - 2_000).toISOString();
}

async function userCount(): Promise<number> {
  return (await tenantUsers(token, INTEROP_TENANT)).length;
}

/** A fresh browser context (no IdP or AnvilID session); closed after `fn`. */
async function withFreshPage<T>(browser: Browser, fn: (page: Page) => Promise<T>): Promise<T> {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  try {
    return await fn(await context.newPage());
  } finally {
    await context.close();
  }
}

/**
 * The authorization-code flow with the org client, signing in through `slug` as `user` (the
 * routed address is `user@<slug domain>`). `atIdp` drives the IdP page (default: its login form).
 */
async function samlCodeFlow(
  page: Page,
  idp: InteropIdp,
  slug: string,
  user: IdpUser,
  opts: { extraParams?: Record<string, string>; atIdp?: (p: Page) => Promise<void>; afterIdp?: (p: Page) => Promise<void> } = {},
): Promise<{ tokens: TokenSet; response: ResponseFacts | undefined; capture: ReturnType<typeof captureSaml> }> {
  const capture = captureSaml(page, new URL(idp.baseUrl).origin);
  try {
    const tokens = await authorizationCodeFlow(
      page,
      client,
      'openid email profile',
      async (p) => {
        await chooseSso(p, `${user.username}@${domainOf(slug)}`);
        await (opts.atIdp ?? ((q) => idp.login(q, user)))(p);
        if (opts.afterIdp) await opts.afterIdp(p);
      },
      issuer,
      opts.extraParams ?? {},
    );
    return { tokens, response: capture.responses.at(-1), capture };
  } finally {
    capture.stop();
  }
}

/** Expects AnvilID's one generic SAML error page at the ACS of `slug` (no reason shown). */
async function expectGenericSamlError(page: Page, slug: string, reason: string): Promise<void> {
  const error = page.locator('#error-message');
  await expect(error).toHaveAttribute('data-error-key', 'saml_login_failed', { timeout: 30_000 });
  await expect(page).toHaveURL((url) => url.pathname === `/t/${INTEROP_TENANT}/ui/login/saml/${slug}/acs`);
  await expect(page.locator('main')).not.toContainText(reason);
}

/** From AnvilID's sign-in page: SSO through `slug` as `user`, ending on the generic error page. */
async function refusedSignIn(page: Page, idp: InteropIdp, slug: string, user: IdpUser): Promise<ResponseFacts | undefined> {
  const capture = captureSaml(page, new URL(idp.baseUrl).origin);
  try {
    await page.goto(`${issuer}/ui/login`);
    await chooseSso(page, `${user.username}@${domainOf(slug)}`);
    await idp.login(page, user);
    await expect(page.locator('#error-message')).toBeVisible({ timeout: 30_000 });
    return capture.responses.at(-1);
  } finally {
    capture.stop();
  }
}

/** The browser has no AnvilID session in the interop tenant. */
async function expectNoAnvilSession(page: Page): Promise<void> {
  await page.goto(`${issuer}/ui/account/sessions`);
  await expect(page).toHaveURL((url) => url.pathname === `/t/${INTEROP_TENANT}/ui/login`);
}

/** Base64 body of a PEM certificate, for comparisons. */
function pemBody(pem: string): string {
  return pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

async function patchSigningCerts(org: string, conn: OrgConnectionView, certs: string[]): Promise<void> {
  const current = (await adminCall<OrgConnectionView>(token, 'GET', connPath(org, `/connections/${conn.id}`))).config;
  const updated = await adminCall<OrgConnectionView>(token, 'PATCH', connPath(org, `/connections/${conn.id}`), {
    config: { ...current, signing_certs: certs },
  });
  expect((updated.config.signing_certs as string[]).map(pemBody)).toEqual(certs.map(pemBody));
}

// ---------------------------------------------------------------------------------------------
// per IdP

for (const idp of IDPS) {
  test.describe(`${idp.label} (${idp.image.split('@')[0]})`, () => {
    test.describe.configure({ mode: 'serial' });

    let org: OrgView;
    let roleName = '';
    const conns = new Map<string, OrgConnectionView>();
    let first: { sub: string; userId: string; response: ResponseFacts } | undefined;

    test.beforeAll(async () => {
      test.setTimeout(180_000);
      org = await createOrg(token, INTEROP_TENANT, { slug: idp.org, display_name: `${idp.label} interop` });
      roleName = `${idp.org}-member`;
      const role = await adminCall<{ id: string; name: string }>(
        token,
        'POST',
        connPath(org.id, '/roles'),
        { name: roleName, permissions: ['interop:read'] },
        201,
      );
      await adminCall(token, 'PATCH', connPath(org.id), { default_role_ids: [role.id] });

      await scenario(idp, 'metadata import by https URL; SP metadata matches the IdP template', idp.okSlug, [2], async () => {
        for (const slug of idp.slugs()) {
          const conn = await createOrgSamlConnection(
            token,
            INTEROP_TENANT,
            org.id,
            { metadataUrl: idp.metadataUrl },
            { slug, display_name: `${idp.label} ${slug}` },
            { attributes: idp.attributes },
          );
          const cfg = conn.config as { idp_entity_id: string; sso_url: string; signing_certs: string[] };
          expect(cfg.idp_entity_id.length).toBeGreaterThan(0);
          expect(cfg.sso_url).toMatch(/^https:\/\/127\.0\.0\.1:\d+\//);
          expect(cfg.signing_certs.length).toBeGreaterThanOrEqual(1);
          expect(conn.sp?.entity_id).toBe(spEntityId(slug));
          expect(conn.sp?.acs_url).toBe(acsUrl(slug));
          // The SP values the IdP template registered are what AnvilID publishes.
          const res = await fetch(`${issuer}/saml/${slug}/metadata`);
          expect(res.status).toBe(200);
          const xml = await res.text();
          expect(xml).toContain(`entityID="${spEntityId(slug)}"`);
          expect(xml).toContain(`Location="${acsUrl(slug)}"`);
          conns.set(slug, conn);

          const claim = await addVerifiedDomain(token, INTEROP_TENANT, org.id, domainOf(slug));
          dnsRecords.push(claim.record_name);
          const routed = await patchDomainRouting(token, INTEROP_TENANT, org.id, claim.id, {
            connection_id: conn.id,
            routing: true,
          });
          expect(routed.routing).toBe(true);
        }
        const ok = conns.get(idp.okSlug)?.config as { idp_entity_id: string; sso_url: string };
        return { idp_entity_id_is_https: ok.idp_entity_id.startsWith('https://'), connections: idp.slugs().length };
      });
    });

    test('1. SP-initiated sign-in: JIT user, mapped profile, membership, signed assertion', async ({ page }) => {
      test.setTimeout(120_000);
      await scenario(idp, 'SP-initiated sign-in (JIT)', idp.okSlug, [1, 3, 4, 5, 6, 16], async () => {
        const t0 = since();
        const before = await userCount();
        const { tokens, response, capture } = await samlCodeFlow(page, idp, idp.okSlug, idp.alice);

        expect(capture.requests).toHaveLength(1);
        const req = capture.requests[0];
        expect(req.issuer).toBe(spEntityId(idp.okSlug));
        expect(req.acsUrl).toBe(acsUrl(idp.okSlug));
        expect(req.nameIdPolicyFormat).toBe(PERSISTENT);
        expect(req.forceAuthn).toBe(false);

        if (!response) throw new Error('no SAMLResponse captured');
        expect(response.encryptedAssertion).toBe(false);
        expect(response.assertionSigned).toBe(true);
        expect(response.signatureMethods.length).toBeGreaterThan(0);
        for (const m of response.signatureMethods) expect(STRONG_SIGNATURE_METHODS).toContain(m);
        for (const m of response.digestMethods) expect(STRONG_DIGEST_METHODS).toContain(m);
        expect([PERSISTENT, UNSPECIFIED]).toContain(response.nameIdFormat);

        if (!tokens.id_token) throw new Error('no id_token');
        const claims = jwtClaims(tokens.id_token);
        expect(claims.org_id).toBe(org.id);
        expect(await userCount()).toBe(before + 1);
        const u = (await tenantUsers(token, INTEROP_TENANT)).find((x) => x.email === idp.alice.email);
        if (!u) throw new Error('JIT user missing');
        expect(u.id).toBe(claims.sub);
        expect(u.email_verified).toBe(true);
        expect(u.claims.given_name).toBe(idp.alice.givenName);
        expect(u.claims.family_name).toBe(idp.alice.familyName);
        expect((await orgMembers(token, INTEROP_TENANT, org.id)).map((m) => m.user_id)).toContain(u.id);
        expect((await orgMemberRoles(token, INTEROP_TENANT, org.id, u.id)).map((r) => r.name)).toContain(roleName);
        await auditFor('saml_login_succeeded', idp.okSlug, t0);

        first = { sub: u.id, userId: u.id, response };
        return observedFacts(response);
      });
    });

    test('2. a second sign-in in a fresh browser reuses the link and sub', async ({ browser }) => {
      test.setTimeout(120_000);
      await scenario(idp, 'second sign-in, same link', idp.okSlug, [7], async () => {
        if (!first) throw new Error('scenario 1 did not complete');
        const before = await userCount();
        const { tokens, response } = await withFreshPage(browser, (p) => samlCodeFlow(p, idp, idp.okSlug, idp.alice));
        if (!tokens.id_token) throw new Error('no id_token');
        expect(jwtClaims(tokens.id_token).sub).toBe(first.sub);
        expect(await userCount()).toBe(before);
        return { name_id_format: response?.nameIdFormat ?? null, same_sub: true };
      });
    });

    test('3. prompt=login sends ForceAuthn and the IdP asks for credentials again', async ({ page }) => {
      test.setTimeout(120_000);
      await scenario(idp, 'prompt=login -> ForceAuthn', idp.okSlug, [8], async () => {
        // Establish an IdP (and AnvilID) session in this browser.
        await samlCodeFlow(page, idp, idp.okSlug, idp.alice);
        const { capture } = await samlCodeFlow(page, idp, idp.okSlug, idp.alice, {
          extraParams: { prompt: 'login' },
          atIdp: async (p) => {
            // The IdP session exists, yet the IdP shows its login form again.
            await idp.expectLoginForm(p);
            await idp.login(p, idp.alice);
          },
        });
        expect(capture.requests).toHaveLength(1);
        expect(capture.requests[0].forceAuthn).toBe(true);
        return { force_authn: true, idp_asked_again: true };
      });
    });

    for (const accepted of idp.accepted) {
      test(`4. other signing setup accepted: ${accepted.slug}`, async ({ page }) => {
        test.setTimeout(120_000);
        await scenario(idp, `accepted: ${accepted.setup}`, accepted.slug, [3], async () => {
          const t0 = since();
          const { tokens, response } = await samlCodeFlow(page, idp, accepted.slug, idp.bob);
          if (!tokens.id_token || !response) throw new Error('sign-in incomplete');
          expect(response.assertionSigned).toBe(true);
          for (const m of response.signatureMethods) expect(STRONG_SIGNATURE_METHODS).toContain(m);
          const u = (await tenantUsers(token, INTEROP_TENANT)).find((x) => x.email === idp.bob.email);
          expect(u?.id).toBe(jwtClaims(tokens.id_token).sub);
          await auditFor('saml_login_succeeded', accepted.slug, t0);
          return observedFacts(response);
        });
      });
    }

    test('5. IdP-initiated SSO is refused with the generic error', async ({ page }) => {
      test.setTimeout(120_000);
      await scenario(idp, 'IdP-initiated SSO refused', idp.okSlug, [9, 16], async () => {
        const t0 = since();
        const capture = captureSaml(page, new URL(idp.baseUrl).origin);
        try {
          await page.goto(idp.idpInitiatedUrl(idp.okSlug, spEntityId(idp.okSlug)));
          await idp.login(page, idp.alice);
          await expectGenericSamlError(page, idp.okSlug, 'relay');
          await expectNoA11yViolations(page);
        } finally {
          capture.stop();
        }
        expect(capture.requests).toHaveLength(0);
        expect(capture.responses).toHaveLength(1);
        await auditFor('saml_login_failed', idp.okSlug, t0, 'relay_state');
        await expectNoAnvilSession(page);
        return { ...observedFacts(capture.responses[0]), reason: 'relay_state' };
      });
    });

    test('6. replaying the captured response is refused', async ({ page }) => {
      test.setTimeout(60_000);
      await scenario(idp, 'replayed response refused', idp.okSlug, [10, 16], async () => {
        if (!first) throw new Error('scenario 1 did not complete');
        const t0 = since();
        const before = await userCount();
        await replayResponse(page, first.response);
        await expectGenericSamlError(page, idp.okSlug, 'replay');
        const event = await latestAudit('saml_login_failed', idp.okSlug, t0);
        // The flow of scenario 1 is finished, so the RelayState no longer leads to a pending
        // request; a replay to a still-pending flow would hit the assertion-id replay guard.
        expect(['replay', 'relay_state', 'no_pending_request']).toContain(event.details.reason);
        expect(await userCount()).toBe(before);
        await expectNoAnvilSession(page);
        return { reason: event.details.reason };
      });
    });

    for (const refusal of idp.refusals) {
      test(`7. refused: ${refusal.slug} (${refusal.reason})`, async ({ page }) => {
        test.setTimeout(120_000);
        await scenario(idp, `refused: ${refusal.setup}`, refusal.slug, [...refusal.rows, 16], async () => {
          const t0 = since();
          const before = await userCount();
          const response = await refusedSignIn(page, idp, refusal.slug, idp.alice);
          await expectGenericSamlError(page, refusal.slug, refusal.reason);
          await auditFor('saml_login_failed', refusal.slug, t0, refusal.reason);
          expect(await userCount()).toBe(before);
          return { ...observedFacts(response), reason: refusal.reason };
        });
      });
    }

    if (idp.id === 'keycloak') {
      test('8. JIT rule: an address outside the verified domains gets no account', async ({ page }) => {
        test.setTimeout(120_000);
        await scenario(idp, 'JIT refused for an unverified domain', idp.okSlug, [6, 16], async () => {
          const mallory: IdpUser = {
            username: 'mallory',
            email: 'mallory@outside.example.test',
            givenName: 'Mallory',
            familyName: 'Outside',
          };
          const t0 = since();
          const before = await userCount();
          const membersBefore = (await orgMembers(token, INTEROP_TENANT, org.id)).length;
          await page.goto(`${issuer}/ui/login`);
          // A routed address on the org's domain; the IdP then asserts mallory's outside address.
          await chooseSso(page, `mallory-${randomBytes(3).toString('hex')}@${domainOf(idp.okSlug)}`);
          await idp.login(page, mallory);
          await expect(page.locator('[data-message-key="upstream.failed"]')).toBeVisible({ timeout: 30_000 });
          await auditFor('saml_login_succeeded', idp.okSlug, t0);
          await auditFor('upstream_login_failed', idp.okSlug, t0, 'no_account');
          expect(await userCount()).toBe(before);
          expect((await tenantUsers(token, INTEROP_TENANT)).some((u) => u.email === mallory.email)).toBe(false);
          expect((await orgMembers(token, INTEROP_TENANT, org.id)).length).toBe(membersBefore);
          return { reason: 'no_account' };
        });
      });

      test('9. the org MFA policy applies after a SAML sign-in', async ({ page }) => {
        test.setTimeout(120_000);
        // bob signed in through kc-both in scenario 4; alice stays without a second factor for
        // the rollover sign-ins.
        const slug = 'kc-both';
        await scenario(idp, 'org MFA policy after SAML sign-in', slug, [15], async () => {
          await adminCall(token, 'PATCH', connPath(org.id), { mfa_policy: 'required' });
          try {
            const { tokens } = await samlCodeFlow(page, idp, slug, idp.bob, {
              afterIdp: async (p) => {
                await expect(p.locator('form#mfa-enroll')).toBeVisible({ timeout: 30_000 });
                await expect(p.locator('#mfa-enroll-required')).toBeVisible();
                const secret = ((await p.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
                await p.locator('#code').fill(totp(secret));
                await p.locator('#mfa-enroll-submit').click();
                await expect(p.locator('#recovery-codes li')).toHaveCount(10);
                await p.locator('#link-continue').click();
              },
            });
            if (!tokens.id_token) throw new Error('no id_token');
            const claims = jwtClaims(tokens.id_token);
            expect(claims.amr).toEqual(expect.arrayContaining(['fed', 'mfa']));
            return { amr: claims.amr };
          } finally {
            await adminCall(token, 'PATCH', connPath(org.id), { mfa_policy: null });
          }
        });
      });

      test('10. certificate rollover, then a connection pinned to the retired key is refused', async ({ browser }) => {
        test.setTimeout(300_000);
        const slug = idp.okSlug;
        const conn = conns.get(slug);
        if (!conn) throw new Error('no kc-ok connection');
        const kc = await KeycloakAdmin.connect(idp.baseUrl);
        const signIn = () => withFreshPage(browser, (p) => samlCodeFlow(p, idp, slug, idp.alice));

        await scenario(idp, 'certificate rollover', slug, [12], async () => {
          const old = await kc.activeRsaKey();
          if (!old.certificate) throw new Error('Keycloak key without certificate');
          const oldPem = pemOf(old.certificate);
          expect((conn.config.signing_certs as string[]).map(pemBody)).toContain(pemBody(oldPem));

          // 1. A new key at a lower priority: Keycloak still signs with the old one.
          const newId = await kc.addRsaKey('interop-rollover', 10);
          const added = (await kc.keys()).find((k) => k.providerId === newId && k.algorithm === 'RS256');
          if (!added?.certificate) throw new Error('new Keycloak key not listed');
          const newPem = pemOf(added.certificate);
          const descriptor = await (await fetch(idp.metadataUrl)).text();
          expect(descriptor).toContain(added.certificate);
          // 2. Add the new certificate as a second entry.
          await patchSigningCerts(org.id, conn, [oldPem, newPem]);
          await signIn();
          // 3. Switch the IdP to the new key, then retire the old one.
          await kc.setKeyConfig(newId, { priority: '200' });
          expect((await kc.activeRsaKey()).kid).toBe(added.kid);
          await signIn();
          await kc.setKeyConfig(old.providerId, { active: 'false' });
          await signIn();
          // 4. Remove the old certificate.
          await patchSigningCerts(org.id, conn, [newPem]);
          await signIn();

          // 5. Pinned only to the retired key: refused.
          await patchSigningCerts(org.id, conn, [oldPem]);
          const t0 = since();
          await withFreshPage(browser, async (p) => {
            await refusedSignIn(p, idp, slug, idp.alice);
            await expectGenericSamlError(p, slug, 'key');
          });
          const event = await latestAudit('saml_login_failed', slug, t0);
          expect(['untrusted_key', 'signature']).toContain(event.details.reason);
          await patchSigningCerts(org.id, conn, [newPem]);
          return { retired_key_reason: event.details.reason };
        });
      });
    }
  });
}
