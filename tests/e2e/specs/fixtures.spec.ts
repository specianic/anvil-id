// Self-tests for the e2e fixtures. They need no AnvilID server.

import { generateKeyPairSync } from 'node:crypto';
import { expect, test as base } from '@playwright/test';
import { base32Decode, base32Encode, totp } from '../lib/totp';
import { WCAG_TAGS } from '../fixtures/axe';
import { test } from '../fixtures/webauthn';

// RFC 6238 Appendix B, SHA-1 seed "12345678901234567890". The appendix lists 8-digit values; the
// 6-digit codes are their last six digits.
const RFC6238_SECRET = base32Encode(Buffer.from('12345678901234567890', 'ascii'));

base('base32 round-trips and decodes the RFC 4648 vectors', () => {
  expect(RFC6238_SECRET).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  expect(base32Decode('MZXW6YTBOI======').toString('ascii')).toBe('foobar');
  expect(base32Decode('mzxw6ytboi').toString('ascii')).toBe('foobar');
  expect(() => base32Decode('M1')).toThrow();
});

base('totp matches the RFC 6238 SHA-1 test vectors', () => {
  expect(totp(RFC6238_SECRET, 59)).toBe('287082');
  expect(totp(RFC6238_SECRET, 1111111109)).toBe('081804');
  expect(totp(RFC6238_SECRET, 1111111111)).toBe('050471');
  expect(totp(RFC6238_SECRET, 1234567890)).toBe('005924');
  expect(totp(RFC6238_SECRET, 2000000000)).toBe('279037');
  expect(totp(RFC6238_SECRET, 20000000000)).toBe('353130');
  expect(totp(RFC6238_SECRET)).toMatch(/^\d{6}$/);
});

base('axe audit uses the WCAG 2.2 AA tag set', () => {
  expect([...WCAG_TAGS]).toEqual(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']);
});

test('virtual authenticator attaches, creates a resident credential and tampers on request', async ({
  page,
  authenticator,
}) => {
  await page.goto('about:blank');
  expect(authenticator.authenticatorId).not.toBe('');
  expect(await authenticator.getCredentials()).toEqual([]);

  // A credential added through CDP is visible, and its counter can be rewritten.
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
  const credentialId = Buffer.from('fixture-self-test').toString('base64');
  await authenticator.cdp.send('WebAuthn.addCredential', {
    authenticatorId: authenticator.authenticatorId,
    credential: {
      credentialId,
      isResidentCredential: true,
      rpId: 'localhost',
      privateKey: pkcs8,
      userHandle: Buffer.from('user-1').toString('base64'),
      signCount: 1,
    },
  });
  const creds = await authenticator.getCredentials();
  expect(creds).toHaveLength(1);
  expect(creds[0].isResidentCredential).toBe(true);
  expect(creds[0].signCount).toBe(1);

  await authenticator.setSignCount(credentialId, 42);
  expect((await authenticator.getCredentials())[0].signCount).toBe(42);

  await authenticator.overrideResponse({ isBogusSignature: true });
  await authenticator.overrideResponse({});
  await authenticator.setUserVerified(false);
});
