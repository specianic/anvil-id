// Self-test of the local mock SAML IdP (lib/mock-saml-idp.ts). Needs no AnvilID: requests are built
// here, and a small echo server stands in for AnvilID's ACS in the browser test.

import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { X509Certificate } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { SignedXml } from 'xml-crypto';
import { encodeRedirectSamlRequest, startMockSamlIdp, type MockSamlIdp } from '../lib/mock-saml-idp';

const SP_ENTITY_ID = 'http://localhost:8080/saml/acme';
const ACS_URL = 'http://localhost:8080/ui/login/saml/acme/acs';

function authnRequest(id: string | null, acsUrl = ACS_URL, issuer = SP_ENTITY_ID): string {
  return (
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    (id === null ? '' : ` ID="${id}"`) +
    ` Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="http://127.0.0.1/sso"` +
    ` AssertionConsumerServiceURL="${acsUrl}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">` +
    `<saml:Issuer>${issuer}</saml:Issuer></samlp:AuthnRequest>`
  );
}

function redirectUrl(idp: MockSamlIdp, xml: string, relayState?: string): string {
  const url = new URL(idp.ssoUrl);
  url.searchParams.set('SAMLRequest', encodeRedirectSamlRequest(xml));
  if (relayState !== undefined) url.searchParams.set('RelayState', relayState);
  return url.href;
}

function htmlUnescape(value: string): string {
  return value.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

interface PostedForm {
  action: string;
  fields: Record<string, string>;
}

async function fetchForm(url: string): Promise<PostedForm> {
  const res = await fetch(url);
  expect(res.status).toBe(200);
  const html = await res.text();
  expect(html).toContain('document.forms[0].submit()');
  expect(html).toContain('id="mock-saml-continue"');
  const action = /<form[^>]*action="([^"]*)"/.exec(html);
  if (!action) throw new Error('no form in mock response');
  const fields: Record<string, string> = {};
  for (const m of html.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)">/g)) fields[htmlUnescape(m[1])] = htmlUnescape(m[2]);
  return { action: htmlUnescape(action[1]), fields };
}

function decodeResponse(form: PostedForm): string {
  return Buffer.from(form.fields.SAMLResponse, 'base64').toString('utf8');
}

function attr(xml: string, element: string, name: string): string | undefined {
  const el = new RegExp(`<${element}\\b[^>]*>`).exec(xml);
  if (!el) return undefined;
  return new RegExp(`\\s${name}="([^"]*)"`).exec(el[0])?.[1];
}

function text(xml: string, element: string): string | undefined {
  return new RegExp(`<${element}\\b[^>]*>([^<]*)</${element}>`).exec(xml)?.[1];
}

/** Verifies the single ds:Signature with xml-crypto against `certPem`; returns the signed reference URIs. */
function verifySignature(xml: string, certPem: string): { valid: boolean; references: string[] } {
  const signature = /<ds:Signature\b[\s\S]*?<\/ds:Signature>/.exec(xml);
  if (!signature) throw new Error('no ds:Signature');
  const sig = new SignedXml({ publicCert: certPem });
  sig.loadSignature(signature[0]);
  let valid: boolean;
  try {
    valid = sig.checkSignature(xml);
  } catch {
    valid = false;
  }
  return { valid, references: sig.getReferences().map((r) => r.uri ?? '') };
}

test.describe('mock SAML IdP', () => {
  let idp: MockSamlIdp;

  test.beforeEach(async () => {
    idp = await startMockSamlIdp();
  });

  test.afterEach(async () => {
    await idp.close();
  });

  test('publishes a usable self-signed certificate and IdP metadata', async () => {
    const cert = new X509Certificate(idp.certPem);
    expect(cert.verify(cert.publicKey)).toBe(true);
    expect(cert.publicKey.asymmetricKeyType).toBe('rsa');
    expect(new Date(cert.validTo).getTime()).toBeGreaterThan(Date.now());
    expect(idp.certPem).not.toContain('PRIVATE KEY');

    const md = idp.metadataXml;
    expect(attr(md, 'md:EntityDescriptor', 'entityID')).toBe(idp.entityId);
    expect(md).toContain('<md:IDPSSODescriptor');
    expect(md).toContain('<md:KeyDescriptor use="signing">');
    const body = idp.certPem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
    expect(text(md, 'ds:X509Certificate')).toBe(body);
    expect(attr(md, 'md:SingleSignOnService', 'Binding')).toBe('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    expect(attr(md, 'md:SingleSignOnService', 'Location')).toBe(idp.ssoUrl);

    const served = await fetch(`${idp.url}/metadata`);
    expect(served.status).toBe(200);
    expect(await served.text()).toBe(md);
  });

  test('answers an AuthnRequest with a signed assertion that verifies against the published cert', async () => {
    idp.setUser({ id: 'user-42', email: 'ada@example.test', givenName: 'Ada', familyName: 'Lovelace' });
    const form = await fetchForm(redirectUrl(idp, authnRequest('_req123'), 'relay-abc'));
    expect(form.action).toBe(ACS_URL);
    expect(form.fields.RelayState).toBe('relay-abc');
    const xml = decodeResponse(form);

    expect(attr(xml, 'samlp:Response', 'InResponseTo')).toBe('_req123');
    expect(attr(xml, 'samlp:Response', 'Destination')).toBe(ACS_URL);
    expect(attr(xml, 'saml:SubjectConfirmationData', 'InResponseTo')).toBe('_req123');
    expect(attr(xml, 'saml:SubjectConfirmationData', 'Recipient')).toBe(ACS_URL);
    expect(text(xml, 'saml:Audience')).toBe(SP_ENTITY_ID);
    expect(text(xml, 'saml:NameID')).toBe('user-42');
    expect(xml).toContain('<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>ada@example.test</saml:AttributeValue>');
    expect(xml).toContain('<saml:AttributeValue>Ada</saml:AttributeValue>');
    expect(xml).toContain('<saml:AttributeValue>Lovelace</saml:AttributeValue>');
    const notBefore = Date.parse(attr(xml, 'saml:Conditions', 'NotBefore') ?? '');
    const notOnOrAfter = Date.parse(attr(xml, 'saml:Conditions', 'NotOnOrAfter') ?? '');
    expect(notBefore).toBeLessThan(Date.now());
    expect(notOnOrAfter).toBeGreaterThan(Date.now());

    // Exactly one signature: a direct child of the Assertion, right after its Issuer, over #{assertion ID}.
    expect(xml.match(/<ds:Signature\b/g)).toHaveLength(1);
    const assertionId = attr(xml, 'saml:Assertion', 'ID');
    expect(assertionId).toBeTruthy();
    expect(xml).toMatch(/<saml:Assertion\b[^>]*><saml:Issuer>[^<]*<\/saml:Issuer><ds:Signature\b/);
    expect(xml).toContain('Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"');
    expect(xml).toContain('Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"');
    expect(xml).toContain('Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"');
    const { valid, references } = verifySignature(xml, idp.certPem);
    expect(valid).toBe(true);
    expect(references).toEqual([`#${assertionId}`]);

    // Tampering with the signed assertion breaks the signature (the verification above is meaningful).
    const tampered = xml.replace('<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">user-42<', '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">admin<');
    expect(tampered).not.toBe(xml);
    expect(verifySignature(tampered, idp.certPem).valid).toBe(false);

    expect(idp.requests).toEqual([{ id: '_req123', acsUrl: ACS_URL, issuer: SP_ENTITY_ID, relayState: 'relay-abc', variant: 'ok' }]);
  });

  test('a signature does not verify under a different IdP certificate', async () => {
    const other = await startMockSamlIdp();
    try {
      const xml = decodeResponse(await fetchForm(redirectUrl(idp, authnRequest('_req-other'))));
      expect(verifySignature(xml, idp.certPem).valid).toBe(true);
      expect(verifySignature(xml, other.certPem).valid).toBe(false);
    } finally {
      await other.close();
    }
  });

  test('bad variants change exactly the documented property', async () => {
    idp.setVariant('wrong-audience');
    let xml = decodeResponse(await fetchForm(redirectUrl(idp, authnRequest('_v1'))));
    expect(text(xml, 'saml:Audience')).not.toBe(SP_ENTITY_ID);
    expect(attr(xml, 'saml:SubjectConfirmationData', 'Recipient')).toBe(ACS_URL);
    expect(verifySignature(xml, idp.certPem).valid).toBe(true);

    idp.setVariant('wrong-recipient');
    xml = decodeResponse(await fetchForm(redirectUrl(idp, authnRequest('_v2'))));
    expect(attr(xml, 'saml:SubjectConfirmationData', 'Recipient')).not.toBe(ACS_URL);
    expect(attr(xml, 'samlp:Response', 'Destination')).toBe(ACS_URL);
    expect(text(xml, 'saml:Audience')).toBe(SP_ENTITY_ID);
    expect(verifySignature(xml, idp.certPem).valid).toBe(true);

    idp.setVariant('expired');
    xml = decodeResponse(await fetchForm(redirectUrl(idp, authnRequest('_v3'))));
    expect(Date.parse(attr(xml, 'saml:Conditions', 'NotOnOrAfter') ?? '')).toBeLessThan(Date.now() - 60_000);
    expect(Date.parse(attr(xml, 'saml:SubjectConfirmationData', 'NotOnOrAfter') ?? '')).toBeLessThan(Date.now() - 60_000);
    expect(verifySignature(xml, idp.certPem).valid).toBe(true);

    idp.setVariant('unsigned');
    xml = decodeResponse(await fetchForm(redirectUrl(idp, authnRequest('_v4'))));
    expect(xml).not.toContain('Signature');
    expect(attr(xml, 'samlp:Response', 'InResponseTo')).toBe('_v4');

    expect(idp.requests.map((r) => r.variant)).toEqual(['wrong-audience', 'wrong-recipient', 'expired', 'unsigned']);
    expect(() => idp.setVariant('nope' as never)).toThrow();
  });

  test('rejects malformed requests with 400', async () => {
    const noId = await fetch(redirectUrl(idp, authnRequest(null)));
    expect(noId.status).toBe(400);
    expect(await noId.text()).toContain('without ID');

    const missing = await fetch(idp.ssoUrl);
    expect(missing.status).toBe(400);

    const garbage = await fetch(`${idp.ssoUrl}?SAMLRequest=${encodeURIComponent('bm90LWRlZmxhdGU=')}`);
    expect(garbage.status).toBe(400);

    const post = await fetch(idp.ssoUrl, { method: 'POST' });
    expect(post.status).toBe(405);
    expect(idp.requests).toEqual([]);
  });

  test('the browser auto-submits SAMLResponse and RelayState to the ACS', async ({ page }) => {
    const received: Record<string, string>[] = [];
    const acs: Server = createServer((req: IncomingMessage, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        if (req.method === 'POST') received.push(Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8'))));
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><title>acs</title><p id="acs">received</p>');
      });
    });
    await new Promise<void>((resolve) => acs.listen(0, '127.0.0.1', () => resolve()));
    const acsUrl = `http://localhost:${(acs.address() as AddressInfo).port}/ui/login/saml/acme/acs`;
    try {
      await page.goto(redirectUrl(idp, authnRequest('_browser', acsUrl), 'rs-1'));
      await expect(page.locator('#acs')).toHaveText('received');
      expect(received).toHaveLength(1);
      expect(received[0].RelayState).toBe('rs-1');
      const xml = Buffer.from(received[0].SAMLResponse, 'base64').toString('utf8');
      expect(attr(xml, 'samlp:Response', 'Destination')).toBe(acsUrl);
      expect(verifySignature(xml, idp.certPem).valid).toBe(true);
    } finally {
      acs.closeAllConnections();
      await new Promise<void>((resolve) => acs.close(() => resolve()));
    }
  });
});
