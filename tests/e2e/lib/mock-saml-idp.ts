// Local mock SAML 2.0 identity provider for the SAML e2e tests (test tooling only, never shipped).
//
// Profile (the one AnvilID's SP accepts, see 06-RESEARCH "Supported profile"):
//   - SP-initiated. `GET {ssoUrl}?SAMLRequest=...&RelayState=...` (HTTP-Redirect binding: SAMLRequest is
//     base64(DEFLATE(AuthnRequest XML))). The request's `ID`, `AssertionConsumerServiceURL` and `Issuer`
//     are read with minimal string parsing (acceptable in test tooling); a request without any of them
//     gets a 400.
//   - The answer is an HTML page with an auto-submitting form (plus a visible submit button for no-JS
//     browsers) that POSTs `SAMLResponse` (base64 of the Response XML) and `RelayState` to the ACS URL
//     (HTTP-POST binding).
//   - The `saml:Assertion` carries an enveloped XML-DSig signature (RSA-SHA256, SHA-256 digest, exc-c14n,
//     transforms [enveloped-signature, exc-c14n]) whose single Reference is `#{assertion ID}`, placed as a
//     direct child of the assertion right after `saml:Issuer`. The Response itself is not signed.
//   - InResponseTo = request ID, Destination = Recipient = ACS URL, Audience = the request's Issuer
//     (the SP entity ID), NotBefore/NotOnOrAfter = now -/+ 5 minutes, NameID = the configured user's id,
//     attributes email / given_name / family_name.
//
// Bad variants for the negative e2e cases (setVariant): `wrong-audience`, `wrong-recipient`, `expired`,
// `unsigned`. Each changes exactly one property of an otherwise valid response.
//
// The RSA key pair and the self-signed certificate are generated at start-up, held in memory only and
// never written anywhere. Only the certificate (certPem, metadataXml) leaves the process. The server
// binds 127.0.0.1 on a free port unless `port` is given.

import { createPrivateKey, generateKeyPairSync, randomBytes, randomUUID, sign, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { SignedXml } from 'xml-crypto';

export type SamlVariant = 'ok' | 'wrong-audience' | 'wrong-recipient' | 'expired' | 'unsigned';

export interface SamlUser {
  /** NameID value (persistent format). */
  id: string;
  email: string;
  givenName?: string;
  familyName?: string;
}

/** One AuthnRequest the mock received, for assertions. */
export interface SamlRequestLog {
  id: string;
  acsUrl: string;
  issuer: string;
  relayState: string | null;
  variant: SamlVariant;
}

export interface MockSamlIdpOptions {
  /** IdP entity ID. Default: `{url}/metadata`. */
  entityId?: string;
  /** Path of the SSO endpoint. Default: `/sso`. */
  ssoPath?: string;
  /** Port to bind on 127.0.0.1. Default: 0 (a free port). */
  port?: number;
}

export interface MockSamlIdp {
  /** Base URL, e.g. http://127.0.0.1:41234 */
  url: string;
  /** SingleSignOnService URL (HTTP-Redirect binding). */
  ssoUrl: string;
  entityId: string;
  /** The signing certificate (PEM). */
  certPem: string;
  /** EntityDescriptor with IDPSSODescriptor, signing KeyDescriptor and SingleSignOnService. Also served at GET /metadata. */
  metadataXml: string;
  /** AuthnRequests received so far, oldest first. */
  requests: SamlRequestLog[];
  setUser(user: SamlUser): void;
  setVariant(variant: SamlVariant): void;
  close(): Promise<void>;
}

export const SAML_NS = {
  protocol: 'urn:oasis:names:tc:SAML:2.0:protocol',
  assertion: 'urn:oasis:names:tc:SAML:2.0:assertion',
  metadata: 'urn:oasis:names:tc:SAML:2.0:metadata',
  dsig: 'http://www.w3.org/2000/09/xmldsig#',
  redirectBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
  postBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
} as const;

const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
const SKEW_MS = 5 * 60 * 1000;

// ---------------------------------------------------------------------------------------------------
// Self-signed X.509 certificate. node:crypto can parse certificates (X509Certificate) but not create
// them, so this is a minimal DER encoder for exactly one shape:
//
//   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
//   TBSCertificate ::= SEQUENCE {
//     [0] EXPLICIT version (v3 = 2), serialNumber INTEGER, signature AlgorithmIdentifier,
//     issuer Name, validity SEQUENCE { notBefore, notAfter }, subject Name, subjectPublicKeyInfo }
//
// issuer == subject == CN=<commonName>; no extensions; sha256WithRSAEncryption.
// ---------------------------------------------------------------------------------------------------

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  for (let n = len; n > 0; n >>= 8) bytes.unshift(n & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, ...content: Buffer[]): Buffer {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

function derOid(oid: string): Buffer {
  const parts = oid.split('.').map(Number);
  const bytes: number[] = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const enc: number[] = [part & 0x7f];
    for (let n = part >> 7; n > 0; n >>= 7) enc.unshift(0x80 | (n & 0x7f));
    bytes.push(...enc);
  }
  return der(0x06, Buffer.from(bytes));
}

function derUtcTime(date: Date): Buffer {
  // YYMMDDHHMMSSZ (valid for 1950-2049, enough for test certificates).
  const iso = date.toISOString();
  const text = iso.slice(2, 4) + iso.slice(5, 7) + iso.slice(8, 10) + iso.slice(11, 13) + iso.slice(14, 16) + iso.slice(17, 19) + 'Z';
  return der(0x17, Buffer.from(text, 'ascii'));
}

function derName(commonName: string): Buffer {
  // Name ::= SEQUENCE OF SET OF SEQUENCE { OID 2.5.4.3 (CN), UTF8String }
  return der(0x30, der(0x31, der(0x30, derOid('2.5.4.3'), der(0x0c, Buffer.from(commonName, 'utf8')))));
}

/** Creates a self-signed RSA certificate (PEM) for the given key pair. */
export function selfSignedCertPem(privateKey: KeyObject, publicKey: KeyObject, commonName: string, validDays = 7): string {
  const sha256WithRsa = der(0x30, derOid('1.2.840.113549.1.1.11'), der(0x05));
  const serial = randomBytes(16);
  serial[0] &= 0x7f; // positive INTEGER
  serial[0] |= 0x01; // and no leading zero byte
  const now = Date.now();
  const tbs = der(
    0x30,
    der(0xa0, der(0x02, Buffer.from([0x02]))),
    der(0x02, serial),
    sha256WithRsa,
    derName(commonName),
    der(0x30, derUtcTime(new Date(now - 60 * 60 * 1000)), derUtcTime(new Date(now + validDays * 24 * 60 * 60 * 1000))),
    derName(commonName),
    publicKey.export({ type: 'spki', format: 'der' }),
  );
  const signature = sign('sha256', tbs, privateKey);
  const certDer = der(0x30, tbs, sha256WithRsa, der(0x03, Buffer.from([0x00]), signature));
  // Round-trip through node's parser so a malformed encoding fails here, not in the SP.
  const cert = new X509Certificate(certDer);
  if (!cert.verify(publicKey)) throw new Error('mock-saml-idp: self-signed certificate does not verify');
  return cert.toString();
}

/** The base64 body of a PEM certificate (what goes into ds:X509Certificate). */
export function pemBody(pem: string): string {
  return pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
}

// ---------------------------------------------------------------------------------------------------
// XML helpers
// ---------------------------------------------------------------------------------------------------

export function escapeXml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function unescapeXml(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/** Encodes an AuthnRequest for the HTTP-Redirect binding: base64(raw DEFLATE(xml)). */
export function encodeRedirectSamlRequest(xml: string): string {
  return deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
}

/** Decodes an HTTP-Redirect `SAMLRequest` value back to XML. */
export function decodeRedirectSamlRequest(samlRequest: string): string {
  return inflateRawSync(Buffer.from(samlRequest, 'base64')).toString('utf8');
}

interface ParsedAuthnRequest {
  id: string;
  acsUrl: string;
  issuer: string;
}

/** Minimal string parsing of an AuthnRequest: the root element's ID / AssertionConsumerServiceURL and the Issuer text. */
export function parseAuthnRequest(xml: string): ParsedAuthnRequest | { error: string } {
  const root = /<(?:[A-Za-z_][\w.-]*:)?AuthnRequest\b([^>]*)>/.exec(xml);
  if (!root) return { error: 'not an AuthnRequest' };
  const attr = (name: string): string | undefined => {
    const m = new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)')`).exec(root[1]);
    return m ? unescapeXml(m[2] ?? m[3]) : undefined;
  };
  const id = attr('ID');
  if (!id) return { error: 'AuthnRequest without ID' };
  const acsUrl = attr('AssertionConsumerServiceURL');
  if (!acsUrl) return { error: 'AuthnRequest without AssertionConsumerServiceURL' };
  const issuerMatch = /<(?:[A-Za-z_][\w.-]*:)?Issuer\b[^>]*>([^<]*)<\/(?:[A-Za-z_][\w.-]*:)?Issuer>/.exec(xml);
  const issuer = issuerMatch ? unescapeXml(issuerMatch[1]).trim() : '';
  if (!issuer) return { error: 'AuthnRequest without Issuer' };
  return { id, acsUrl, issuer };
}

function isoNoMillis(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

interface ResponseParams {
  idpEntityId: string;
  request: ParsedAuthnRequest;
  user: SamlUser;
  variant: SamlVariant;
  privateKeyPem: string;
  certPem: string;
  now?: number;
}

/** Builds the (optionally signed) SAML Response XML for one AuthnRequest. Exported for the self-test. */
export function buildSamlResponse(p: ResponseParams): string {
  const now = p.now ?? Date.now();
  const responseId = `_r${randomUUID().replace(/-/g, '')}`;
  const assertionId = `_a${randomUUID().replace(/-/g, '')}`;
  const issueInstant = isoNoMillis(now);
  const expired = p.variant === 'expired';
  // `expired`: a window that closed 5 minutes ago (beyond any reasonable skew allowance).
  const notBefore = isoNoMillis(expired ? now - 3 * SKEW_MS : now - SKEW_MS);
  const notOnOrAfter = isoNoMillis(expired ? now - SKEW_MS : now + SKEW_MS);
  const audience = p.variant === 'wrong-audience' ? `${p.request.issuer}/wrong-audience` : p.request.issuer;
  const recipient = p.variant === 'wrong-recipient' ? new URL('/wrong-acs', p.request.acsUrl).href : p.request.acsUrl;
  const x = escapeXml;

  const attribute = (name: string, value: string | undefined): string =>
    value === undefined
      ? ''
      : `<saml:Attribute Name="${x(name)}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">` +
        `<saml:AttributeValue>${x(value)}</saml:AttributeValue></saml:Attribute>`;

  const assertion =
    `<saml:Assertion xmlns:saml="${SAML_NS.assertion}" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">` +
    `<saml:Issuer>${x(p.idpEntityId)}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${x(p.user.id)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData InResponseTo="${x(p.request.id)}" NotOnOrAfter="${notOnOrAfter}" Recipient="${x(recipient)}"/>` +
    `</saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${x(audience)}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${assertionId}">` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    `<saml:AttributeStatement>` +
    attribute('email', p.user.email) +
    attribute('given_name', p.user.givenName) +
    attribute('family_name', p.user.familyName) +
    `</saml:AttributeStatement>` +
    `</saml:Assertion>`;

  const response =
    `<samlp:Response xmlns:samlp="${SAML_NS.protocol}" xmlns:saml="${SAML_NS.assertion}" ID="${responseId}" Version="2.0" ` +
    `IssueInstant="${issueInstant}" Destination="${x(p.request.acsUrl)}" InResponseTo="${x(p.request.id)}">` +
    `<saml:Issuer>${x(p.idpEntityId)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    assertion +
    `</samlp:Response>`;

  if (p.variant === 'unsigned') return `<?xml version="1.0" encoding="UTF-8"?>${response}`;

  const sig = new SignedXml({
    privateKey: p.privateKeyPem,
    publicCert: p.certPem,
    signatureAlgorithm: RSA_SHA256,
    canonicalizationAlgorithm: EXC_C14N,
  });
  sig.addReference({
    xpath: `//*[local-name(.)='Assertion' and namespace-uri(.)='${SAML_NS.assertion}']`,
    transforms: [ENVELOPED, EXC_C14N],
    digestAlgorithm: SHA256,
  });
  sig.computeSignature(response, {
    prefix: 'ds',
    location: {
      reference: `//*[local-name(.)='Assertion' and namespace-uri(.)='${SAML_NS.assertion}']/*[local-name(.)='Issuer']`,
      action: 'after',
    },
  });
  return `<?xml version="1.0" encoding="UTF-8"?>${sig.getSignedXml()}`;
}

function buildMetadata(entityId: string, ssoUrl: string, certPem: string): string {
  const x = escapeXml;
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<md:EntityDescriptor xmlns:md="${SAML_NS.metadata}" xmlns:ds="${SAML_NS.dsig}" entityID="${x(entityId)}">` +
    `<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="${SAML_NS.protocol}">` +
    `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${pemBody(certPem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
    `<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>` +
    `<md:SingleSignOnService Binding="${SAML_NS.redirectBinding}" Location="${x(ssoUrl)}"/>` +
    `</md:IDPSSODescriptor>` +
    `</md:EntityDescriptor>`
  );
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function sendText(res: ServerResponse, status: number, contentType: string, body: string): void {
  res.writeHead(status, { 'content-type': contentType, 'cache-control': 'no-store' });
  res.end(body);
}

const VARIANTS: readonly SamlVariant[] = ['ok', 'wrong-audience', 'wrong-recipient', 'expired', 'unsigned'];

export async function startMockSamlIdp(opts: MockSamlIdpOptions = {}): Promise<MockSamlIdp> {
  const ssoPath = opts.ssoPath ?? '/sso';
  if (!ssoPath.startsWith('/')) throw new Error('mock-saml-idp: ssoPath must start with "/"');

  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  // xml-crypto takes the key as PEM; it stays in this closure and is never written anywhere.
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  createPrivateKey(privateKeyPem); // sanity: the export parses

  let user: SamlUser = { id: 'mock-saml-user-1', email: 'saml.user@example.test', givenName: 'Sam', familyName: 'Ell' };
  let variant: SamlVariant = 'ok';
  const requests: SamlRequestLog[] = [];

  // Filled in after listen() (the default entity ID and the URLs depend on the port).
  let entityId = '';
  let certPem = '';
  let metadataXml = '';

  const handle = (req: IncomingMessage, res: ServerResponse): void => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/metadata') {
      sendText(res, 200, 'application/samlmetadata+xml', metadataXml);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/cert.pem') {
      sendText(res, 200, 'application/x-pem-file', certPem);
      return;
    }
    if (url.pathname !== ssoPath) {
      sendText(res, 404, 'text/plain; charset=utf-8', 'not found');
      return;
    }
    if (req.method !== 'GET') {
      sendText(res, 405, 'text/plain; charset=utf-8', 'HTTP-Redirect binding only (GET)');
      return;
    }
    const samlRequest = url.searchParams.get('SAMLRequest');
    if (!samlRequest) {
      sendText(res, 400, 'text/plain; charset=utf-8', 'missing SAMLRequest');
      return;
    }
    let requestXml: string;
    try {
      requestXml = decodeRedirectSamlRequest(samlRequest);
    } catch {
      sendText(res, 400, 'text/plain; charset=utf-8', 'SAMLRequest is not base64(DEFLATE(xml))');
      return;
    }
    const parsed = parseAuthnRequest(requestXml);
    if ('error' in parsed) {
      sendText(res, 400, 'text/plain; charset=utf-8', parsed.error);
      return;
    }
    const relayState = url.searchParams.get('RelayState');
    requests.push({ ...parsed, relayState, variant });

    const responseXml = buildSamlResponse({ idpEntityId: entityId, request: parsed, user, variant, privateKeyPem, certPem });
    const fields: [string, string][] = [['SAMLResponse', Buffer.from(responseXml, 'utf8').toString('base64')]];
    if (relayState !== null) fields.push(['RelayState', relayState]);
    const inputs = fields.map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join('');
    sendText(
      res,
      200,
      'text/html; charset=utf-8',
      `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Mock SAML IdP</title></head>
<body onload="document.forms[0].submit()">
<h1>Mock SAML IdP</h1>
<p>Signing in as <span id="mock-saml-user">${escapeHtml(user.email)}</span>.</p>
<form id="mock-saml-form" method="post" action="${escapeHtml(parsed.acsUrl)}">${inputs}<button id="mock-saml-continue" type="submit">Continue</button></form>
</body>
</html>`,
    );
  };

  const server = createServer((req, res) => {
    try {
      handle(req, res);
    } catch (err) {
      sendText(res, 500, 'text/plain; charset=utf-8', `mock-saml-idp error: ${(err as Error).message}`);
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port ?? 0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  const url = `http://127.0.0.1:${port}`;
  const ssoUrl = `${url}${ssoPath}`;
  entityId = opts.entityId ?? `${url}/metadata`;
  certPem = selfSignedCertPem(privateKey, publicKey, 'AnvilID e2e mock SAML IdP');
  metadataXml = buildMetadata(entityId, ssoUrl, certPem);

  return {
    url,
    ssoUrl,
    entityId,
    certPem,
    metadataXml,
    requests,
    setUser(next: SamlUser): void {
      user = { ...next };
    },
    setVariant(next: SamlVariant): void {
      if (!VARIANTS.includes(next)) throw new Error(`mock-saml-idp: unknown variant ${String(next)}`);
      variant = next;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
