// Test tooling for the real-IdP SAML interop spec (specs/saml-interop.spec.ts, 07-28). The IdPs run
// in containers started by tests/saml-interop/run.sh, which exports everything read here:
//   SAML_INTEROP_IDPS                       space-separated IdP ids (keycloak simplesamlphp shibboleth)
//   SAML_INTEROP_<IDP>_METADATA_URL         https metadata URL (AnvilID imports it by URL)
//   SAML_INTEROP_<IDP>_BASE_URL             https base URL of the IdP
//   SAML_INTEROP_<IDP>_IMAGE                the pinned image reference (from compose.yml)
//   SAML_INTEROP_<IDP>_USER_PASSWORD        the per-run password of the IdP's test accounts
//   SAML_INTEROP_KC_ADMIN_PASSWORD          the per-run Keycloak bootstrap admin password
//   SAML_INTEROP_RESULTS                    where recordResult writes the results file
// Missing variables fail the spec (requireEnv); nothing is skipped.
//
// SAML messages are decoded with plain string/regex parsing, as lib/mock-saml-idp.ts does: this is
// test tooling reading what a real IdP produced, never a verifier. The results file holds IdP ids,
// images, scenario names, checklist rows, pass/fail and algorithm/format URIs only: never SAML
// messages, certificates, passwords or user ids.

import { execSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { expect, type Page, type Request } from '@playwright/test';
import { requireEnv } from './anvil';

export type IdpId = 'keycloak' | 'simplesamlphp' | 'shibboleth';

const IDP_IDS: readonly IdpId[] = ['keycloak', 'simplesamlphp', 'shibboleth'];

export interface IdpUser {
  /** Login name at the IdP. */
  username: string;
  /** The address the IdP asserts. */
  email: string;
  givenName: string;
  familyName: string;
}

/** A connection whose IdP-side configuration AnvilID must refuse, with the expected audit reason. */
export interface Refusal {
  slug: string;
  reason: string;
  rows: number[];
  /** What the IdP is configured to do, for the results file. */
  setup: string;
}

export interface InteropIdp {
  id: IdpId;
  label: string;
  image: string;
  metadataUrl: string;
  baseUrl: string;
  password: string;
  /** Org slug in tenant `interop`. */
  org: string;
  /** The main connection (assertion signed, persistent NameID). */
  okSlug: string;
  /** The verified domain the IdP's users' addresses are on. */
  okDomain: string;
  /** Other accepted signing setups, signed in as bob. */
  accepted: Array<{ slug: string; setup: string }>;
  refusals: Refusal[];
  /** AnvilID attribute mapping (names as this IdP sends them). */
  attributes: { email: string; given_name: string; family_name: string };
  alice: IdpUser;
  bob: IdpUser;
  /** Every connection slug of this IdP. */
  slugs(): string[];
  /** The IdP's own unsolicited (IdP-initiated) SSO URL for SP `spEntityId` with connection `slug`. */
  idpInitiatedUrl(slug: string, spEntityId: string): string;
  /** On the IdP's login page: signs in. */
  login(page: Page, user: IdpUser): Promise<void>;
  /** Expects the IdP's login form (credentials asked for). */
  expectLoginForm(page: Page): Promise<void>;
}

/** The interop tenant's slug: the IdP templates register its SP values. */
export const INTEROP_TENANT = 'interop';

/** The routed test domain of connection `slug` (RFC 2606 name, only the mock DNS answers it). */
export function domainOf(slug: string): string {
  return `${slug}.interop.example.com`;
}

function user(username: string, domain: string, givenName: string, familyName: string): IdpUser {
  return { username, email: `${username}@${domain}`, givenName, familyName };
}

async function fillAndSubmit(
  page: Page,
  form: { username: string; password: string; submit: string },
  u: IdpUser,
  password: string,
): Promise<void> {
  await expect(page.locator(form.password)).toBeVisible({ timeout: 30_000 });
  // Re-authentication (ForceAuthn with an IdP session) may show the user name read-only
  // (Keycloak: "Please re-authenticate to continue"); only the password is asked for then.
  const username = page.locator(form.username);
  if ((await username.count()) > 0 && (await username.isEditable())) await username.fill(u.username);
  await page.locator(form.password).fill(password);
  await page.locator(form.submit).click();
}

function env(idp: IdpId, name: string): string {
  return requireEnv(`SAML_INTEROP_${idp.toUpperCase()}_${name}`);
}

function keycloak(): InteropIdp {
  const baseUrl = env('keycloak', 'BASE_URL');
  const password = env('keycloak', 'USER_PASSWORD');
  const okDomain = domainOf('kc-ok');
  const form = { username: '#username', password: '#password', submit: '#kc-login' };
  const idp: InteropIdp = {
    id: 'keycloak',
    label: 'Keycloak',
    image: env('keycloak', 'IMAGE'),
    metadataUrl: env('keycloak', 'METADATA_URL'),
    baseUrl,
    password,
    org: 'kc',
    okSlug: 'kc-ok',
    okDomain,
    accepted: [{ slug: 'kc-both', setup: 'Response and assertion signed (RSA-SHA256)' }],
    refusals: [
      { slug: 'kc-resp-only', reason: 'signature_profile', rows: [14], setup: 'Response signed, assertion unsigned' },
      { slug: 'kc-unsigned', reason: 'signature_profile', rows: [3], setup: 'Nothing signed' },
      { slug: 'kc-sha1', reason: 'algorithm', rows: [3], setup: 'Assertion signed with RSA-SHA1' },
      { slug: 'kc-enc', reason: 'encrypted', rows: [13], setup: 'Assertion signed and encrypted' },
    ],
    attributes: { email: 'email', given_name: 'given_name', family_name: 'family_name' },
    alice: user('alice', okDomain, 'Alice', 'Kc'),
    bob: user('bob', okDomain, 'Bob', 'Kc'),
    slugs: () => [idp.okSlug, ...idp.accepted.map((a) => a.slug), ...idp.refusals.map((r) => r.slug)],
    // saml_idp_initiated_sso_url_name of client kc-ok (interop-realm.json.tmpl).
    idpInitiatedUrl: (slug) => `${baseUrl}/realms/interop/protocol/saml/clients/${slug}`,
    login: (page, u) => fillAndSubmit(page, form, u, password),
    expectLoginForm: async (page) => {
      await expect(page.locator(form.password)).toBeVisible({ timeout: 30_000 });
    },
  };
  return idp;
}

function simplesamlphp(): InteropIdp {
  const baseUrl = env('simplesamlphp', 'BASE_URL');
  const password = env('simplesamlphp', 'USER_PASSWORD');
  const okDomain = domainOf('ssp-ok');
  // modules/core/templates/loginuserpass.twig (SimpleSAMLphp 2.5).
  const form = { username: '#username', password: '#password', submit: '#submit_button' };
  const idp: InteropIdp = {
    id: 'simplesamlphp',
    label: 'SimpleSAMLphp',
    image: env('simplesamlphp', 'IMAGE'),
    metadataUrl: env('simplesamlphp', 'METADATA_URL'),
    baseUrl,
    password,
    org: 'ssp',
    okSlug: 'ssp-ok',
    okDomain,
    accepted: [{ slug: 'ssp-assert-only', setup: 'Assertion signed, Response unsigned' }],
    refusals: [
      { slug: 'ssp-resp-only', reason: 'signature_profile', rows: [14], setup: 'Response signed, assertion unsigned' },
      { slug: 'ssp-enc', reason: 'encrypted', rows: [13], setup: 'Assertion signed and encrypted' },
    ],
    attributes: { email: 'mail', given_name: 'givenName', family_name: 'sn' },
    alice: user('alice', okDomain, 'Alice', 'Ssp'),
    bob: user('bob', okDomain, 'Bob', 'Ssp'),
    slugs: () => [idp.okSlug, ...idp.accepted.map((a) => a.slug), ...idp.refusals.map((r) => r.slug)],
    // SimpleSAMLphp 2.x: an unsolicited response from the SSO endpoint with `spentityid`.
    idpInitiatedUrl: (_slug, sp) =>
      `${baseUrl}/module.php/saml/idp/singleSignOnService?spentityid=${encodeURIComponent(sp)}`,
    login: (page, u) => fillAndSubmit(page, form, u, password),
    expectLoginForm: async (page) => {
      await expect(page.locator(form.password)).toBeVisible({ timeout: 30_000 });
    },
  };
  return idp;
}

function shibboleth(): InteropIdp {
  const baseUrl = env('shibboleth', 'BASE_URL');
  const password = env('shibboleth', 'USER_PASSWORD');
  const okDomain = domainOf('shib-ok');
  // views/login.vm (Shibboleth IdP 5).
  const form = { username: '#username', password: '#password', submit: 'button[name="_eventId_proceed"]' };
  const idp: InteropIdp = {
    id: 'shibboleth',
    label: 'Shibboleth IdP',
    image: env('shibboleth', 'IMAGE'),
    metadataUrl: env('shibboleth', 'METADATA_URL'),
    baseUrl,
    password,
    org: 'shib',
    okSlug: 'shib-ok',
    okDomain,
    accepted: [],
    refusals: [
      {
        slug: 'shib-default',
        reason: 'signature_profile',
        rows: [14],
        setup: 'Default SAML2.SSO signing: Response signed, assertion unsigned',
      },
    ],
    // Released with the default attribute registry: urn:oid:… Name, FriendlyName mail/givenName/sn.
    attributes: { email: 'mail', given_name: 'givenName', family_name: 'sn' },
    // attribute-resolver.xml.tmpl: givenName "Interop", sn = uid.
    alice: user('alice', okDomain, 'Interop', 'alice'),
    bob: user('bob', okDomain, 'Interop', 'bob'),
    slugs: () => [idp.okSlug, ...idp.accepted.map((a) => a.slug), ...idp.refusals.map((r) => r.slug)],
    idpInitiatedUrl: (_slug, sp) => `${baseUrl}/profile/SAML2/Unsolicited/SSO?providerId=${encodeURIComponent(sp)}`,
    login: (page, u) => fillAndSubmit(page, form, u, password),
    expectLoginForm: async (page) => {
      await expect(page.locator(form.password)).toBeVisible({ timeout: 30_000 });
    },
  };
  return idp;
}

/** The IdPs of this run (SAML_INTEROP_IDPS); unknown or missing entries fail. */
export function interopIdps(): InteropIdp[] {
  const ids = requireEnv('SAML_INTEROP_IDPS').split(/[\s,]+/).filter(Boolean);
  if (ids.length === 0) throw new Error('SAML_INTEROP_IDPS is empty');
  return ids.map((id) => {
    switch (id) {
      case 'keycloak':
        return keycloak();
      case 'simplesamlphp':
        return simplesamlphp();
      case 'shibboleth':
        return shibboleth();
      default:
        throw new Error(`unknown IdP in SAML_INTEROP_IDPS: ${id} (expected ${IDP_IDS.join(', ')})`);
    }
  });
}

// ---------------------------------------------------------------------------------------------
// SAML message capture

/** What the AuthnRequest AnvilID sent says. */
export interface AuthnRequestFacts {
  ssoUrl: string;
  issuer: string | null;
  acsUrl: string | null;
  nameIdPolicyFormat: string | null;
  forceAuthn: boolean;
  id: string | null;
}

/** What the IdP's response says (from the decoded XML, before AnvilID judged it). */
export interface ResponseFacts {
  acsUrl: string;
  /** Base64 SAMLResponse and RelayState exactly as posted (kept in memory for the replay case). */
  samlResponse: string;
  relayState: string | null;
  responseSigned: boolean;
  assertionSigned: boolean;
  encryptedAssertion: boolean;
  signatureMethods: string[];
  digestMethods: string[];
  nameIdFormat: string | null;
}

function attr(tag: string, name: string): string | null {
  const m = new RegExp(`\\s${name}="([^"]*)"`).exec(tag);
  return m ? m[1] : null;
}

function firstTag(xml: string, local: string): string | null {
  const m = new RegExp(`<(?:[\\w-]+:)?${local}\\b[^>]*>`).exec(xml);
  return m ? m[0] : null;
}

function textOf(xml: string, local: string): string | null {
  const m = new RegExp(`<(?:[\\w-]+:)?${local}\\b[^>]*>([^<]*)</(?:[\\w-]+:)?${local}>`).exec(xml);
  return m ? m[1].trim() : null;
}

/** Decodes a Redirect-binding SAMLRequest (base64 of raw DEFLATE). */
export function decodeAuthnRequest(url: string): AuthnRequestFacts {
  const u = new URL(url);
  const encoded = u.searchParams.get('SAMLRequest');
  if (!encoded) throw new Error('no SAMLRequest in the redirect');
  const xml = inflateRawSync(Buffer.from(encoded, 'base64')).toString('utf8');
  const root = firstTag(xml, 'AuthnRequest');
  if (!root) throw new Error('the SAMLRequest is not an AuthnRequest');
  const policy = firstTag(xml, 'NameIDPolicy');
  return {
    ssoUrl: `${u.origin}${u.pathname}`,
    issuer: textOf(xml, 'Issuer'),
    acsUrl: attr(root, 'AssertionConsumerServiceURL'),
    nameIdPolicyFormat: policy ? attr(policy, 'Format') : null,
    forceAuthn: attr(root, 'ForceAuthn') === 'true',
    id: attr(root, 'ID'),
  };
}

/** Decodes a POSTed SAMLResponse (form body). */
export function decodeResponse(acsUrl: string, body: string): ResponseFacts {
  const form = new URLSearchParams(body);
  const samlResponse = form.get('SAMLResponse');
  if (!samlResponse) throw new Error('no SAMLResponse in the ACS POST');
  const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
  // Split at the assertion: signatures inside it sign the assertion, the others the Response.
  const start = /<(?:[\w-]+:)?Assertion\b/.exec(xml);
  const endRe = /<\/(?:[\w-]+:)?Assertion>/g;
  let end = -1;
  for (let m = endRe.exec(xml); m; m = endRe.exec(xml)) end = m.index + m[0].length;
  const assertion = start && end > start.index ? xml.slice(start.index, end) : '';
  const outside = start && end > start.index ? xml.slice(0, start.index) + xml.slice(end) : xml;
  const sigRe = /<(?:[\w-]+:)?Signature[\s>]/;
  const all = (local: string) =>
    [...xml.matchAll(new RegExp(`<(?:[\\w-]+:)?${local}\\b[^>]*>`, 'g'))]
      .map((m) => attr(m[0], 'Algorithm'))
      .filter((a): a is string => a !== null);
  const nameId = firstTag(assertion, 'NameID');
  return {
    acsUrl,
    samlResponse,
    relayState: form.get('RelayState'),
    responseSigned: sigRe.test(outside),
    assertionSigned: sigRe.test(assertion),
    encryptedAssertion: /<(?:[\w-]+:)?EncryptedAssertion\b/.test(xml),
    signatureMethods: [...new Set(all('SignatureMethod'))],
    digestMethods: [...new Set(all('DigestMethod'))],
    nameIdFormat: nameId ? attr(nameId, 'Format') : null,
  };
}

export interface SamlCapture {
  requests: AuthnRequestFacts[];
  responses: ResponseFacts[];
  stop(): void;
}

/**
 * Records, in `page`, every AuthnRequest sent to `ssoPrefix` (the IdP's origin) and every response
 * POSTed to an AnvilID ACS (`/ui/login/saml/{slug}/acs`).
 */
export function captureSaml(page: Page, ssoPrefix: string): SamlCapture {
  const capture: SamlCapture = { requests: [], responses: [], stop: () => page.off('request', onRequest) };
  function onRequest(r: Request): void {
    const url = r.url();
    if (url.startsWith(ssoPrefix) && url.includes('SAMLRequest=')) {
      capture.requests.push(decodeAuthnRequest(url));
    } else if (r.method() === 'POST' && /\/ui\/login\/saml\/[^/]+\/acs$/.test(new URL(url).pathname)) {
      const body = r.postData();
      if (body && body.includes('SAMLResponse=')) capture.responses.push(decodeResponse(url, body));
    }
  }
  page.on('request', onRequest);
  return capture;
}

/** SHA-256 or stronger signature/digest URIs (what AnvilID's profile accepts). */
export const STRONG_SIGNATURE_METHODS = [
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
];
export const STRONG_DIGEST_METHODS = [
  'http://www.w3.org/2001/04/xmlenc#sha256',
  'http://www.w3.org/2001/04/xmldsig-more#sha384',
  'http://www.w3.org/2001/04/xmlenc#sha512',
];

/** Re-POSTs a captured response to its ACS from `page` (an auto-submitting form, like an IdP). */
export async function replayResponse(page: Page, r: ResponseFacts): Promise<void> {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  const relay = r.relayState === null ? '' : `<input type="hidden" name="RelayState" value="${esc(r.relayState)}">`;
  await page.setContent(
    `<!doctype html><html lang="en"><title>replay</title><body>` +
      `<form id="replay" method="post" action="${esc(r.acsUrl)}">` +
      `<input type="hidden" name="SAMLResponse" value="${esc(r.samlResponse)}">${relay}</form></body></html>`,
  );
  await Promise.all([page.waitForURL((u) => u.href === r.acsUrl), page.locator('#replay').evaluate((f) => (f as HTMLFormElement).submit())]);
}

// ---------------------------------------------------------------------------------------------
// Keycloak admin (bootstrap admin of the per-run container; the run CA is trusted through
// NODE_EXTRA_CA_CERTS)

export interface KeycloakKey {
  kid: string;
  providerId: string;
  providerPriority: number;
  status: string;
  algorithm: string;
  use: string;
  certificate?: string;
}

export class KeycloakAdmin {
  private constructor(
    private readonly baseUrl: string,
    private readonly token: string,
  ) {}

  static async connect(baseUrl: string): Promise<KeycloakAdmin> {
    const res = await fetch(`${baseUrl}/realms/master/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: 'admin-cli',
        username: 'admin',
        password: requireEnv('SAML_INTEROP_KC_ADMIN_PASSWORD'),
      }).toString(),
    });
    if (res.status !== 200) throw new Error(`Keycloak admin token: HTTP ${res.status}`);
    const body = (await res.json()) as { access_token: string };
    return new KeycloakAdmin(baseUrl, body.access_token);
  }

  private async call<T>(method: string, path: string, body?: unknown, expected = [200]): Promise<T> {
    const res = await fetch(`${this.baseUrl}/admin/realms/interop${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.token}`,
        accept: 'application/json',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!expected.includes(res.status)) {
      throw new Error(`Keycloak ${method} ${path}: HTTP ${res.status} ${await res.text()}`);
    }
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /** The realm's keys (active, passive and disabled). */
  async keys(): Promise<KeycloakKey[]> {
    const body = await this.call<{ keys: KeycloakKey[] }>('GET', '/keys');
    return body.keys;
  }

  /** The RS256 signing key Keycloak signs with now (highest-priority active one). */
  async activeRsaKey(): Promise<KeycloakKey> {
    const keys = (await this.keys()).filter((k) => k.algorithm === 'RS256' && k.use === 'SIG' && k.status === 'ACTIVE');
    keys.sort((a, b) => b.providerPriority - a.providerPriority);
    if (!keys[0]) throw new Error('Keycloak realm has no active RS256 key');
    return keys[0];
  }

  /** Adds a generated RSA signing key provider with `priority`; returns its component id. */
  async addRsaKey(name: string, priority: number): Promise<string> {
    const realm = await this.call<{ id: string }>('GET', '');
    const res = await fetch(`${this.baseUrl}/admin/realms/interop/components`, {
      method: 'POST',
      headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        name,
        providerId: 'rsa-generated',
        providerType: 'org.keycloak.keys.KeyProvider',
        parentId: realm.id,
        config: {
          priority: [String(priority)],
          enabled: ['true'],
          active: ['true'],
          keySize: ['2048'],
          algorithm: ['RS256'],
        },
      }),
    });
    if (res.status !== 201) throw new Error(`Keycloak add key: HTTP ${res.status} ${await res.text()}`);
    const location = res.headers.get('location') ?? '';
    const id = location.split('/').pop();
    if (!id) throw new Error('Keycloak add key: no component id');
    return id;
  }

  /**
   * Changes settings (`priority`, `active`, ...) of the key provider component `id` (the
   * `providerId` of its keys). Inactive keys no longer sign; the highest-priority active key signs.
   */
  async setKeyConfig(id: string, changes: Record<string, string>): Promise<void> {
    const c = await this.call<{ config: Record<string, string[]> } & Record<string, unknown>>('GET', `/components/${id}`);
    for (const [k, v] of Object.entries(changes)) c.config[k] = [v];
    await this.call('PUT', `/components/${id}`, c, [204]);
  }
}

/** A base64 DER certificate as one PEM block. */
export function pemOf(base64Der: string): string {
  const lines = base64Der.replace(/\s+/g, '').match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

// ---------------------------------------------------------------------------------------------
// Results file

export interface ScenarioResult {
  scenario: string;
  connection: string;
  rows: number[];
  result: 'pass' | 'fail';
  observed?: Record<string, unknown>;
}

interface ResultsFile {
  generated_at: string;
  commit: string | null;
  idps: Record<string, { image: string; scenarios: ScenarioResult[] }>;
}

function commit(): string | null {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    return execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch {
    return null;
  }
}

/** Appends one scenario outcome to SAML_INTEROP_RESULTS (no messages, keys, passwords or ids). */
export function recordResult(idp: InteropIdp, r: ScenarioResult): void {
  const path = requireEnv('SAML_INTEROP_RESULTS');
  const file: ResultsFile = existsSync(path)
    ? (JSON.parse(readFileSync(path, 'utf8')) as ResultsFile)
    : { generated_at: new Date().toISOString(), commit: commit(), idps: {} };
  file.generated_at = new Date().toISOString();
  const entry = (file.idps[idp.id] ??= { image: idp.image, scenarios: [] });
  entry.scenarios.push(r);
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`);
}

/** Response facts safe for the results file (URIs and booleans only). */
export function observedFacts(r: ResponseFacts | undefined): Record<string, unknown> | undefined {
  if (!r) return undefined;
  return {
    response_signed: r.responseSigned,
    assertion_signed: r.assertionSigned,
    encrypted_assertion: r.encryptedAssertion,
    signature_methods: r.signatureMethods,
    digest_methods: r.digestMethods,
    name_id_format: r.nameIdFormat,
  };
}
