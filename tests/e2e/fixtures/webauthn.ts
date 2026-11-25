// Virtual WebAuthn authenticator for Playwright (Chromium only), driven through the Chrome DevTools
// Protocol WebAuthn domain. Tests that need passkeys import `test` from here instead of
// '@playwright/test' and request the `authenticator` fixture.
//
// The authenticator is a CTAP 2.1 platform ("internal") authenticator with resident keys and user
// verification, so it can create discoverable credentials and satisfy userVerification=required.
// Presence is simulated automatically, so no browser UI ever appears. It is removed on teardown.

import { test as base, type CDPSession, type Page } from '@playwright/test';

export interface VirtualCredential {
  credentialId: string; // base64
  isResidentCredential: boolean;
  rpId?: string;
  privateKey: string; // base64 PKCS#8
  userHandle?: string; // base64
  signCount: number;
  largeBlob?: string;
  backupEligibility?: boolean;
  backupState?: boolean;
}

export interface AuthenticatorOptions {
  /** Defaults to true: the authenticator reports successful user verification. */
  isUserVerified?: boolean;
}

export interface ResponseOverride {
  /** The next assertions carry an invalid signature. */
  isBogusSignature?: boolean;
  /** The next responses claim UV although it was not performed (UV bit flipped). */
  isBadUV?: boolean;
  /** The next responses lack the user-present flag. */
  isBadUP?: boolean;
}

export class VirtualAuthenticator {
  constructor(
    readonly cdp: CDPSession,
    readonly authenticatorId: string,
  ) {}

  /** Every credential the authenticator holds. */
  async getCredentials(): Promise<VirtualCredential[]> {
    const { credentials } = await this.cdp.send('WebAuthn.getCredentials', {
      authenticatorId: this.authenticatorId,
    });
    return credentials as VirtualCredential[];
  }

  /**
   * Rewrites the stored signature counter of one credential, e.g. to simulate a cloned
   * authenticator (counter going backwards). Chromium has no "set counter" command, so the
   * credential is removed and re-added with the new counter.
   */
  async setSignCount(credentialId: string, signCount: number): Promise<void> {
    const existing = (await this.getCredentials()).find((c) => c.credentialId === credentialId);
    if (!existing) {
      throw new Error(`virtual authenticator has no credential ${credentialId}`);
    }
    await this.cdp.send('WebAuthn.removeCredential', {
      authenticatorId: this.authenticatorId,
      credentialId,
    });
    await this.cdp.send('WebAuthn.addCredential', {
      authenticatorId: this.authenticatorId,
      credential: {
        credentialId: existing.credentialId,
        isResidentCredential: existing.isResidentCredential,
        rpId: existing.rpId,
        privateKey: existing.privateKey,
        userHandle: existing.userHandle,
        signCount,
      },
    });
  }

  /** Makes the authenticator produce tampered responses (negative tests). */
  async overrideResponse(override: ResponseOverride): Promise<void> {
    await this.cdp.send('WebAuthn.setResponseOverrideBits', {
      authenticatorId: this.authenticatorId,
      isBogusSignature: override.isBogusSignature ?? false,
      isBadUV: override.isBadUV ?? false,
      isBadUP: override.isBadUP ?? false,
    });
  }

  /** Toggles whether later ceremonies report successful user verification. */
  async setUserVerified(isUserVerified: boolean): Promise<void> {
    await this.cdp.send('WebAuthn.setUserVerified', {
      authenticatorId: this.authenticatorId,
      isUserVerified,
    });
  }
}

/** Attaches a virtual authenticator to `page`. Prefer the `authenticator` fixture. */
export async function addVirtualAuthenticator(
  page: Page,
  options: AuthenticatorOptions = {},
): Promise<VirtualAuthenticator> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: options.isUserVerified ?? true,
      automaticPresenceSimulation: true,
    },
  });
  return new VirtualAuthenticator(cdp, authenticatorId);
}

export async function removeVirtualAuthenticator(auth: VirtualAuthenticator): Promise<void> {
  try {
    await auth.cdp.send('WebAuthn.removeVirtualAuthenticator', {
      authenticatorId: auth.authenticatorId,
    });
    await auth.cdp.send('WebAuthn.disable');
  } catch {
    // The page (and its CDP session) may already be closed at teardown.
  }
  await auth.cdp.detach().catch(() => undefined);
}

export const test = base.extend<{ authenticator: VirtualAuthenticator }>({
  authenticator: async ({ page }, use) => {
    const auth = await addVirtualAuthenticator(page);
    await use(auth);
    await removeVirtualAuthenticator(auth);
  },
});

export { expect } from '@playwright/test';
