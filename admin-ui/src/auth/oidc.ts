// OIDC sign-in for the console: the built-in public client `anvil-console` of the `system` tenant
// (authorization code + PKCE S256, handled by oidc-client-ts). Admins are users of the system tenant.
import { type User, UserManager, WebStorageStateStore } from "oidc-client-ts";
import { setAccessTokenProvider } from "@/api/client";

export const CONSOLE_CLIENT_ID = "anvil-console";
export const SYSTEM_ISSUER = `${window.location.origin}/t/system`;

export const userManager = new UserManager({
  authority: SYSTEM_ISSUER,
  client_id: CONSOLE_CLIENT_ID,
  redirect_uri: `${window.location.origin}/console/callback`,
  response_type: "code",
  scope: "openid admin:read admin:write",
  // Tokens live for the browser tab only.
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
  // No iframe-based renewal: the console refreshes with refresh token rotation on a 401.
  automaticSilentRenew: false,
  monitorSession: false,
});

/** State carried through the authorization request: where to return after sign-in. */
export interface SigninState {
  /** A browser path inside the console, e.g. `/console/users?x=1`. */
  returnTo: string;
}

const CONSOLE_HOME = "/console/";

/**
 * Accept only paths inside the console as return targets (never another origin, `//host`, or a
 * path outside /console/); anything else falls back to the console home.
 */
export function safeReturnTo(value: unknown): string {
  if (typeof value !== "string" || value.includes("\\")) return CONSOLE_HOME;
  let url: URL;
  try {
    url = new URL(value, window.location.origin);
  } catch {
    return CONSOLE_HOME;
  }
  if (url.origin !== window.location.origin || !url.pathname.startsWith(CONSOLE_HOME)) return CONSOLE_HOME;
  return url.pathname + url.search + url.hash;
}

/** The current browser location as a return target. */
export function currentReturnTo(): string {
  return window.location.pathname + window.location.search + window.location.hash;
}

// Set by signOut(): the next sign-in asks for credentials again (prompt=login) even though the
// server-side session of the system tenant still exists (RP-initiated logout arrives later).
const SIGNED_OUT_KEY = "anvil-console:signed-out";

export function signIn(returnTo: string): Promise<void> {
  const state: SigninState = { returnTo: safeReturnTo(returnTo) };
  const afterSignOut = window.sessionStorage.getItem(SIGNED_OUT_KEY) !== null;
  window.sessionStorage.removeItem(SIGNED_OUT_KEY);
  return userManager.signinRedirect(afterSignOut ? { state, prompt: "login" } : { state });
}

// React StrictMode runs effects twice in development; the code exchange must happen exactly once.
let callbackPromise: Promise<User> | null = null;

export function completeSignIn(): Promise<User> {
  callbackPromise ??= userManager.signinRedirectCallback();
  return callbackPromise;
}

let refreshing: Promise<string | null> | null = null;

/**
 * Exchange the refresh token for a new token set (the server rotates the refresh token). Concurrent
 * callers share one exchange. On failure the local session is cleared, which signs the user out.
 */
export function refreshTokens(): Promise<string | null> {
  refreshing ??= (async () => {
    try {
      const user = await userManager.getUser();
      if (!user?.refresh_token) {
        await userManager.removeUser();
        return null;
      }
      // With a refresh token present, signinSilent uses the refresh_token grant (no iframe).
      const renewed = await userManager.signinSilent();
      return renewed?.access_token ?? null;
    } catch {
      await userManager.removeUser();
      return null;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

/**
 * Sign out: revoke the refresh token at the system tenant (RFC 7009), then clear local state.
 * RP-initiated logout (ending the server-side session) arrives in a later release.
 */
export async function signOut(): Promise<void> {
  const user = await userManager.getUser();
  if (user?.refresh_token) {
    try {
      const response = await fetch(`${SYSTEM_ISSUER}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token: user.refresh_token,
          token_type_hint: "refresh_token",
          client_id: CONSOLE_CLIENT_ID,
        }),
      });
      // The revocation endpoint ships in 0.2 (plan 03-18). Until then the server answers 404 and
      // there is nothing to revoke against; that case is ignored deliberately and the local session
      // is still cleared below. Any other failure is reported but does not keep the user signed in.
      if (!response.ok && response.status !== 404) {
        console.warn(`token revocation failed with status ${response.status}`);
      }
    } catch (error) {
      console.warn("token revocation failed", error);
    }
  }
  window.sessionStorage.setItem(SIGNED_OUT_KEY, "1");
  await userManager.removeUser();
}

setAccessTokenProvider({
  async accessToken() {
    const user = await userManager.getUser();
    if (!user || user.expired) return null;
    return user.access_token;
  },
  refresh: refreshTokens,
});
