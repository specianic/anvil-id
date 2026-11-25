// Helpers for logout e2e tests: RP-initiated logout URLs and the sample RP's back-channel record.

/** One back-channel logout token the sample RP accepted (examples/node-rp /backchannel_logout). */
export interface BackchannelEntry {
  sub?: string;
  sid?: string;
  jti: string;
  received_at: string;
}

export interface EndSessionParams {
  idTokenHint?: string;
  postLogoutRedirectUri?: string;
  state?: string;
  clientId?: string;
  uiLocales?: string;
}

/** `{issuer}/logout?...`: AnvilID's end_session_endpoint with the given parameters. */
export function endSessionUrl(issuer: string, params: EndSessionParams = {}): string {
  const url = new URL(`${issuer.replace(/\/+$/, '')}/logout`);
  if (params.idTokenHint) url.searchParams.set('id_token_hint', params.idTokenHint);
  if (params.postLogoutRedirectUri) url.searchParams.set('post_logout_redirect_uri', params.postLogoutRedirectUri);
  if (params.state) url.searchParams.set('state', params.state);
  if (params.clientId) url.searchParams.set('client_id', params.clientId);
  if (params.uiLocales) url.searchParams.set('ui_locales', params.uiLocales);
  return url.href;
}

/** Reads the back-channel logout tokens the sample RP recorded for `sub` (all when omitted). */
export async function backchannelReceived(rpUrl: string, sub?: string): Promise<BackchannelEntry[]> {
  const url = new URL(`${rpUrl.replace(/\/+$/, '')}/backchannel_logout/received`);
  if (sub) url.searchParams.set('sub', sub);
  const res = await fetch(url);
  if (res.status !== 200) throw new Error(`GET ${url.pathname} failed: HTTP ${res.status}`);
  return (await res.json()) as BackchannelEntry[];
}

/**
 * Polls the sample RP until it has recorded a back-channel logout for `sub`, and returns the
 * entries. Delivery is asynchronous (outbox worker), hence the polling. Throws after `timeoutMs`.
 */
export async function waitForBackchannel(
  rpUrl: string,
  sub: string,
  timeoutMs = 15_000,
): Promise<BackchannelEntry[]> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const entries = await backchannelReceived(rpUrl, sub);
    if (entries.length > 0) return entries;
    if (Date.now() > deadline) {
      throw new Error(`no back-channel logout for sub ${sub} within ${timeoutMs} ms`);
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}
