// Adds parameters (prompt, acr_values, ...) to the authorization requests a page sends, so
// clients that build their own request (the sample RP, lib/account.ts signInForIdToken) can be
// driven with them. Works with JavaScript disabled (network interception).
//
// Playwright routes only the first request of a redirect chain, so two cases are handled:
// - a navigation straight to `{issuer}/authorize` (signInForIdToken) is answered with a 302 to the
//   same URL plus the parameters;
// - a GET navigation to another origin (the RP's /login) is fetched without following redirects,
//   and a redirect to `{issuer}/authorize` gets the parameters added to its Location.

import type { Page, Route } from '@playwright/test';
import { anvilUrl } from './anvil';

/**
 * Until the returned function is called, every authorization request from `page` to
 * `{issuer}/authorize` gets `params` (existing values are replaced). `/authorize/continue` is not
 * touched.
 */
export async function addAuthorizeParams(
  page: Page,
  params: Record<string, string>,
  issuer: string = anvilUrl(),
): Promise<() => Promise<void>> {
  const endpoint = new URL(`${issuer.replace(/\/+$/, '')}/authorize`);
  const isAuthorize = (url: URL) => url.origin === endpoint.origin && url.pathname === endpoint.pathname;
  /** `url` with `params` added, or undefined when it already carries them all. */
  const withParams = (url: URL): URL | undefined => {
    if (Object.entries(params).every(([k, v]) => url.searchParams.get(k) === v)) return undefined;
    const out = new URL(url.href);
    for (const [k, v] of Object.entries(params)) out.searchParams.set(k, v);
    return out;
  };
  const matches = (url: URL) => isAuthorize(url) || url.origin !== endpoint.origin;

  const handler = async (route: Route) => {
    const request = route.request();
    if (request.method() !== 'GET' || !request.isNavigationRequest()) {
      await route.continue();
      return;
    }
    const url = new URL(request.url());
    if (isAuthorize(url)) {
      const target = withParams(url);
      if (!target) await route.continue();
      else await route.fulfill({ status: 302, headers: { location: target.href, 'cache-control': 'no-store' } });
      return;
    }
    const response = await route.fetch({ maxRedirects: 0 });
    const location = response.headers()['location'];
    const next = location ? new URL(location, url) : undefined;
    const target = next && isAuthorize(next) ? withParams(next) : undefined;
    if (!target) {
      await route.fulfill({ response });
      return;
    }
    await route.fulfill({ response, headers: { ...response.headers(), location: target.href } });
  };
  await page.route(matches, handler);
  return () => page.unroute(matches, handler);
}
