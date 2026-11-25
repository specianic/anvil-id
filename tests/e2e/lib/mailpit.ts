// Helpers for reading mail captured by Mailpit through its HTTP API.
// The Mailpit base URL comes from the environment (MAILPIT_URL).

import { requireEnv } from './anvil';

export interface MailpitAddress {
  Name: string;
  Address: string;
}

export interface MailpitMessage {
  ID: string;
  From: MailpitAddress;
  To: MailpitAddress[];
  Subject: string;
  Text: string;
  HTML: string;
  Date: string;
}

interface SearchResponse {
  messages: Array<{ ID: string; Created: string }>;
}

export function mailpitUrl(): string {
  return requireEnv('MAILPIT_URL');
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Polls Mailpit until a message addressed to `address` exists and returns the
 * newest one. Throws after `timeoutMs`.
 */
export async function latestMessageTo(
  address: string,
  { timeoutMs = 15_000, intervalMs = 250 }: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<MailpitMessage> {
  const base = mailpitUrl();
  const query = encodeURIComponent(`to:"${address}"`);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const res = await fetch(`${base}/api/v1/search?query=${query}`, {
      headers: { accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Mailpit search failed: HTTP ${res.status}`);
    }
    const found = (await res.json()) as SearchResponse;
    if (found.messages?.length) {
      // Mailpit returns newest first; sort defensively by creation time.
      const newest = [...found.messages].sort(
        (a, b) => Date.parse(b.Created) - Date.parse(a.Created),
      )[0];
      const msgRes = await fetch(`${base}/api/v1/message/${encodeURIComponent(newest.ID)}`, {
        headers: { accept: 'application/json' },
      });
      if (!msgRes.ok) {
        throw new Error(`Mailpit message fetch failed: HTTP ${msgRes.status}`);
      }
      return (await msgRes.json()) as MailpitMessage;
    }
    if (Date.now() >= deadline) {
      throw new Error(`no mail to ${address} within ${timeoutMs} ms`);
    }
    await sleep(intervalMs);
  }
}

/**
 * Returns the first absolute http(s) link in `text` whose path starts with
 * `pathPrefix` (for example `/t/default/verify`).
 */
export function extractLink(text: string, pathPrefix: string): string {
  for (const match of text.matchAll(/https?:\/\/[^\s"'<>]+/g)) {
    const candidate = match[0].replace(/[).,;]+$/, '').replaceAll('&amp;', '&');
    try {
      const url = new URL(candidate);
      if (url.pathname.startsWith(pathPrefix)) {
        return url.href;
      }
    } catch {
      // not a URL; keep looking
    }
  }
  throw new Error(`no link with path prefix ${pathPrefix} found in message`);
}
