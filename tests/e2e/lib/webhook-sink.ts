// A local webhook receiver for the e2e suite: an HTTP server on 127.0.0.1 that checks every
// delivery's Standard Webhooks v1 signature with node:crypto and records it.
//
// The e2e instance runs in development mode (loopback public URL), where the outbound policy
// allows plain http to loopback destinations, so endpoints can point at this sink. Nothing here
// holds a fixed credential: the endpoint secret is the one the admin API returned at creation.
//
// Signature scheme (docs/WEBHOOKS.md): `webhook-signature` holds one or more space-separated
// `v1,<base64>` entries; each is HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{body}`
// keyed with the base64-decoded part of the `whsec_` secret.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/** Largest timestamp distance (seconds) a delivery may have from the local clock. */
const TOLERANCE_SECONDS = 5 * 60;

/** One request received by the sink. */
export interface WebhookDelivery {
  /** `webhook-id` (stable across retries of one delivery). */
  id: string;
  /** `webhook-timestamp` (unix seconds). */
  timestamp: number;
  /** The raw body exactly as received. */
  body: string;
  /** The parsed body, or undefined when it is not JSON. */
  payload?: { type?: string; timestamp?: string; data?: Record<string, unknown>; [k: string]: unknown };
  /** True when at least one `v1` signature matched under the current secret and the timestamp was fresh. */
  verified: boolean;
  /** Every request header (lower-case names). */
  headers: Record<string, string | string[] | undefined>;
}

/** Decodes a `whsec_` secret into the HMAC key bytes. */
export function webhookKey(secret: string): Buffer {
  if (!secret.startsWith('whsec_')) throw new Error('webhook secret must start with whsec_');
  return Buffer.from(secret.slice('whsec_'.length), 'base64');
}

/** The `v1,<base64>` signature for one delivery. */
export function signWebhook(secret: string, id: string, timestamp: number, body: string): string {
  const mac = createHmac('sha256', webhookKey(secret)).update(`${id}.${timestamp}.${body}`).digest('base64');
  return `v1,${mac}`;
}

/**
 * Verifies a delivery: true when the timestamp is within the tolerance and any `v1` entry of the
 * signature header matches (constant-time comparison).
 */
export function verifyWebhook(
  secret: string,
  id: string,
  timestamp: string,
  body: string,
  signatureHeader: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
  if (!/^\d+$/.test(timestamp)) return false;
  const ts = Number.parseInt(timestamp, 10);
  if (Math.abs(nowSeconds - ts) > TOLERANCE_SECONDS) return false;
  const expected = Buffer.from(signWebhook(secret, id, ts, body));
  return signatureHeader
    .split(' ')
    .filter((entry) => entry.startsWith('v1,'))
    .some((entry) => {
      const given = Buffer.from(entry);
      return given.length === expected.length && timingSafeEqual(given, expected);
    });
}

export interface WebhookSink {
  /** The URL to register as the endpoint, e.g. http://127.0.0.1:43123/hook. */
  url: string;
  /** Sets the secret the admin API returned; deliveries are verified against it. */
  setSecret(secret: string): void;
  /** Every request received so far, oldest first. */
  deliveries(): WebhookDelivery[];
  /** Waits until a received delivery satisfies `match` and returns it. */
  waitFor(match: (d: WebhookDelivery) => boolean, timeoutMs?: number): Promise<WebhookDelivery>;
  stop(): Promise<void>;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 1024 * 1024) {
        reject(new Error('webhook body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function header(req: IncomingMessage, name: string): string {
  const value = req.headers[name];
  return Array.isArray(value) ? value.join(' ') : (value ?? '');
}

/**
 * Starts the sink on 127.0.0.1 (random port). A verified delivery is answered 204, anything else
 * 401 (so the server would retry it); both are recorded.
 */
export async function startWebhookSink(): Promise<WebhookSink> {
  let secret: string | undefined;
  const received: WebhookDelivery[] = [];

  const server: Server = createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== '/hook') {
      res.writeHead(404).end();
      return;
    }
    readBody(req).then(
      (body) => {
        const id = header(req, 'webhook-id');
        const timestamp = header(req, 'webhook-timestamp');
        const signature = header(req, 'webhook-signature');
        const verified =
          secret !== undefined && id !== '' && verifyWebhook(secret, id, timestamp, body, signature);
        let payload: WebhookDelivery['payload'];
        try {
          payload = JSON.parse(body) as WebhookDelivery['payload'];
        } catch {
          payload = undefined;
        }
        received.push({
          id,
          timestamp: Number.parseInt(timestamp, 10),
          body,
          payload,
          verified,
          headers: { ...req.headers },
        });
        res.writeHead(verified ? 204 : 401).end();
      },
      () => res.writeHead(400).end(),
    );
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}/hook`,
    setSecret(value: string) {
      webhookKey(value);
      secret = value;
    },
    deliveries: () => [...received],
    async waitFor(match, timeoutMs = 30_000) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const found = received.find(match);
        if (found) return found;
        if (Date.now() > deadline) {
          const seen = received.map((d) => `${d.payload?.type ?? '?'} verified=${d.verified}`).join(', ');
          throw new Error(`no matching webhook delivery within ${timeoutMs} ms (received: ${seen || 'none'})`);
        }
        await new Promise((r) => setTimeout(r, 200));
      }
    },
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
