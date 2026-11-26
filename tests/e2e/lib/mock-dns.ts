// Local mock DNS server for the domain-verification and identifier-first routing e2e tests
// (test tooling only, never shipped).
//
// Zero npm dependencies (node:dgram, node:http), so the file also runs directly with
// `node --experimental-strip-types` (see mock-dns-cli.ts).
//
// ONE instance serves the whole e2e suite: run.sh starts it through mock-dns-cli.ts before anvilid,
// points anvilid's `domain_verification_resolvers` at `127.0.0.1:$E2E_DNS_PORT` and exports
// E2E_DNS_CONTROL_URL. Specs never start their own server (the mock-dns self-test is the only
// exception); they publish records with `publishTxt(name, values)` / `removeTxt(name)`, which talk to the
// HTTP control channel:
//
//   PUT    /txt/{name}   body: JSON array of strings (non-empty)  -> 204, replaces the name's TXT values
//   DELETE /txt/{name}                                            -> 204 (also when the name was absent)
//   DELETE /txt                                                   -> 204, removes every record
//   GET    /txt                                                   -> 200, JSON object name -> values (debugging)
//
// DNS behaviour (UDP on 127.0.0.1):
//   - Names compare case-insensitively and a trailing dot is ignored.
//   - TXT (type 16) query for a configured name: NOERROR, one TXT RR per value, each value split into
//     255-byte character-strings (resolvers return the chunks; callers join them). TTL 0.
//   - Any other query type for a configured name: NOERROR with an empty answer section (NODATA), as an
//     authoritative server does for an existing name without records of that type.
//   - Unknown name: NXDOMAIN.
//   - Opcode other than QUERY: NOTIMP. Not exactly one question, or an unparsable question: FORMERR.
//   - The TC flag is never set (values stay small; responses are not size-checked against 512 bytes).

import { createSocket } from 'node:dgram';
import type { RemoteInfo, Socket } from 'node:dgram';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface MockDnsOptions {
  /** UDP port on 127.0.0.1. 0 = a free port. */
  port: number;
  /** HTTP control port on 127.0.0.1. 0 = a free port. */
  controlPort: number;
}

export interface MockDns {
  /** Always 127.0.0.1. */
  address: string;
  /** The bound UDP port. */
  port: number;
  /** Base URL of the HTTP control channel, e.g. http://127.0.0.1:41234 */
  controlUrl: string;
  /** Replaces the TXT values of `name` (in-process equivalent of PUT /txt/{name}). An empty list removes the name. */
  setTxt(name: string, values: string[]): void;
  /** Removes every record. */
  clear(): void;
  close(): Promise<void>;
}

const TYPE_TXT = 16;
const CLASS_IN = 1;
const RCODE_NOERROR = 0;
const RCODE_FORMERR = 1;
const RCODE_NXDOMAIN = 3;
const RCODE_NOTIMP = 4;
const MAX_CONTROL_BODY = 64 * 1024;

/** Lower-cases a DNS name and strips one trailing dot; returns null for an invalid name. */
export function normalizeDnsName(name: string): string | null {
  const n = name.trim().toLowerCase().replace(/\.$/, '');
  if (n.length === 0 || Buffer.byteLength(n) > 253) return null;
  for (const label of n.split('.')) {
    const len = Buffer.byteLength(label);
    if (len === 0 || len > 63) return null;
  }
  return n;
}

interface Question {
  name: string;
  type: number;
  klass: number;
  /** Offset just past the question section. */
  end: number;
}

/** Reads the single question (no compression pointers are legal in a query's question). */
function readQuestion(msg: Buffer): Question | null {
  let offset = 12;
  const labels: string[] = [];
  for (;;) {
    if (offset >= msg.length) return null;
    const len = msg[offset];
    offset += 1;
    if (len === 0) break;
    if (len > 63 || offset + len > msg.length) return null;
    labels.push(msg.toString('latin1', offset, offset + len));
    offset += len;
  }
  if (offset + 4 > msg.length) return null;
  return {
    name: labels.join('.').toLowerCase(),
    type: msg.readUInt16BE(offset),
    klass: msg.readUInt16BE(offset + 2),
    end: offset + 4,
  };
}

function txtRdata(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8');
  const parts: Buffer[] = [];
  if (bytes.length === 0) parts.push(Buffer.from([0]));
  for (let i = 0; i < bytes.length; i += 255) {
    const chunk = bytes.subarray(i, i + 255);
    parts.push(Buffer.from([chunk.length]), chunk);
  }
  return Buffer.concat(parts);
}

function buildResponse(query: Buffer, rcode: number, question: Question | null, answers: string[]): Buffer {
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2); // ID
  const qFlags = query.readUInt16BE(2);
  const opcode = (qFlags >> 11) & 0x0f;
  const rd = qFlags & 0x0100;
  // QR=1, opcode echoed, AA=1, TC=0, RD echoed, RA=0, rcode.
  header.writeUInt16BE(0x8000 | (opcode << 11) | 0x0400 | rd | (rcode & 0x0f), 2);
  header.writeUInt16BE(question ? 1 : 0, 4);
  header.writeUInt16BE(answers.length, 6);
  const parts: Buffer[] = [header];
  if (question) {
    parts.push(query.subarray(12, question.end));
    for (const value of answers) {
      const rdata = txtRdata(value);
      const rr = Buffer.alloc(12);
      rr.writeUInt16BE(0xc00c, 0); // pointer to the question name
      rr.writeUInt16BE(TYPE_TXT, 2);
      rr.writeUInt16BE(CLASS_IN, 4);
      rr.writeUInt32BE(0, 6); // TTL 0: tests change records constantly
      rr.writeUInt16BE(rdata.length, 10);
      parts.push(rr, rdata);
    }
  }
  return Buffer.concat(parts);
}

function answer(records: Map<string, string[]>, msg: Buffer): Buffer | null {
  if (msg.length < 12) return null; // not even a header: drop
  if (msg[2] & 0x80) return null; // a response, not a query: drop
  const opcode = (msg[2] >> 3) & 0x0f;
  if (opcode !== 0) return buildResponse(msg, RCODE_NOTIMP, null, []);
  if (msg.readUInt16BE(4) !== 1) return buildResponse(msg, RCODE_FORMERR, null, []);
  const q = readQuestion(msg);
  if (!q) return buildResponse(msg, RCODE_FORMERR, null, []);
  const values = q.klass === CLASS_IN || q.klass === 255 ? records.get(q.name) : undefined;
  if (!values) return buildResponse(msg, RCODE_NXDOMAIN, q, []);
  if (q.type !== TYPE_TXT && q.type !== 255) return buildResponse(msg, RCODE_NOERROR, q, []);
  return buildResponse(msg, RCODE_NOERROR, q, values);
}

function sendStatus(res: ServerResponse, status: number, message?: string): void {
  if (message === undefined) {
    res.writeHead(status);
    res.end();
  } else {
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(message);
  }
}

function readBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      // Past the limit the rest is drained and discarded, so the client still reads the 413.
      if (size <= MAX_CONTROL_BODY) chunks.push(c);
    });
    req.on('end', () => resolve(size > MAX_CONTROL_BODY ? null : Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function parseValues(body: string): string[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed) || parsed.length === 0 || !parsed.every((v) => typeof v === 'string')) return null;
  return parsed as string[];
}

export async function startMockDns(opts: MockDnsOptions): Promise<MockDns> {
  const records = new Map<string, string[]>();

  const setTxt = (name: string, values: string[]): void => {
    const n = normalizeDnsName(name);
    if (n === null) throw new Error(`mock-dns: invalid name ${JSON.stringify(name)}`);
    if (values.length === 0) records.delete(n);
    else records.set(n, [...values]);
  };

  const udp: Socket = createSocket('udp4');
  udp.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
    const reply = answer(records, msg);
    if (reply) udp.send(reply, rinfo.port, rinfo.address);
  });
  await new Promise<void>((resolve, reject) => {
    udp.once('error', reject);
    udp.bind(opts.port, '127.0.0.1', () => {
      udp.off('error', reject);
      resolve();
    });
  });
  // Later socket errors (e.g. ICMP-induced) must not crash the suite-wide process.
  udp.on('error', (err) => console.error(`mock-dns: udp error: ${err.message}`));

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (url.pathname === '/txt') {
      if (req.method === 'DELETE') {
        records.clear();
        sendStatus(res, 204);
      } else if (req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(Object.fromEntries(records)));
      } else {
        sendStatus(res, 405, 'method not allowed');
      }
      return;
    }
    if (!url.pathname.startsWith('/txt/')) {
      sendStatus(res, 404, 'not found');
      return;
    }
    let rawName: string;
    try {
      rawName = decodeURIComponent(url.pathname.slice('/txt/'.length));
    } catch {
      sendStatus(res, 400, 'bad name encoding');
      return;
    }
    const name = normalizeDnsName(rawName);
    if (name === null) {
      sendStatus(res, 400, 'invalid DNS name');
      return;
    }
    if (req.method === 'DELETE') {
      records.delete(name);
      sendStatus(res, 204);
      return;
    }
    if (req.method !== 'PUT') {
      sendStatus(res, 405, 'method not allowed');
      return;
    }
    const body = await readBody(req);
    if (body === null) {
      sendStatus(res, 413, 'body too large');
      return;
    }
    const values = parseValues(body);
    if (values === null) {
      sendStatus(res, 400, 'body must be a non-empty JSON array of strings');
      return;
    }
    records.set(name, values);
    sendStatus(res, 204);
  };

  const http: Server = createServer((req, res) => {
    handle(req, res).catch((err: Error) => {
      if (!res.headersSent) sendStatus(res, 500, `mock-dns error: ${err.message}`);
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      http.once('error', reject);
      http.listen(opts.controlPort, '127.0.0.1', () => resolve());
    });
  } catch (err) {
    udp.close();
    throw err;
  }

  const port = (udp.address() as AddressInfo).port;
  const controlUrl = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;

  return {
    address: '127.0.0.1',
    port,
    controlUrl,
    setTxt,
    clear: () => records.clear(),
    close: () =>
      new Promise<void>((resolve) => {
        http.closeAllConnections();
        http.close(() => udp.close(() => resolve()));
      }),
  };
}

// ---------------------------------------------------------------------------------------------------
// Spec client: the only way specs touch DNS. Reads E2E_DNS_CONTROL_URL (exported by run.sh).
// ---------------------------------------------------------------------------------------------------

function controlBase(controlUrl: string | undefined): string {
  const base = controlUrl ?? process.env.E2E_DNS_CONTROL_URL;
  if (!base) throw new Error('E2E_DNS_CONTROL_URL is not set (run the suite through tests/e2e/run.sh, which starts the mock DNS)');
  return base.replace(/\/$/, '');
}

/** Publishes (replaces) the TXT values of `name` on the suite-wide mock DNS. */
export async function publishTxt(name: string, values: string[], controlUrl?: string): Promise<void> {
  const res = await fetch(`${controlBase(controlUrl)}/txt/${encodeURIComponent(name)}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(values),
  });
  if (res.status !== 204) throw new Error(`mock-dns: PUT ${name} -> ${res.status} ${await res.text()}`);
}

/** Removes every TXT value of `name` from the suite-wide mock DNS. */
export async function removeTxt(name: string, controlUrl?: string): Promise<void> {
  const res = await fetch(`${controlBase(controlUrl)}/txt/${encodeURIComponent(name)}`, { method: 'DELETE' });
  if (res.status !== 204) throw new Error(`mock-dns: DELETE ${name} -> ${res.status} ${await res.text()}`);
}
