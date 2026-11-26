// Self-test of the local mock DNS (lib/mock-dns.ts, lib/mock-dns-cli.ts). Needs no AnvilID.
//
// This is the ONLY spec allowed to start its own mock DNS (on ephemeral ports); every other spec
// publishes records on the suite-wide instance through publishTxt/removeTxt.
//
// Names use the reserved `.test` TLD (RFC 2606), so nothing here could ever resolve publicly.

import { spawn } from 'node:child_process';
import { Resolver } from 'node:dns/promises';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { publishTxt, removeTxt, startMockDns, type MockDns } from '../lib/mock-dns';

function resolverFor(dns: MockDns): Resolver {
  const r = new Resolver({ timeout: 2000, tries: 1 });
  r.setServers([`${dns.address}:${dns.port}`]);
  return r;
}

/** resolveTxt returns each record as its character-string chunks; join them back. */
async function txt(r: Resolver, name: string): Promise<string[]> {
  return (await r.resolveTxt(name)).map((chunks) => chunks.join('')).sort();
}

async function errorCode(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code ?? 'no-code';
  }
  return 'resolved';
}

test.describe('mock DNS', () => {
  let dns: MockDns;

  test.beforeEach(async () => {
    dns = await startMockDns({ port: 0, controlPort: 0 });
  });

  test.afterEach(async () => {
    await dns.close();
  });

  test('answers TXT for configured names, including values longer than 255 bytes', async () => {
    const long = 'anvilid-verify=' + 'x'.repeat(600);
    dns.setTxt('_anvilid.acme.test', ['anvilid-verify=abc123', long]);
    const r = resolverFor(dns);
    expect(await txt(r, '_anvilid.acme.test')).toEqual(['anvilid-verify=abc123', long].sort());
    // The long value really travels as several 255-byte character-strings.
    const raw = await r.resolveTxt('_anvilid.acme.test');
    expect(raw.find((chunks) => chunks.join('') === long)?.map((c) => c.length)).toEqual([255, 255, 105]);
  });

  test('unknown names are NXDOMAIN (ENOTFOUND)', async () => {
    dns.setTxt('known.test', ['v']);
    expect(await errorCode(resolverFor(dns).resolveTxt('unknown.test'))).toBe('ENOTFOUND');
  });

  test('a non-TXT query for a configured name gets an empty NOERROR answer (ENODATA)', async () => {
    dns.setTxt('known.test', ['v']);
    expect(await errorCode(resolverFor(dns).resolve4('known.test'))).toBe('ENODATA');
  });

  test('names compare case-insensitively and tolerate a trailing dot', async () => {
    dns.setTxt('Mixed.Case.TEST.', ['one']);
    const r = resolverFor(dns);
    expect(await txt(r, 'mixed.case.test')).toEqual(['one']);
    expect(await txt(r, 'MIXED.case.Test')).toEqual(['one']);
    expect(await txt(r, 'mixed.case.test.')).toEqual(['one']);
  });

  test('the HTTP control channel and the spec client manage records', async () => {
    const r = resolverFor(dns);
    await publishTxt('_anvilid.example.test', ['a', 'b'], dns.controlUrl);
    expect(await txt(r, '_anvilid.example.test')).toEqual(['a', 'b']);

    // PUT replaces.
    await publishTxt('_ANVILID.example.test', ['c'], dns.controlUrl);
    expect(await txt(r, '_anvilid.example.test')).toEqual(['c']);

    const listed = await fetch(`${dns.controlUrl}/txt`);
    expect(await listed.json()).toEqual({ '_anvilid.example.test': ['c'] });

    await removeTxt('_anvilid.example.test', dns.controlUrl);
    expect(await errorCode(r.resolveTxt('_anvilid.example.test'))).toBe('ENOTFOUND');
    // Removing an absent name is fine (idempotent).
    await removeTxt('_anvilid.example.test', dns.controlUrl);

    await publishTxt('one.test', ['1'], dns.controlUrl);
    await publishTxt('two.test', ['2'], dns.controlUrl);
    const cleared = await fetch(`${dns.controlUrl}/txt`, { method: 'DELETE' });
    expect(cleared.status).toBe(204);
    expect(await errorCode(r.resolveTxt('one.test'))).toBe('ENOTFOUND');
    expect(await errorCode(r.resolveTxt('two.test'))).toBe('ENOTFOUND');
  });

  test('the control channel rejects bad input', async () => {
    const put = (path: string, body: string): Promise<Response> =>
      fetch(`${dns.controlUrl}${path}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body });
    expect((await put('/txt/bad.test', 'not json')).status).toBe(400);
    expect((await put('/txt/bad.test', '[]')).status).toBe(400);
    expect((await put('/txt/bad.test', '[1, 2]')).status).toBe(400);
    expect((await put('/txt/bad.test', '"str"')).status).toBe(400);
    expect((await put(`/txt/${encodeURIComponent('a..b.test')}`, '["v"]')).status).toBe(400);
    expect((await put(`/txt/${'x'.repeat(64)}.test`, '["v"]')).status).toBe(400);
    expect((await put('/txt/big.test', JSON.stringify(['x'.repeat(70 * 1024)]))).status).toBe(413);
    expect((await fetch(`${dns.controlUrl}/txt/bad.test`, { method: 'POST' })).status).toBe(405);
    expect((await fetch(`${dns.controlUrl}/other`)).status).toBe(404);
    expect(await (await fetch(`${dns.controlUrl}/txt`)).json()).toEqual({});
    await expect(publishTxt('bad.test', [], dns.controlUrl)).rejects.toThrow(/400/);
  });

  test('the spec client fails loudly without E2E_DNS_CONTROL_URL', async () => {
    const saved = process.env.E2E_DNS_CONTROL_URL;
    delete process.env.E2E_DNS_CONTROL_URL;
    try {
      await expect(publishTxt('x.test', ['v'])).rejects.toThrow(/E2E_DNS_CONTROL_URL/);
      await expect(removeTxt('x.test')).rejects.toThrow(/E2E_DNS_CONTROL_URL/);
    } finally {
      if (saved !== undefined) process.env.E2E_DNS_CONTROL_URL = saved;
    }
  });
});

test('mock-dns-cli prints READY, serves, and exits on SIGTERM', async () => {
  const cli = fileURLToPath(new URL('../lib/mock-dns-cli.ts', import.meta.url));
  const child = spawn(process.execPath, ['--experimental-strip-types', '--no-warnings', cli, '--port', '0', '--control-port', '0'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    const ready = await new Promise<string>((resolve, reject) => {
      let out = '';
      let err = '';
      child.stdout.on('data', (c: Buffer) => {
        out += c.toString('utf8');
        const line = out.split('\n').find((l) => l.startsWith('READY '));
        if (line) resolve(line);
      });
      child.stderr.on('data', (c: Buffer) => (err += c.toString('utf8')));
      child.once('exit', (code) => reject(new Error(`cli exited early (${code}): ${err}`)));
      setTimeout(() => reject(new Error(`no READY line: ${out} ${err}`)), 10_000);
    });
    const [, port, controlUrl] = ready.split(' ');
    await publishTxt('cli.test', ['from-cli'], controlUrl);
    const r = new Resolver({ timeout: 2000, tries: 1 });
    r.setServers([`127.0.0.1:${port}`]);
    expect((await r.resolveTxt('cli.test')).map((c) => c.join(''))).toEqual(['from-cli']);

    const exited = new Promise<number | null>((resolve) => child.once('exit', (code) => resolve(code)));
    child.kill('SIGTERM');
    expect(await exited).toBe(0);
  } finally {
    if (child.exitCode === null) child.kill('SIGKILL');
  }
});
