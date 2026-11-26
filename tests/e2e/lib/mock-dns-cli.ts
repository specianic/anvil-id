// Suite-wide mock DNS entry point (started once by tests/e2e/run.sh, before anvilid):
//
//   node --experimental-strip-types tests/e2e/lib/mock-dns-cli.ts --port 53535 --control-port 53536
//
// Prints `READY <udp port> <control URL>` once both sockets are bound, then serves until SIGTERM or
// SIGINT. Port 0 picks a free port (the printed line tells which). See lib/mock-dns.ts for the DNS
// behaviour and the control API.

type MockDnsModule = typeof import('./mock-dns');

function usage(message: string): never {
  console.error(`mock-dns-cli: ${message}`);
  console.error('usage: mock-dns-cli.ts --port <udp port> --control-port <http port>');
  process.exit(2);
}

function portArg(flag: string): number {
  const i = process.argv.indexOf(flag);
  if (i < 0 || i + 1 >= process.argv.length) usage(`missing ${flag}`);
  const value = Number(process.argv[i + 1]);
  if (!Number.isInteger(value) || value < 0 || value > 65535) usage(`invalid ${flag} ${process.argv[i + 1]}`);
  return value;
}

const port = portArg('--port');
const controlPort = portArg('--control-port');

// Imported with an explicit .ts path at runtime (node strips types; tsc resolves the type above).
const mod = (await import(new URL('./mock-dns.ts', import.meta.url).href)) as MockDnsModule;
const dns = await mod.startMockDns({ port, controlPort });
console.log(`READY ${dns.port} ${dns.controlUrl}`);

const shutdown = (): void => {
  void dns.close().then(() => process.exit(0));
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
