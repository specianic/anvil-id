// Manual debugging entry point for the mock IdPs:
//
//   node --experimental-strip-types tests/e2e/lib/mock-idp-cli.ts apple|github [redirect_uri] [client_id]
//
// Prints the base URL (and, for github, the generated client secret) and runs until interrupted.
// The Apple-like mock starts without a client key, so its token endpoint answers invalid_client;
// the authorize page and /auth/keys are usable for inspection.

type MockIdpModule = typeof import('./mock-idp');

const kind = process.argv[2];
if (kind !== 'apple' && kind !== 'github') {
  console.error('usage: mock-idp-cli.ts apple|github [redirect_uri] [client_id]');
  process.exit(2);
}
const redirectUri = process.argv[3] ?? 'http://localhost:8080/ui/login/upstream/mock/callback';
const clientId = process.argv[4] ?? 'mock-client';

// Imported with an explicit .ts path at runtime (node strips types; tsc resolves the type above).
const mod = (await import(new URL('./mock-idp.ts', import.meta.url).href)) as MockIdpModule;
const idp = await mod.startMockIdp({ kind, clientId, redirectUri });
console.log(idp.url);
if (kind === 'github') console.log(`client_secret=${idp.clientSecret}`);

const shutdown = (): void => {
  void idp.stop().then(() => process.exit(0));
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
