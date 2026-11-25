import { defineConfig, devices } from '@playwright/test';

// Endpoints come from the environment only:
//   ANVIL_URL    public URL of the AnvilID under test
//   MAILPIT_URL  Mailpit HTTP API/UI base URL
//   RP_URL       base URL of the sample relying party (examples/node-rp)
//
// Projects:
//   chromium  every spec except the no-JavaScript ones
//   nojs      specs named nojs*.spec.ts, run with JavaScript disabled (UI-01/UI-02: every flow works
//             without JavaScript)
const NOJS_SPECS = /nojs\..*\.spec\.ts|nojs\.spec\.ts/;

export default defineConfig({
  testDir: 'specs',
  outputDir: '../../e2e-results',
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: process.env.ANVIL_URL,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
      testIgnore: NOJS_SPECS,
    },
    {
      name: 'nojs',
      use: { ...devices['Desktop Chrome'], javaScriptEnabled: false },
      testMatch: NOJS_SPECS,
    },
  ],
});
