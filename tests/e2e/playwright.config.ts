import { defineConfig, devices } from '@playwright/test';

// Endpoints come from the environment only:
//   ANVIL_URL    public URL of the AnvilID under test
//   MAILPIT_URL  Mailpit HTTP API/UI base URL
//   RP_URL       base URL of the sample relying party (examples/node-rp)
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
    },
  ],
});
