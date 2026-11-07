import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // E2E_RETRIES=0 in the release-candidate job: a flake is a failure there.
  retries: process.env.E2E_RETRIES !== undefined ? Number(process.env.E2E_RETRIES) : process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',

  use: {
    // Base URL for the broker
    baseURL: process.env.BROKER_URL || 'http://localhost:3000',
    trace: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Run broker before tests
  webServer: {
    // DISABLE_SMTP=1 prevents .env from enabling SMTP (checked before .env loads)
    command: 'DISABLE_SMTP=1 AGENT_PROVISIONING=1 cargo run -p browserid-broker',
    url: 'http://localhost:3000/.well-known/browserid',
    cwd: '..',
    // E2E_EXTERNAL_BROKER=1: a broker (the release-candidate job's image) is
    // already serving :3000; never start a second one.
    reuseExistingServer: !process.env.CI || !!process.env.E2E_EXTERNAL_BROKER,
    timeout: 120000,
  },
});
