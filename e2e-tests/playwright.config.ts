import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
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
    // Set SMTP_HOST empty to force console email sender during tests
    // (dotenvy loads .env AFTER process starts, so env -u doesn't work)
    command: 'SMTP_HOST= cargo run -p browserid-broker',
    url: 'http://localhost:3000/.well-known/browserid',
    cwd: '..',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
