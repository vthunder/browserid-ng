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
    // DISABLE_SMTP=1 prevents .env from enabling SMTP (checked before .env loads)
    command: 'DISABLE_SMTP=1 cargo run -p browserid-broker',
    url: 'http://localhost:3000/.well-known/browserid',
    cwd: '..',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
