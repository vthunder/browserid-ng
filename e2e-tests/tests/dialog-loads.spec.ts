import { test, expect } from '../fixtures/test-helpers';

test.describe('Dialog Loading', () => {
  test('dialog page loads successfully', async ({ page }) => {
    await page.goto('/dialog/dialog.html?origin=http://example.com');

    // Check page title
    await expect(page).toHaveTitle('Sign In');
  });

  test('dialog shows email input after initialization', async ({ dialogPage }) => {
    await dialogPage.goto('http://example.com');

    await expect(dialogPage.emailInput).toBeVisible();
  });

  test('dialog shows RP name from origin', async ({ page }) => {
    await page.goto('/dialog/dialog.html?origin=http://example.com');

    // Wait for initialization
    await page.waitForSelector('#email-screen.active');

    // Check RP name is displayed
    const rpName = page.locator('.rp-name').first();
    await expect(rpName).toHaveText('example.com');
  });

  test('broker well-known endpoint is accessible', async ({ request }) => {
    const response = await request.get('/.well-known/browserid');

    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body).toHaveProperty('public-key');
    expect(body).toHaveProperty('authentication');
    expect(body).toHaveProperty('provisioning');
  });

  test('session context returns unauthenticated initially', async ({ brokerApi }) => {
    const context = await brokerApi.getSessionContext();

    expect(context.authenticated).toBe(false);
  });
});
