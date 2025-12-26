/**
 * Returning User E2E Tests
 *
 * Adapted from browserid/automation-tests/tests/returning-user.js
 *
 * Tests the returning user flow - when a user is already authenticated
 * and opens the dialog again.
 */

import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

test.describe('Returning User Flow', () => {
  test('authenticated user with single email auto-completes', async ({ dialogPage, request, context }) => {
    const testEmail = generateTestEmail();
    const testPassword = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // First, create and authenticate a user via API
    // Stage user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: testPassword },
    });
    expect(stageResponse.ok()).toBeTruthy();

    // Get verification code
    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    expect(pending.success).toBeTruthy();

    // Complete registration
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Now sign in through the dialog to establish a session
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, testPassword);
    await dialogPage.waitForSuccess();

    // Open dialog again - should auto-complete since user is authenticated
    // Create a new page in same context to share cookies
    const newPage = await context.newPage();
    await newPage.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);

    // Should show success screen directly (auto-sign-in for returning user)
    await newPage.waitForSelector('#success-screen.active', { timeout: 15000 });

    await newPage.close();
  });

  test('session persists across dialog opens', async ({ dialogPage, request, context }) => {
    const testEmail = generateTestEmail();
    const testPassword = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: testPassword },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, testPassword);
    await dialogPage.waitForSuccess();

    // Check session context shows authenticated
    const sessionResponse = await request.get(`${baseUrl}/wsapi/session_context`);
    const session = await sessionResponse.json();
    expect(session.authenticated).toBeTruthy();
  });

  test('logout clears session', async ({ dialogPage, request }) => {
    const testEmail = generateTestEmail();
    const testPassword = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: testPassword },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, testPassword);
    await dialogPage.waitForSuccess();

    // Logout
    await request.post(`${baseUrl}/wsapi/logout`);

    // Check session is cleared
    const sessionResponse = await request.get(`${baseUrl}/wsapi/session_context`);
    const session = await sessionResponse.json();
    expect(session.authenticated).toBeFalsy();
  });

  test('after logout, dialog shows email screen', async ({ dialogPage, request, context, page }) => {
    const testEmail = generateTestEmail();
    const testPassword = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create and sign in user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: testPassword },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, testPassword);
    await dialogPage.waitForSuccess();

    // Logout via browser (using page's fetch to maintain cookies)
    await page.evaluate(async () => {
      await fetch('/wsapi/logout', { method: 'POST', credentials: 'include' });
    });

    // Open dialog again - should show email screen
    const newPage = await context.newPage();
    await newPage.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);

    // Should show email screen (not auto-complete)
    await newPage.waitForSelector('#email-screen.active', { timeout: 10000 });

    await newPage.close();
  });
});
