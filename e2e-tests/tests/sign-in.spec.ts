/**
 * Sign-In E2E Tests
 *
 * Ported from browserid/automation-tests/tests/sign-in-test.js
 *
 * Tests the sign-in flow for existing users through the dialog.
 */

import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

// Use describe.configure to run tests in this file serially to avoid state conflicts
test.describe.configure({ mode: 'serial' });

test.describe('Sign In Flow', () => {
  // Generate unique email at module level - use a more unique identifier
  const uniqueId = `${Date.now()}-${Math.random().toString(36).substring(7)}`;
  const testEmail = `signin-test-${uniqueId}@example.com`;
  const testPassword = generateTestPassword();

  test.beforeAll(async ({ request }) => {
    // Create a verified user before running sign-in tests
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

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
    expect(pending.code).toBeDefined();

    // Complete registration
    const completeResponse = await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });
    expect(completeResponse.ok()).toBeTruthy();
  });

  test('sign in with existing user shows password screen', async ({ dialogPage }) => {
    await dialogPage.goto('http://example.com');

    // Enter email
    await dialogPage.enterEmail(testEmail);

    // Should show password screen for existing user
    await dialogPage.waitForScreen('password');

    // Password input should be visible
    await expect(dialogPage.passwordInput).toBeVisible();
  });

  test('sign in with correct password succeeds', async ({ dialogPage }) => {
    await dialogPage.goto('http://example.com');

    // Sign in with existing user
    await dialogPage.signInExistingUser(testEmail, testPassword);

    // Should show success screen
    await dialogPage.waitForSuccess();
    await expect(dialogPage.successScreen).toHaveClass(/active/);
  });

  test('sign in with wrong password shows error', async ({ dialogPage }) => {
    await dialogPage.goto('http://example.com');

    // Try to sign in with wrong password
    await dialogPage.signInExistingUser(testEmail, 'WrongPassword123!');

    // Should stay on password screen with error
    await expect(dialogPage.passwordError).toBeVisible();
    const errorText = await dialogPage.getPasswordError();
    expect(errorText).toContain('Invalid credentials');
  });

  test('sign in is case-insensitive for email', async ({ dialogPage }) => {
    await dialogPage.goto('http://example.com');

    // Sign in with uppercase email
    await dialogPage.signInExistingUser(testEmail.toUpperCase(), testPassword);

    // Should still succeed
    await dialogPage.waitForSuccess();
    await expect(dialogPage.successScreen).toHaveClass(/active/);
  });

  test('sign in shows RP name', async ({ dialogPage }) => {
    await dialogPage.goto('http://example.com');

    // RP name should be displayed
    await expect(dialogPage.rpName).toHaveText('example.com');
  });

  test('unknown email shows create account screen', async ({ dialogPage }) => {
    await dialogPage.goto('http://example.com');

    // Enter a new email
    const newEmail = generateTestEmail();
    await dialogPage.enterEmail(newEmail);

    // Should show create account screen
    await dialogPage.waitForScreen('create');
    await expect(dialogPage.createPasswordInput).toBeVisible();
  });

  test('back button returns to email screen', async ({ dialogPage }) => {
    await dialogPage.goto('http://example.com');

    // Enter email to get to password screen
    await dialogPage.enterEmail(testEmail);
    await dialogPage.waitForScreen('password');

    // Click back
    await dialogPage.backButton.first().click();

    // Should return to email screen
    await dialogPage.waitForScreen('email');
    await expect(dialogPage.emailInput).toBeVisible();
  });
});
