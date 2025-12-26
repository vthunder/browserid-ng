/**
 * Reset Password E2E Tests
 *
 * Adapted from browserid/automation-tests/tests/reset-password-test.js
 *
 * Tests the forgot password flow through the dialog.
 */

import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

test.describe('Reset Password Flow', () => {
  test('forgot password link leads to reset screen', async ({ dialogPage, request }) => {
    const testEmail = generateTestEmail();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create a user first via API
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: generateTestPassword() },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Go to dialog and enter email
    await dialogPage.goto('http://example.com');
    await dialogPage.enterEmail(testEmail);
    await dialogPage.waitForScreen('password');

    // Click forgot password
    await dialogPage.forgotPasswordLink.click();

    // Should show reset email screen
    await dialogPage.page.waitForSelector('#reset-email-screen.active');
    const resetEmailInput = dialogPage.page.locator('#reset-email');
    await expect(resetEmailInput).toBeVisible();
    // Email should be pre-filled
    await expect(resetEmailInput).toHaveValue(testEmail);
  });

  test('can request password reset', async ({ dialogPage, request }) => {
    const testEmail = generateTestEmail();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: generateTestPassword() },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Request password reset via dialog
    await dialogPage.goto('http://example.com');
    await dialogPage.enterEmail(testEmail);
    await dialogPage.waitForScreen('password');
    await dialogPage.forgotPasswordLink.click();

    await dialogPage.page.waitForSelector('#reset-email-screen.active');
    await dialogPage.page.click('#reset-email-form button[type="submit"]');

    // Should show reset password screen (enter code + new password)
    await dialogPage.page.waitForSelector('#reset-password-screen.active');
    await expect(dialogPage.page.locator('#reset-code')).toBeVisible();
    await expect(dialogPage.page.locator('#new-password')).toBeVisible();
  });

  test('complete password reset with valid code', async ({ dialogPage, request }) => {
    const testEmail = generateTestEmail();
    const oldPassword = generateTestPassword();
    const newPassword = 'NewResetPassword789!';
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: oldPassword },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Request password reset
    await dialogPage.goto('http://example.com');
    await dialogPage.enterEmail(testEmail);
    await dialogPage.waitForScreen('password');
    await dialogPage.forgotPasswordLink.click();

    await dialogPage.page.waitForSelector('#reset-email-screen.active');
    await dialogPage.page.click('#reset-email-form button[type="submit"]');
    await dialogPage.page.waitForSelector('#reset-password-screen.active');

    // Get the reset code from test endpoint
    const resetPendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=password_reset`
    );
    const resetPending = await resetPendingResponse.json();
    expect(resetPending.success).toBeTruthy();
    expect(resetPending.code).toBeDefined();

    // Enter reset code and new password
    await dialogPage.page.fill('#reset-code', resetPending.code);
    await dialogPage.page.fill('#new-password', newPassword);
    await dialogPage.page.click('#reset-password-form button[type="submit"]');

    // Should show success screen
    await dialogPage.waitForSuccess();
  });

  test('can sign in with new password after reset', async ({ dialogPage, request, context }) => {
    const testEmail = generateTestEmail();
    const oldPassword = generateTestPassword();
    const newPassword = 'NewResetPassword789!';
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: oldPassword },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Request and complete password reset
    await dialogPage.goto('http://example.com');
    await dialogPage.enterEmail(testEmail);
    await dialogPage.waitForScreen('password');
    await dialogPage.forgotPasswordLink.click();

    await dialogPage.page.waitForSelector('#reset-email-screen.active');
    await dialogPage.page.click('#reset-email-form button[type="submit"]');
    await dialogPage.page.waitForSelector('#reset-password-screen.active');

    const resetPendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=password_reset`
    );
    const resetPending = await resetPendingResponse.json();

    await dialogPage.page.fill('#reset-code', resetPending.code);
    await dialogPage.page.fill('#new-password', newPassword);
    await dialogPage.page.click('#reset-password-form button[type="submit"]');
    await dialogPage.waitForSuccess();

    // Logout and sign in with new password
    await dialogPage.page.evaluate(async () => {
      await fetch('/wsapi/logout', { method: 'POST', credentials: 'include' });
    });

    const newPage = await context.newPage();
    await newPage.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
    await newPage.waitForSelector('#email-screen.active');

    await newPage.fill('#email', testEmail);
    await newPage.click('#email-form button[type="submit"]');
    await newPage.waitForSelector('#password-screen.active');

    await newPage.fill('#password', newPassword);
    await newPage.click('#password-form button[type="submit"]');

    // Should succeed
    await newPage.waitForSelector('#success-screen.active');
    await newPage.close();
  });

  test('invalid reset code is rejected', async ({ dialogPage, request }) => {
    const testEmail = generateTestEmail();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: generateTestPassword() },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Request password reset
    await dialogPage.goto('http://example.com');
    await dialogPage.enterEmail(testEmail);
    await dialogPage.waitForScreen('password');
    await dialogPage.forgotPasswordLink.click();

    await dialogPage.page.waitForSelector('#reset-email-screen.active');
    await dialogPage.page.click('#reset-email-form button[type="submit"]');
    await dialogPage.page.waitForSelector('#reset-password-screen.active');

    // Enter wrong code
    await dialogPage.page.fill('#reset-code', '000000');
    await dialogPage.page.fill('#new-password', 'SomeNewPassword123!');
    await dialogPage.page.click('#reset-password-form button[type="submit"]');

    // Should show error
    const codeError = dialogPage.page.locator('#reset-code-error');
    await expect(codeError).toBeVisible();
  });

  test('old password does not work after reset', async ({ dialogPage, request, context }) => {
    const testEmail = generateTestEmail();
    const oldPassword = generateTestPassword();
    const newPassword = 'NewResetPassword789!';
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: oldPassword },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Complete password reset
    await dialogPage.goto('http://example.com');
    await dialogPage.enterEmail(testEmail);
    await dialogPage.waitForScreen('password');
    await dialogPage.forgotPasswordLink.click();

    await dialogPage.page.waitForSelector('#reset-email-screen.active');
    await dialogPage.page.click('#reset-email-form button[type="submit"]');
    await dialogPage.page.waitForSelector('#reset-password-screen.active');

    const resetPendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=password_reset`
    );
    const resetPending = await resetPendingResponse.json();

    await dialogPage.page.fill('#reset-code', resetPending.code);
    await dialogPage.page.fill('#new-password', newPassword);
    await dialogPage.page.click('#reset-password-form button[type="submit"]');
    await dialogPage.waitForSuccess();

    // Logout
    await dialogPage.page.evaluate(async () => {
      await fetch('/wsapi/logout', { method: 'POST', credentials: 'include' });
    });

    // Try old password - should fail
    const newPage = await context.newPage();
    await newPage.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
    await newPage.waitForSelector('#email-screen.active');

    await newPage.fill('#email', testEmail);
    await newPage.click('#email-form button[type="submit"]');
    await newPage.waitForSelector('#password-screen.active');

    await newPage.fill('#password', oldPassword);
    await newPage.click('#password-form button[type="submit"]');

    // Should show error
    await expect(newPage.locator('#password-error')).toBeVisible();
    await expect(newPage.locator('#password-error')).toContainText('Invalid credentials');

    await newPage.close();
  });
});
