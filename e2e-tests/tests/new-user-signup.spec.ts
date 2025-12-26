/**
 * New User Signup E2E Tests
 *
 * Ported from browserid/automation-tests/tests/new-user/new-user-secondary-test.js
 *
 * Tests the new user registration flow through the dialog.
 * Unlike the original which used restmail, we use our test endpoint
 * to retrieve verification codes.
 */

import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

test.describe('New User Signup Flow', () => {
  test('new email shows create account screen', async ({ dialogPage }) => {
    const newEmail = generateTestEmail();
    await dialogPage.goto('http://example.com');

    // Enter a new email
    await dialogPage.enterEmail(newEmail);

    // Should show create account screen
    await dialogPage.waitForScreen('create');
    await expect(dialogPage.createPasswordInput).toBeVisible();
    await expect(dialogPage.confirmPasswordInput).toBeVisible();
  });

  test('password mismatch shows error', async ({ dialogPage }) => {
    const newEmail = generateTestEmail();
    await dialogPage.goto('http://example.com');

    // Enter email
    await dialogPage.enterEmail(newEmail);
    await dialogPage.waitForScreen('create');

    // Enter mismatched passwords
    await dialogPage.createPasswordInput.fill('Password123!');
    await dialogPage.confirmPasswordInput.fill('DifferentPassword!');
    await dialogPage.createAccountButton.click();

    // Should show error
    const confirmError = dialogPage.page.locator('#confirm-password-error');
    await expect(confirmError).toBeVisible();
    await expect(confirmError).toHaveText('Passwords do not match');
  });

  test('short password is rejected by HTML5 validation', async ({ dialogPage }) => {
    const newEmail = generateTestEmail();
    await dialogPage.goto('http://example.com');

    // Enter email
    await dialogPage.enterEmail(newEmail);
    await dialogPage.waitForScreen('create');

    // Enter short password
    await dialogPage.createPasswordInput.fill('short');
    await dialogPage.confirmPasswordInput.fill('short');

    // Try to submit - HTML5 validation should prevent it
    await dialogPage.createAccountButton.click();

    // We should still be on the create screen (form didn't submit)
    // because HTML5 minlength validation blocks it
    await expect(dialogPage.createScreen).toHaveClass(/active/);

    // The password input should have the :invalid pseudo-class
    // We can check by verifying the create screen is still active
    await expect(dialogPage.createPasswordInput).toBeVisible();
  });

  test('successful signup leads to verification screen', async ({ dialogPage }) => {
    const newEmail = generateTestEmail();
    const password = generateTestPassword();

    await dialogPage.goto('http://example.com');

    // Sign up
    await dialogPage.signUpNewUser(newEmail, password);

    // Should show verification screen
    await dialogPage.waitForScreen('verify');
    await expect(dialogPage.verificationCodeInput).toBeVisible();
  });

  test('complete signup with verification code', async ({ dialogPage, request }) => {
    const newEmail = generateTestEmail();
    const password = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    await dialogPage.goto('http://example.com');

    // Sign up
    await dialogPage.signUpNewUser(newEmail, password);
    await dialogPage.waitForScreen('verify');

    // Get verification code from test endpoint
    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(newEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    expect(pending.success).toBeTruthy();
    expect(pending.code).toBeDefined();

    // Enter verification code
    await dialogPage.enterVerificationCode(pending.code);

    // Should show success screen
    await dialogPage.waitForSuccess();
    await expect(dialogPage.successScreen).toHaveClass(/active/);
  });

  test('invalid verification code shows error', async ({ dialogPage }) => {
    const newEmail = generateTestEmail();
    const password = generateTestPassword();

    await dialogPage.goto('http://example.com');

    // Sign up
    await dialogPage.signUpNewUser(newEmail, password);
    await dialogPage.waitForScreen('verify');

    // Enter wrong verification code
    await dialogPage.enterVerificationCode('000000');

    // Should show error
    await expect(dialogPage.verifyError).toBeVisible();
  });

  test('back button from create screen returns to email screen', async ({ dialogPage }) => {
    const newEmail = generateTestEmail();
    await dialogPage.goto('http://example.com');

    // Enter email
    await dialogPage.enterEmail(newEmail);
    await dialogPage.waitForScreen('create');

    // Click back
    await dialogPage.backButton.first().click();

    // Should return to email screen
    await dialogPage.waitForScreen('email');
    await expect(dialogPage.emailInput).toBeVisible();
  });

  test('back button from verify screen returns to email screen', async ({ dialogPage }) => {
    const newEmail = generateTestEmail();
    const password = generateTestPassword();

    await dialogPage.goto('http://example.com');

    // Sign up
    await dialogPage.signUpNewUser(newEmail, password);
    await dialogPage.waitForScreen('verify');

    // Click back
    await dialogPage.backButton.first().click();

    // Should return to email screen
    await dialogPage.waitForScreen('email');
    await expect(dialogPage.emailInput).toBeVisible();
  });
});
