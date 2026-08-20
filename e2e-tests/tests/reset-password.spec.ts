/**
 * Reset Password E2E Tests
 *
 * Since audit M7 (browserid-ng-dw35) the cold sign-in dialog is
 * enumeration-safe: it shows the same optimistic password screen whether or
 * not an account exists, and one "email me a code" hatch covers new users,
 * password-less accounts, AND forgotten passwords. A reset is therefore the
 * unified sign-in-code flow: choose a new password, confirm with the mailed
 * code — the server resolves create-vs-reset after the mailbox proof.
 */

import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

/** Create a verified, password-backed user via the API. */
async function createUser(request: any, email: string, password: string) {
  const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
    data: { email, pass: password },
  });
  expect(stageResponse.ok()).toBeTruthy();
  const pendingResponse = await request.get(
    `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=new_account`
  );
  const pending = await pendingResponse.json();
  await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
    data: { email, token: pending.code },
  });
}

/** Fetch the pending unified sign-in code for an address. */
async function getSigninCode(request: any, email: string): Promise<string> {
  const response = await request.get(
    `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=signin_code`
  );
  const pending = await response.json();
  expect(pending.success).toBeTruthy();
  expect(pending.code).toBeDefined();
  return pending.code;
}

test.describe('Reset Password Flow (unified sign-in code)', () => {
  test('code hatch leads to the sign-in-code screen', async ({ dialogPage, request }) => {
    const testEmail = generateTestEmail();
    await createUser(request, testEmail, generateTestPassword());

    // Go to dialog and enter email — an existing account gets the SAME
    // optimistic password screen as an unknown one (no enumeration).
    await dialogPage.goto('http://example.com');
    await dialogPage.enterEmail(testEmail);
    await dialogPage.waitForScreen('password');
    await expect(dialogPage.emailCodeLink).toBeVisible();

    await dialogPage.emailCodeLink.click();
    await dialogPage.waitForScreen('create');
    await expect(dialogPage.createPasswordInput).toBeVisible();
    await expect(dialogPage.confirmPasswordInput).toBeVisible();
  });

  test('complete password reset with valid code', async ({ dialogPage, request }) => {
    const testEmail = generateTestEmail();
    const newPassword = 'NewResetPassword789!';
    await createUser(request, testEmail, generateTestPassword());

    // Reset = choose the new password up front, then confirm via code.
    await dialogPage.goto('http://example.com');
    await dialogPage.signUpNewUser(testEmail, newPassword);
    await dialogPage.waitForScreen('verify');

    const code = await getSigninCode(request, testEmail);
    await dialogPage.enterVerificationCode(code);

    // Should show success screen
    await dialogPage.waitForSuccess();
  });

  test('can sign in with new password after reset', async ({ dialogPage, request, context }) => {
    const testEmail = generateTestEmail();
    const newPassword = 'NewResetPassword789!';
    await createUser(request, testEmail, generateTestPassword());

    // Request and complete the reset through the dialog.
    await dialogPage.goto('http://example.com');
    await dialogPage.signUpNewUser(testEmail, newPassword);
    await dialogPage.waitForScreen('verify');
    await dialogPage.enterVerificationCode(await getSigninCode(request, testEmail));
    await dialogPage.waitForSuccess();

    // Logout and sign in with new password
    await dialogPage.page.evaluate(async () => {
      const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) => r.json());
      await fetch('/wsapi/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ csrf: sc.csrf_token }),
      });
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

  test('invalid code is rejected', async ({ dialogPage, request }) => {
    const testEmail = generateTestEmail();
    await createUser(request, testEmail, generateTestPassword());

    await dialogPage.goto('http://example.com');
    await dialogPage.signUpNewUser(testEmail, 'SomeNewPassword123!');
    await dialogPage.waitForScreen('verify');

    // Enter wrong code
    await dialogPage.enterVerificationCode('000000');

    // Should show error
    await expect(dialogPage.verifyError).toBeVisible();
  });

  test('old password does not work after reset', async ({ dialogPage, request, context }) => {
    const testEmail = generateTestEmail();
    const oldPassword = generateTestPassword();
    const newPassword = 'NewResetPassword789!';
    await createUser(request, testEmail, oldPassword);

    // Complete the reset through the dialog.
    await dialogPage.goto('http://example.com');
    await dialogPage.signUpNewUser(testEmail, newPassword);
    await dialogPage.waitForScreen('verify');
    await dialogPage.enterVerificationCode(await getSigninCode(request, testEmail));
    await dialogPage.waitForSuccess();

    // Logout
    await dialogPage.page.evaluate(async () => {
      const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) => r.json());
      await fetch('/wsapi/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ csrf: sc.csrf_token }),
      });
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
