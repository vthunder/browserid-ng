/**
 * Change Password E2E Tests
 *
 * Adapted from browserid/automation-tests/tests/change-password-test.js
 *
 * Tests password change functionality. The original test used an account
 * management page; we test via API since our dialog doesn't have password
 * change UI (that would be in a separate account management interface).
 */

import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

test.describe('Change Password Flow', () => {
  test('can change password via API after signing in', async ({ dialogPage, request, page }) => {
    const testEmail = generateTestEmail();
    const oldPassword = generateTestPassword();
    const newPassword = 'NewPassword456!';
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

    // Sign in through dialog to establish session
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, oldPassword);
    await dialogPage.waitForSuccess();

    // Change password via API (using browser's fetch to maintain session)
    const updateResult = await page.evaluate(async ({ oldPass, newPass }) => {
      const response = await fetch('/wsapi/update_password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ oldpass: oldPass, newpass: newPass }),
      });
      return response.json();
    }, { oldPass: oldPassword, newPass: newPassword });

    expect(updateResult.success).toBeTruthy();

    // Logout
    await page.evaluate(async () => {
      await fetch('/wsapi/logout', { method: 'POST', credentials: 'include' });
    });

    // Sign in with new password should work
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, newPassword);
    await dialogPage.waitForSuccess();
  });

  test('old password no longer works after change', async ({ dialogPage, request, page, context }) => {
    const testEmail = generateTestEmail();
    const oldPassword = generateTestPassword();
    const newPassword = 'NewPassword456!';
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

    // Sign in and change password
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, oldPassword);
    await dialogPage.waitForSuccess();

    await page.evaluate(async ({ oldPass, newPass }) => {
      await fetch('/wsapi/update_password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ oldpass: oldPass, newpass: newPass }),
      });
    }, { oldPass: oldPassword, newPass: newPassword });

    // Logout
    await page.evaluate(async () => {
      await fetch('/wsapi/logout', { method: 'POST', credentials: 'include' });
    });

    // Try to sign in with old password - should fail
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

  test('wrong old password is rejected', async ({ dialogPage, request, page }) => {
    const testEmail = generateTestEmail();
    const password = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: password },
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
    await dialogPage.signInExistingUser(testEmail, password);
    await dialogPage.waitForSuccess();

    // Try to change password with wrong old password
    const updateResult = await page.evaluate(async ({ wrongOldPass, newPass }) => {
      const response = await fetch('/wsapi/update_password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ oldpass: wrongOldPass, newpass: newPass }),
      });
      return { ok: response.ok, data: await response.json() };
    }, { wrongOldPass: 'WrongOldPassword!', newPass: 'NewPassword456!' });

    expect(updateResult.ok).toBeFalsy();
    expect(updateResult.data.reason).toContain('Invalid credentials');
  });

  test('new password must meet length requirements', async ({ dialogPage, request, page }) => {
    const testEmail = generateTestEmail();
    const password = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: password },
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
    await dialogPage.signInExistingUser(testEmail, password);
    await dialogPage.waitForSuccess();

    // Try to change to a short password
    const updateResult = await page.evaluate(async ({ oldPass, shortPass }) => {
      const response = await fetch('/wsapi/update_password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ oldpass: oldPass, newpass: shortPass }),
      });
      return { ok: response.ok, data: await response.json() };
    }, { oldPass: password, shortPass: 'short' });

    expect(updateResult.ok).toBeFalsy();
    expect(updateResult.data.reason).toContain('Password too short');
  });
});
