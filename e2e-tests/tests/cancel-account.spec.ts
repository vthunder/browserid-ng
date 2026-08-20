/**
 * Cancel Account E2E Tests
 *
 * Adapted from browserid/automation-tests/tests/cancel-account.js
 *
 * Tests account cancellation functionality. Since we don't have an
 * account management UI in the dialog, we test via API.
 */

import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

test.describe('Cancel Account Flow', () => {
  test('can cancel account via API after signing in', async ({ dialogPage, request, page }) => {
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
      data: { email: testEmail, token: pending.code },
    });

    // Sign in through dialog
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, password);
    await dialogPage.waitForSuccess();

    // Cancel account via API
    const cancelResult = await page.evaluate(async ({ email, pass }) => {
      const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) => r.json());
      const response = await fetch('/wsapi/account_cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, pass, csrf: sc.csrf_token }),
      });
      return response.json();
    }, { email: testEmail, pass: password });

    expect(cancelResult.success).toBeTruthy();
  });

  test('session is invalidated after account cancellation', async ({ dialogPage, request, page }) => {
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
      data: { email: testEmail, token: pending.code },
    });

    // Sign in
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, password);
    await dialogPage.waitForSuccess();

    // Cancel account
    await page.evaluate(async ({ email, pass }) => {
      const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) => r.json());
      await fetch('/wsapi/account_cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, pass, csrf: sc.csrf_token }),
      });
    }, { email: testEmail, pass: password });

    // Check session is no longer authenticated
    const sessionResult = await page.evaluate(async () => {
      const response = await fetch('/wsapi/session_context', { credentials: 'include' });
      return response.json();
    });

    expect(sessionResult.authenticated).toBeFalsy();
  });

  test('email becomes unknown after account cancellation', async ({ dialogPage, request, page, context }) => {
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
      data: { email: testEmail, token: pending.code },
    });

    // Sign in and cancel
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, password);
    await dialogPage.waitForSuccess();

    await page.evaluate(async ({ email, pass }) => {
      const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) => r.json());
      await fetch('/wsapi/account_cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, pass, csrf: sc.csrf_token }),
      });
    }, { email: testEmail, pass: password });

    // Try to use the email again. Since audit M7 the cold dialog shows the
    // SAME optimistic password screen for unknown and existing addresses (no
    // enumeration) — the code hatch is how the now-unknown address re-signs
    // up.
    const newPage = await context.newPage();
    await newPage.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
    await newPage.waitForSelector('#email-screen.active');

    await newPage.fill('#email', testEmail);
    await newPage.click('#email-form button[type="submit"]');

    await newPage.waitForSelector('#password-screen.active');
    await newPage.click('#email-code-link');
    await newPage.waitForSelector('#create-screen.active');
    await expect(newPage.locator('#create-password')).toBeVisible();

    await newPage.close();
  });

  test('wrong password is rejected for account cancellation', async ({ dialogPage, request, page }) => {
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
      data: { email: testEmail, token: pending.code },
    });

    // Sign in
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(testEmail, password);
    await dialogPage.waitForSuccess();

    // Try to cancel with wrong password
    const cancelResult = await page.evaluate(async (email) => {
      const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) => r.json());
      const response = await fetch('/wsapi/account_cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, pass: 'WrongPassword!', csrf: sc.csrf_token }),
      });
      return { ok: response.ok, data: await response.json() };
    }, testEmail);

    expect(cancelResult.ok).toBeFalsy();
    expect(cancelResult.data.reason).toContain('Invalid');
  });

  test('account cancellation requires authentication', async ({ request }) => {
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Try to cancel without being logged in
    const cancelResponse = await request.post(`${baseUrl}/wsapi/account_cancel`, {
      data: { email: 'test@example.com', pass: 'SomePassword!' },
    });

    expect(cancelResponse.ok()).toBeFalsy();
    const body = await cancelResponse.json();
    expect(body.reason).toContain('Not authenticated');
  });
});
