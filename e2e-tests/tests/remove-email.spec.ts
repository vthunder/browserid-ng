/**
 * Remove Email E2E Tests
 *
 * Adapted from browserid/automation-tests/tests/remove-email.js
 *
 * Tests email removal functionality. The original test used the account
 * management UI with primary IdP; we test via API for secondary emails.
 */

import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

test.describe('Remove Email Flow', () => {
  test('can add and list multiple emails', async ({ dialogPage, request, page }) => {
    const primaryEmail = generateTestEmail();
    const secondaryEmail = generateTestEmail();
    const password = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user with primary email
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: primaryEmail, pass: password },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(primaryEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(primaryEmail, password);
    await dialogPage.waitForSuccess();

    // Add secondary email via API
    const stageEmailResult = await page.evaluate(async (email) => {
      const response = await fetch('/wsapi/stage_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      });
      return response.json();
    }, secondaryEmail);
    expect(stageEmailResult.success).toBeTruthy();

    // Get verification code and complete
    const emailPendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(secondaryEmail)}&type=add_email`
    );
    const emailPending = await emailPendingResponse.json();
    expect(emailPending.success).toBeTruthy();

    const completeResult = await page.evaluate(async (token) => {
      const response = await fetch('/wsapi/complete_email_addition', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token }),
      });
      return response.json();
    }, emailPending.code);
    expect(completeResult.success).toBeTruthy();

    // List emails - should have both
    const listResult = await page.evaluate(async () => {
      const response = await fetch('/wsapi/list_emails', { credentials: 'include' });
      return response.json();
    });

    expect(listResult.success).toBeTruthy();
    const emailAddresses = listResult.emails.map((e: { email: string }) => e.email);
    expect(emailAddresses).toContain(primaryEmail);
    expect(emailAddresses).toContain(secondaryEmail);
  });

  test('can remove secondary email via API', async ({ dialogPage, request, page }) => {
    const primaryEmail = generateTestEmail();
    const secondaryEmail = generateTestEmail();
    const password = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: primaryEmail, pass: password },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(primaryEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(primaryEmail, password);
    await dialogPage.waitForSuccess();

    // Add secondary email
    await page.evaluate(async (email) => {
      await fetch('/wsapi/stage_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      });
    }, secondaryEmail);

    const emailPendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(secondaryEmail)}&type=add_email`
    );
    const emailPending = await emailPendingResponse.json();

    await page.evaluate(async (token) => {
      await fetch('/wsapi/complete_email_addition', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token }),
      });
    }, emailPending.code);

    // Remove secondary email
    const removeResult = await page.evaluate(async (email) => {
      const response = await fetch('/wsapi/remove_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      });
      return response.json();
    }, secondaryEmail);

    expect(removeResult.success).toBeTruthy();

    // Verify email is removed from list
    const listResult = await page.evaluate(async () => {
      const response = await fetch('/wsapi/list_emails', { credentials: 'include' });
      return response.json();
    });

    const emailAddresses = listResult.emails.map((e: { email: string }) => e.email);
    expect(emailAddresses).toContain(primaryEmail);
    expect(emailAddresses).not.toContain(secondaryEmail);
  });

  test('cannot remove last email', async ({ dialogPage, request, page }) => {
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

    // Try to remove the only email
    const removeResult = await page.evaluate(async (email) => {
      const response = await fetch('/wsapi/remove_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      });
      return { ok: response.ok, data: await response.json() };
    }, testEmail);

    expect(removeResult.ok).toBeFalsy();
    // Internal errors return generic message for security
    expect(removeResult.data.reason).toContain('Internal server error');
  });

  test('removed email becomes unknown', async ({ dialogPage, request, page, context }) => {
    const primaryEmail = generateTestEmail();
    const secondaryEmail = generateTestEmail();
    const password = generateTestPassword();
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Create user with two emails
    const stageResponse = await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: primaryEmail, pass: password },
    });
    expect(stageResponse.ok()).toBeTruthy();

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(primaryEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();
    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in
    await dialogPage.goto('http://example.com');
    await dialogPage.signInExistingUser(primaryEmail, password);
    await dialogPage.waitForSuccess();

    // Add secondary email
    await page.evaluate(async (email) => {
      await fetch('/wsapi/stage_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      });
    }, secondaryEmail);

    const emailPendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(secondaryEmail)}&type=add_email`
    );
    const emailPending = await emailPendingResponse.json();

    await page.evaluate(async (token) => {
      await fetch('/wsapi/complete_email_addition', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token }),
      });
    }, emailPending.code);

    // Remove secondary email
    await page.evaluate(async (email) => {
      await fetch('/wsapi/remove_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      });
    }, secondaryEmail);

    // Logout
    await page.evaluate(async () => {
      await fetch('/wsapi/logout', { method: 'POST', credentials: 'include' });
    });

    // Try to use the removed email - should show create screen (unknown email)
    const newPage = await context.newPage();
    await newPage.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
    await newPage.waitForSelector('#email-screen.active');

    await newPage.fill('#email', secondaryEmail);
    await newPage.click('#email-form button[type="submit"]');

    // Should show create screen (new user), not password screen
    await newPage.waitForSelector('#create-screen.active');
    await expect(newPage.locator('#create-password')).toBeVisible();

    await newPage.close();
  });

  test('email removal requires authentication', async ({ request }) => {
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

    // Try to remove email without being logged in
    const removeResponse = await request.post(`${baseUrl}/wsapi/remove_email`, {
      data: { email: 'test@example.com' },
    });

    expect(removeResponse.ok()).toBeFalsy();
    const body = await removeResponse.json();
    expect(body.reason).toContain('Not authenticated');
  });
});
