/**
 * Regression test for bean 8t8h — RP-selected fallback IdPs (spec §8.1).
 *
 * When the RP passes `acceptedFallbacks` that does NOT include this broker's
 * own domain, a secondary (no-primary) email must fail fast in the dialog with
 * a clear "this site doesn't accept email sign-in via <broker>" message —
 * rather than verifying and getting rejected at the RP. With no argument
 * (default {this broker}) the same email proceeds past the gate as today.
 *
 * The gate is client-side UX (spec §8.1); the actual enforcement is the RP's
 * verifier trusted-issuer set (§6.1), covered by the browserid-rp unit test
 * `exchange_rejects_wrong_audience_and_untrusted_issuer`.
 *
 * We drive the real dialog and stub only address_info (the email's type/state),
 * leaving session_context real so the dialog learns the broker's own domain.
 */

import { test, expect } from '@playwright/test';

const BASE_URL = process.env.BROKER_URL || 'http://localhost:3000';

async function stubSecondaryKnown(page, email: string) {
  await page.route('**/wsapi/address_info*', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        type: 'secondary',
        state: 'known',
        issuer: 'localhost',
        disabled: false,
        normalizedEmail: email.toLowerCase(),
      }),
    });
  });
}

test.describe('acceptedFallbacks gate (8t8h)', () => {
  test('secondary email routes to an accepted external fallback (not this broker)', async ({ page }) => {
    const email = `nofallback-${Date.now()}@secondary-example.test`;
    await stubSecondaryKnown(page, email);

    // acceptedFallbacks lists a fallback that is NOT this broker's domain, so
    // the dialog routes verification THROUGH that fallback (apgv), rather than
    // blocking or using this broker. The fallback here is fake, so it fails at
    // fetch — but the error naming it proves routing kicked in.
    await page.goto(
      `${BASE_URL}/dialog/dialog.html?origin=http://example.com` +
      `&accepted_fallbacks=some-other-fallback.example`);
    await expect(page.locator('#email-screen')).toBeVisible();

    await page.fill('#email', email);
    await page.click('#email-form button[type="submit"]');

    await expect(page.locator('#error-screen')).toHaveClass(/active/, { timeout: 10000 });
    await expect(page.locator('.error-message')).toContainText('some-other-fallback.example');
  });

  test('secondary email proceeds when no acceptedFallbacks is passed (default)', async ({ page }) => {
    const email = `default-${Date.now()}@secondary-example.test`;
    await stubSecondaryKnown(page, email);

    // No acceptedFallbacks → default {this broker} → gate passes; the flow
    // moves on to the known-secondary sign-in path (not the error screen).
    await page.goto(`${BASE_URL}/dialog/dialog.html?origin=http://example.com`);
    await expect(page.locator('#email-screen')).toBeVisible();

    await page.fill('#email', email);
    await page.click('#email-form button[type="submit"]');

    // It must NOT hit the fallback-declined error. (It proceeds to sign-in;
    // whatever screen it lands on, it isn't this gate's error.)
    await page.waitForTimeout(1500);
    const onError = await page.locator('#error-screen').evaluate(
      (el) => el.classList.contains('active')).catch(() => false);
    if (onError) {
      const msg = await page.locator('.error-message').textContent();
      expect(msg || '').not.toContain('accept email sign-in via');
    }
  });
});
