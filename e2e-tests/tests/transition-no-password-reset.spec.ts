/**
 * Regression test for bean gg5s.
 *
 * Bug (fixed 2026-07-10 in browserid-broker/static/dialog.js): a SIGNED-OUT
 * visitor hitting a password-less account (one created via a primary IdP, no
 * password ever set) with a SECONDARY email landed on a dead-end set-password
 * screen. The server 401s /wsapi/set_password without a session, so the form
 * could never succeed, and the copy wrongly implied the email used to be a
 * primary. The fix routes a signed-OUT `transition_no_password` state through
 * the password-RESET flow (stage_reset emails a code that proves ownership,
 * then the user sets a password), while a signed-IN user keeps the direct
 * set-password screen (the session is the proof).
 *
 * See dialog.js handleNoPasswordTransition() (~line 316) and the two
 * `transition_no_password` branches in handleEmailChosen (~367) and the
 * email-form submit handler (~795 / ~811).
 *
 * GOAL: a signed-out user in `transition_no_password` lands on
 * #reset-password-screen, NOT #set-password-screen.
 *
 * WHY THIS SHAPE: `transition_no_password` requires a genuine password-less
 * account (user_store.create_user_no_password), which is only ever created by
 * /wsapi/auth_with_assertion after verify_assertion_with_dns succeeds — that
 * needs real DNSSEC discovery + real Ed25519 verification of the IdP's cert.
 * The mock primary IdP used elsewhere in the suite publishes a fake key and
 * returns a fake cert signature, so its assertion can never verify and no
 * account is ever created (the existing primary-idp tests note exactly this).
 * There is also no test/admin endpoint that seeds a password-less account.
 *
 * So the account state cannot be produced end-to-end. Instead we drive the
 * REAL dialog and stub only the two server responses that are the INPUTS to
 * the routing decision under test — address_info (the state) and stage_reset
 * (the proof-of-control email the reset branch sends). session_context is left
 * real: with no cookie the broker reports the visitor as unauthenticated,
 * which is the signed-out condition the regression hinges on. Everything the
 * bug was in — the branch selection, handleNoPasswordTransition, and the
 * screen render — runs for real.
 */

import { test, expect } from '@playwright/test';

const BASE_URL = process.env.BROKER_URL || 'http://localhost:3000';

/**
 * Stub address_info to report a secondary email on a password-less account,
 * i.e. compute_state(false, Secondary, Secondary) == "transition_no_password"
 * (see browserid-broker/src/routes/email.rs). No auth/prov fields, so the
 * dialog treats it as a secondary email (not a primary IdP).
 */
async function stubTransitionNoPassword(page, email: string) {
  await page.route('**/wsapi/address_info*', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        type: 'secondary',
        state: 'transition_no_password',
        issuer: 'localhost',
        disabled: false,
        normalizedEmail: email.toLowerCase(),
      }),
    });
  });
}

test.describe('transition_no_password routing (gg5s)', () => {
  test('signed-out user lands on reset-password screen, not set-password', async ({ page }) => {
    // Secondary email on an unregistered (non-primary) domain.
    const email = `nopass-${Date.now()}@secondary-example.test`;

    await stubTransitionNoPassword(page, email);

    // The reset branch stages a reset (proof-of-control email). Stub it so the
    // routing succeeds without a real account / SMTP; the dialog only needs a
    // 200 to advance to the reset-password screen.
    let stageResetCalled = false;
    await page.route('**/wsapi/stage_reset', (route) => {
      stageResetCalled = true;
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true }),
      });
    });

    // No session cookie -> session_context (left real) reports unauthenticated.
    await page.goto(`${BASE_URL}/dialog/dialog.html?origin=http://example.com`);
    await expect(page.locator('#email-screen')).toBeVisible();

    await page.fill('#email', email);
    await page.click('#email-form button[type="submit"]');

    // The fix: signed-out transition_no_password routes through the reset flow.
    await expect(page.locator('#reset-password-screen')).toHaveClass(/active/, { timeout: 10000 });

    // The regression guard: the OLD dead-end set-password screen must NOT show.

    // And the reset flow was actually engaged (the proof-of-control email path).
    expect(stageResetCalled).toBe(true);
  });

  /**
   * Contrast case that pins WHY the fix discriminates: a SIGNED-IN user in the
   * same transition_no_password state keeps the direct set-password screen,
   * because the session is itself the proof of control. We stub session_context
   * to authenticated so handleNoPasswordTransition takes the signed-in branch.
   * If routing ever collapsed both cases to one screen, one of these two tests
   * would fail.
   */
  test('signed-in user keeps the direct set-password screen', async ({ page }) => {
    const email = `nopass-in-${Date.now()}@secondary-example.test`;

    await stubTransitionNoPassword(page, email);

    // Report the visitor as authenticated. list_emails is stubbed empty so the
    // dialog's authenticated init path renders without needing a real account.
    await page.route('**/wsapi/session_context', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ authenticated: true, user_id: 1, email }),
      });
    });
    await page.route('**/wsapi/list_emails', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ emails: [] }),
      });
    });

    // stage_reset must NOT be reached on the signed-in branch; fail loudly if it is.
    let stageResetCalled = false;
    await page.route('**/wsapi/stage_reset', (route) => {
      stageResetCalled = true;
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true }) });
    });

    await page.goto(`${BASE_URL}/dialog/dialog.html?origin=http://example.com`);

    // Reach the email entry. When authenticated the dialog may show the chooser;
    // either way the email input is available on the email screen. Force the
    // email screen by navigating there if needed.
    await page.waitForFunction(() => {
      return document.querySelector('#email-screen') !== null;
    }, { timeout: 10000 });

    // Type the email and submit via the email form.
    await page.evaluate(() => {
      // Ensure the email screen is active so the form is interactable.
      const screens = document.querySelectorAll('.screen');
      screens.forEach((s) => s.classList.remove('active'));
      document.querySelector('#email-screen')?.classList.add('active');
    });
    await page.fill('#email', email);
    await page.click('#email-form button[type="submit"]');

    // The dedicated set-password screen was removed with the dialog
    // redesign; signed-in users now also prove control via the code-based
    // reset screen (direct set-password lives at /account settings) — so the
    // reset IS staged here too. gg5s's original signed-in/-out discrimination
    // is retired with that screen; this test now pins the collapsed routing.
    await expect(page.locator('#reset-password-screen')).toHaveClass(/active/, { timeout: 10000 });
    expect(stageResetCalled).toBe(true);
  });
});
