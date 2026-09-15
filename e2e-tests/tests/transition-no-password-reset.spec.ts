/**
 * Regression test for bean gg5s, updated for the M7 consolidation (8gqm).
 *
 * A password-less account (created via a primary IdP / bridge, no password
 * ever set) reached with a SECONDARY email must never dead-end. Originally
 * the bug was a signed-out visitor landing on a set-password screen whose
 * POST could only 401; the fix routed signed-out visitors through a mailed
 * code. Since 8gqm the classic stage_reset lane is retired, so the mailed
 * code IS the unified sign-in-code screen: choose a password up front,
 * confirm with the emailed code (stage/complete_signin_code).
 *
 * The discrimination that remains: a session that OWNS the address proves
 * control by itself and keeps the direct set-password screen (iudv); anyone
 * else gets the code screen.
 *
 * WHY STUBBED: `transition_no_password` requires a genuine password-less
 * account, which only real primary/bridge ceremonies create (the mock IdP's
 * assertions can't verify). So we drive the REAL dialog and stub only
 * address_info — the routing input under test. Since M7 the server only
 * discloses `state` to an owning session, so the stub also represents that
 * precondition; session_context / list_emails decide which branch runs.
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

test.describe('transition_no_password routing (gg5s / 8gqm)', () => {
  test('non-owning visitor lands on the sign-in-code screen, not set-password', async ({ page }) => {
    // Secondary email on an unregistered (non-primary) domain.
    const email = `nopass-${Date.now()}@secondary-example.test`;

    await stubTransitionNoPassword(page, email);

    // No session cookie -> session_context (left real) reports unauthenticated,
    // so the session cannot prove control of the address.
    await page.goto(`${BASE_URL}/dialog/dialog.html?origin=http://example.com`);
    await expect(page.locator('#email-screen')).toBeVisible();

    await page.fill('#email', email);
    await page.click('#email-form button[type="submit"]');

    // The unified code screen — password chosen up front, code to confirm.
    await expect(page.locator('#create-screen')).toHaveClass(/active/, { timeout: 10000 });

    // The regression guard: the dead-end set-password screen must NOT show.
    await expect(page.locator('#set-password-screen')).not.toHaveClass(/active/);
  });

  /**
   * Contrast case that pins WHY the routing discriminates: a session that
   * OWNS the address is itself the proof of control, so it keeps the direct
   * set-password screen (no mailed code, browserid-ng-iudv).
   */
  test('a session owning the address keeps the direct set-password screen', async ({ page }) => {
    const email = `nopass-own-${Date.now()}@secondary-example.test`;

    await stubTransitionNoPassword(page, email);

    // Report the visitor as authenticated on a session that PROVED the
    // address but is not admitted (bean 160l: no registry login key bound),
    // the state a bridge sign-in leaves before the add-a-device step. The
    // roster is not this session's to read — it must not be asked for.
    await page.route('**/wsapi/session_context', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ authenticated: true, user_id: 1, admitted: false, proved_emails: [email] }),
      });
    });
    let rosterAsked = false;
    await page.route('**/wsapi/list_emails', (route) => {
      rosterAsked = true;
      route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ success: false, reason: 'not_admitted' }),
      });
    });

    await page.goto(`${BASE_URL}/dialog/dialog.html?origin=http://example.com`);

    // A live issuer session the registry has not admitted opens on the
    // email entry, not the account's address list (Dan, 2026-09-15); naming
    // the proved address is the session-owned flow.
    await page.waitForSelector('#email-screen.active', { timeout: 10000 });
    expect(rosterAsked).toBe(false);
    await page.fill('#email', email);
    await page.click('#email-form button[type="submit"]');

    // The session proves control — direct first-password screen, no code.
    await expect(page.locator('#set-password-screen')).toHaveClass(/active/, { timeout: 10000 });
  });

  test('an admitted session opens on the account address list', async ({ page }) => {
    const email = 'admitted-owner@example.com';
    const sibling = 'sibling@example.com';
    await stubTransitionNoPassword(page, email);
    // The registry admitted this browser: the session is bound to its
    // login key, so the roster is its to see (bean 160l).
    await page.route('**/wsapi/session_context', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ authenticated: true, user_id: 1, admitted: true, account: 'acct_1', proved_emails: [email] }),
      });
    });
    await page.route('**/wsapi/list_emails', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, emails: [email, sibling], derived: [], agents: [], public_names: [], managed: [], proofs: [], has_password: false }),
      });
    });

    await page.goto(`${BASE_URL}/dialog/dialog.html?origin=http://example.com`);
    await page.waitForSelector('#pick-email-screen.active', { timeout: 10000 });
    await expect(page.locator('#pick-email-screen')).toContainText(email);
    await expect(page.locator('#pick-email-screen')).toContainText(sibling);
  });
});
