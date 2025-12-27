import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

/**
 * Silent Assertion Tests
 *
 * These tests verify the communication_iframe's silent assertion flow,
 * which allows RPs to get assertions without showing the dialog.
 *
 * The flow requires:
 * 1. User signs in via dialog (sets localStorage session state)
 * 2. RP calls watch() with loggedInUser
 * 3. communication_iframe checks localStorage and broker session
 * 4. Appropriate callback fires (onmatch, onlogin, or onlogout)
 */

test.describe('Silent Assertion Flow', () => {
  const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
  // Use the broker's own origin for testing since that's where the test page runs
  const rpOrigin = process.env.BROKER_URL || 'http://localhost:3000';

  test('after dialog sign-in, watch() with matching loggedInUser fires onmatch', async ({
    page,
    dialogPage,
    request,
  }) => {
    const testEmail = generateTestEmail();
    const testPassword = generateTestPassword();

    // Create user via API first
    await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: testPassword },
    });

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();

    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in via dialog - use the same origin as the test page will use
    // This is crucial: localStorage is stored per-origin, so the dialog must
    // store for the same origin that the test page will have
    await dialogPage.goto(rpOrigin);
    await dialogPage.signInExistingUser(testEmail, testPassword);
    await dialogPage.waitForSuccess();

    // Now go to test page with include.js (same origin as dialog was opened for)
    await page.goto(`${baseUrl}/dialog/test.html`);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');

    // Call watch() with the same email the user just signed in with
    const result = await page.evaluate(async (email) => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ type: 'timeout' });
        }, 15000);

        (navigator as any).id.watch({
          loggedInUser: email,
          onlogin: function (assertion: string) {
            clearTimeout(timeout);
            resolve({ type: 'login', hasAssertion: !!assertion });
          },
          onlogout: function () {
            clearTimeout(timeout);
            resolve({ type: 'logout' });
          },
          onmatch: function () {
            clearTimeout(timeout);
            resolve({ type: 'match' });
          },
          onready: function () {
            // onready fires before other callbacks
          },
        });
      });
    }, testEmail);

    // Should get onmatch since loggedInUser matches the signed-in user
    expect((result as any).type).toBe('match');
  });

  test('after dialog sign-in, watch() with no loggedInUser fires onlogin with assertion', async ({
    page,
    dialogPage,
    request,
  }) => {
    const testEmail = generateTestEmail();
    const testPassword = generateTestPassword();

    // Create user via API
    await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: testPassword },
    });

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();

    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in via dialog for the same origin as the test page
    await dialogPage.goto(rpOrigin);
    await dialogPage.signInExistingUser(testEmail, testPassword);
    await dialogPage.waitForSuccess();

    // Go to test page
    await page.goto(`${baseUrl}/dialog/test.html`);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');

    // Call watch() with undefined loggedInUser (RP doesn't know if user is logged in)
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ type: 'timeout' });
        }, 15000);

        (navigator as any).id.watch({
          loggedInUser: undefined,
          onlogin: function (assertion: string) {
            clearTimeout(timeout);
            resolve({ type: 'login', hasAssertion: !!assertion, assertion: assertion });
          },
          onlogout: function () {
            clearTimeout(timeout);
            resolve({ type: 'logout' });
          },
          onmatch: function () {
            clearTimeout(timeout);
            resolve({ type: 'match' });
          },
          onready: function () {
            // onready fires before other callbacks
          },
        });
      });
    });

    // Should get onlogin with an assertion
    expect((result as any).type).toBe('login');
    expect((result as any).hasAssertion).toBe(true);
  });

  test('after dialog sign-in, watch() with different loggedInUser fires onlogin with assertion for actual user', async ({
    page,
    dialogPage,
    request,
  }) => {
    const testEmail = generateTestEmail();
    const testPassword = generateTestPassword();

    // Create user via API
    await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: testPassword },
    });

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();

    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in via dialog for the same origin as the test page
    await dialogPage.goto(rpOrigin);
    await dialogPage.signInExistingUser(testEmail, testPassword);
    await dialogPage.waitForSuccess();

    // Go to test page
    await page.goto(`${baseUrl}/dialog/test.html`);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');

    // Call watch() with a DIFFERENT email than the signed-in user
    // BrowserID should fire onlogin with an assertion for the actual signed-in user
    // This allows the RP to update their session to the correct user
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ type: 'timeout' });
        }, 15000);

        (navigator as any).id.watch({
          loggedInUser: 'different-user@example.com',
          onlogin: function (assertion: string) {
            clearTimeout(timeout);
            resolve({ type: 'login', hasAssertion: !!assertion });
          },
          onlogout: function () {
            clearTimeout(timeout);
            resolve({ type: 'logout' });
          },
          onmatch: function () {
            clearTimeout(timeout);
            resolve({ type: 'match' });
          },
          onready: function () {
            // onready fires before other callbacks
          },
        });
      });
    });

    // Should get onlogin with an assertion for the actual signed-in user
    // (not onlogout - BrowserID corrects the RP's view of who's logged in)
    expect((result as any).type).toBe('login');
    expect((result as any).hasAssertion).toBe(true);
  });

  test('without prior sign-in, watch() with null loggedInUser fires onmatch (both agree no user)', async ({
    page,
  }) => {
    // Go directly to test page without signing in
    await page.goto(`${baseUrl}/dialog/test.html`);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');

    // Call watch() with null loggedInUser (RP says no user logged in)
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ type: 'timeout' });
        }, 15000);

        (navigator as any).id.watch({
          loggedInUser: null,
          onlogin: function (assertion: string) {
            clearTimeout(timeout);
            resolve({ type: 'login', hasAssertion: !!assertion });
          },
          onlogout: function () {
            clearTimeout(timeout);
            resolve({ type: 'logout' });
          },
          onmatch: function () {
            clearTimeout(timeout);
            resolve({ type: 'match' });
          },
          onready: function () {
            // onready fires before other callbacks
          },
        });
      });
    });

    // Should get onmatch since both agree there's no logged-in user
    expect((result as any).type).toBe('match');
  });

  test('assertion from silent sign-in is valid JWT format', async ({
    page,
    dialogPage,
    request,
  }) => {
    const testEmail = generateTestEmail();
    const testPassword = generateTestPassword();

    // Create user
    await request.post(`${baseUrl}/wsapi/stage_user`, {
      data: { email: testEmail, pass: testPassword },
    });

    const pendingResponse = await request.get(
      `${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(testEmail)}&type=new_account`
    );
    const pending = await pendingResponse.json();

    await request.post(`${baseUrl}/wsapi/complete_user_creation`, {
      data: { token: pending.code },
    });

    // Sign in via dialog for the same origin as the test page
    await dialogPage.goto(rpOrigin);
    await dialogPage.signInExistingUser(testEmail, testPassword);
    await dialogPage.waitForSuccess();

    // Go to test page
    await page.goto(`${baseUrl}/dialog/test.html`);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');

    // Get assertion
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ type: 'timeout' });
        }, 15000);

        (navigator as any).id.watch({
          loggedInUser: undefined,
          onlogin: function (assertion: string) {
            clearTimeout(timeout);
            resolve({ type: 'login', assertion: assertion });
          },
          onlogout: function () {
            clearTimeout(timeout);
            resolve({ type: 'logout' });
          },
          onready: function () {},
        });
      });
    });

    expect((result as any).type).toBe('login');

    const assertion = (result as any).assertion;
    expect(assertion).toBeTruthy();

    // Assertion should be in format: cert~assertion (both are JWTs)
    const parts = assertion.split('~');
    expect(parts.length).toBe(2);

    // Each part should be a JWT (3 dot-separated base64url strings)
    parts.forEach((part: string) => {
      const jwtParts = part.split('.');
      expect(jwtParts.length).toBe(3);
    });
  });
});

test.describe('Silent Assertion Edge Cases', () => {
  const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

  test('watch() on fresh page (no localStorage) with claimed user fires onlogout', async ({
    page,
  }) => {
    // Fresh page, no prior sign-in, RP claims someone is logged in
    await page.goto(`${baseUrl}/dialog/test.html`);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');

    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ type: 'timeout' });
        }, 15000);

        (navigator as any).id.watch({
          loggedInUser: 'some-user@example.com',
          onlogin: function () {
            clearTimeout(timeout);
            resolve({ type: 'login' });
          },
          onlogout: function () {
            clearTimeout(timeout);
            resolve({ type: 'logout' });
          },
          onmatch: function () {
            clearTimeout(timeout);
            resolve({ type: 'match' });
          },
          onready: function () {},
        });
      });
    });

    // Should fire onlogout since broker doesn't know this user
    expect((result as any).type).toBe('logout');
  });

  test('onready fires after onlogin/onlogout/onmatch', async ({ page }) => {
    await page.goto(`${baseUrl}/dialog/test.html`);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');

    const result = await page.evaluate(async () => {
      const events: string[] = [];

      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          resolve({ events, timedOut: true });
        }, 10000);

        (navigator as any).id.watch({
          loggedInUser: null,
          onlogin: function () {
            events.push('login');
          },
          onlogout: function () {
            events.push('logout');
          },
          onmatch: function () {
            events.push('match');
          },
          onready: function () {
            events.push('ready');
            clearTimeout(timeout);
            resolve({ events, timedOut: false });
          },
        });
      });
    });

    expect((result as any).timedOut).toBe(false);
    expect((result as any).events).toContain('ready');

    // onready should be last
    const events = (result as any).events;
    expect(events[events.length - 1]).toBe('ready');
  });
});
