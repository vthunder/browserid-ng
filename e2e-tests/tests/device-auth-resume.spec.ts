/**
 * Device-authorization resume handback.
 *
 * A primary IdP whose device-authorization page must run a TOP-LEVEL OAuth
 * redirect (the atproto bsky-handle IdP) loses `window.opener` on the way
 * back, so it cannot postMessage the certs to the dialog. It instead sends the
 * popup it owns to /dialog/dialog.html?resume=device_auth with the certs in
 * the fragment. That page is same-origin with the still-open dialog window
 * that generated the keys, so it hands the result over a BroadcastChannel and
 * closes; the dialog completes on its normal path.
 *
 * These tests cover the resumed page's half of that choreography (the half
 * that is new): it must offer the result, and it must still report lost state
 * when nobody is waiting — the pre-existing redirect-mode behavior.
 */

import { test, expect } from '@playwright/test';

const CHANNEL = 'browserid:device_auth_resume';
const RESUME = '/dialog/dialog.html?resume=device_auth';
const FRAG = '#device_cert=dev.cert.sig&config_cert=cfg.cert.sig';

test.describe('device-auth resume handback', () => {
  test('reports lost state when no dialog window is waiting', async ({ page }) => {
    await page.goto(RESUME + FRAG);
    // The grace window is 2.5s; allow for it before the error appears.
    await expect(page.locator('#error-screen.active')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#error-screen')).toContainText('Sign-in state was lost');
  });

  test('offers the certs on the channel and closes once acknowledged', async ({ context }) => {
    // Stand in for the dialog window that is still waiting in
    // primaryPopupFlow: same origin, listening on the handoff channel.
    const listener = await context.newPage();
    await listener.goto('/dialog/dialog.html?origin=http://example.com');
    await listener.evaluate((channel) => {
      const w = window as any;
      w.__received = null;
      const chan = new BroadcastChannel(channel);
      chan.onmessage = (ev: MessageEvent) => {
        const m = ev.data;
        if (!m || m.type !== 'browserid:device_auth_resume') return;
        if (w.__received) return;
        w.__received = m.payload;
        chan.postMessage({ type: 'browserid:device_auth_resume_ack', nonce: m.nonce });
      };
    }, CHANNEL);

    const resumed = await context.newPage();
    await resumed.goto(RESUME + FRAG);

    await expect
      .poll(() => listener.evaluate(() => (window as any).__received), { timeout: 10000 })
      .toEqual({
        type: 'browserid:device_certs',
        device_cert: 'dev.cert.sig',
        config_cert: 'cfg.cert.sig'
      });

    // Acknowledged: the resumed page stops, and never claims lost state.
    // (A page opened by Playwright rather than by script may refuse
    // window.close(), so assert on the absence of the error, not on closure.)
    await resumed.waitForTimeout(4000);
    if (!resumed.isClosed()) {
      await expect(resumed.locator('#error-screen.active')).toHaveCount(0);
    }
  });

  test('hands an IdP error across the same channel', async ({ context }) => {
    const listener = await context.newPage();
    await listener.goto('/dialog/dialog.html?origin=http://example.com');
    await listener.evaluate((channel) => {
      const w = window as any;
      w.__received = null;
      const chan = new BroadcastChannel(channel);
      chan.onmessage = (ev: MessageEvent) => {
        const m = ev.data;
        if (!m || m.type !== 'browserid:device_auth_resume') return;
        if (w.__received) return;
        w.__received = m.payload;
        chan.postMessage({ type: 'browserid:device_auth_resume_ack', nonce: m.nonce });
      };
    }, CHANNEL);

    const resumed = await context.newPage();
    await resumed.goto(RESUME + '#device_error=' + encodeURIComponent('refused') +
      '&device_pubkey=somekey');

    await expect
      .poll(() => listener.evaluate(() => (window as any).__received), { timeout: 10000 })
      .toEqual({ type: 'browserid:device_error', reason: 'refused', device_pubkey: 'somekey' });
  });
});

/**
 * Two sign-ins in flight in ONE browser. A BroadcastChannel message reaches
 * every dialog window on the origin, so each waiting window must pair the
 * broadcast against the device key IT generated and ignore everything else.
 * Without that, one flow's result resolves or tears down the other's.
 */
test.describe('device-auth resume handback: concurrent dialog windows', () => {
  const b64url = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // A structurally valid JWS whose payload certifies `pubX`. Never verified
  // here — the dialog only decodes the claims to pair the handback, and the
  // flow dies on the next real step either way, which is what we assert.
  const certFor = (pubX: string) =>
    b64url({ alg: 'EdDSA', typ: 'JWT' }) + '.' +
    b64url({
      typ: 'browserid-device-cert', iss: 'idp.example', iat: 0, exp: 9999999999,
      purpose: 'device', holder: 'h', identities: ['a@idp.example'],
      'public-key': { algorithm: 'Ed25519', publicKey: pubX }
    }) + '.sig';

  /**
   * Drive a real dialog window into primaryPopupFlow: stub address_info so the
   * email looks like a primary with a device-authorization page, point that
   * page at an inert stub, and return the window plus the device pubkey it
   * actually generated (read back out of the popup's own URL fragment).
   */
  // A stub IdP on an origin of its own (the dialog needs an absolute
  // device_auth URL, and a distinct origin keeps the postMessage checks honest).
  const STUB_IDP = 'http://127.0.0.1:3000/e2e-stub-idp.html';

  async function openWaitingDialog(context: any, email: string) {
    const page = await context.newPage();
    await page.route('**/wsapi/address_info*', (route: any) =>
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          type: 'primary', state: 'known',
          device_auth: STUB_IDP,
          access_mint: 'http://127.0.0.1:3000/e2e-stub-mint'
        })
      }));
    await context.route('**/e2e-stub-idp.html*', (route: any) =>
      route.fulfill({ contentType: 'text/html', body: '<title>stub idp</title>' }));

    await page.goto('/dialog/dialog.html?origin=http://example.com');
    await page.waitForSelector('#email-screen.active');
    const popupPromise = page.waitForEvent('popup');
    await page.fill('#email', email);
    await page.click('#email-form button[type="submit"]');
    const popup = await popupPromise;
    // The dialog puts the freshly generated pubkeys in the popup's fragment.
    const pubX = new URLSearchParams(new URL(popup.url()).hash.slice(1)).get('device_pubkey')!;
    expect(pubX).toBeTruthy();
    await expect(page.locator('#loading.active')).toBeVisible();
    return { page, popup, pubX };
  }

  const stillWaiting = (p: any) => p.locator('#loading.active').isVisible();

  test('a certs broadcast resolves only the window whose key it certifies', async ({ context }) => {
    const a = await openWaitingDialog(context, 'alice@idp.example');
    const b = await openWaitingDialog(context, 'bob@idp.example');
    expect(a.pubX).not.toEqual(b.pubX);

    // Real resumed page, real handoffResume — certs certifying A's key only.
    const resumed = await context.newPage();
    await resumed.goto(RESUME + '#device_cert=' + certFor(a.pubX) + '&config_cert=' + certFor(a.pubX));

    // A consumes them and then fails on the next step (the certs are not
    // signed by anything) — the point is that it left the waiting state.
    await expect(a.page.locator('#error-screen.active')).toBeVisible({ timeout: 15000 });
    // B never saw a result of its own and must still be waiting.
    expect(await stillWaiting(b.page)).toBe(true);
    expect(b.popup.isClosed()).toBe(false);
  });

  test('a cert declaring no public key pairs with nobody', async ({ context }) => {
    const a = await openWaitingDialog(context, 'alice@idp.example');
    const b = await openWaitingDialog(context, 'bob@idp.example');

    // The `public-key` claim is advisory, so a cert can legitimately omit it —
    // but then the handoff has no way to tell whose it is. Accepting it would
    // resolve BOTH windows on the same certs, and each would persist a pair
    // whose cert does not match its own key: a login broken until expiry.
    const noKey = b64url({ alg: 'EdDSA', typ: 'JWT' }) + '.' +
      b64url({ typ: 'browserid-device-cert', iss: 'idp.example', exp: 9999999999 }) + '.sig';
    const resumed = await context.newPage();
    await resumed.goto(RESUME + '#device_cert=' + noKey + '&config_cert=' + noKey);

    // Nobody claims it, so the resumed page falls back to the lost-state error.
    await expect(resumed.locator('#error-screen.active')).toBeVisible({ timeout: 10000 });
    expect(await stillWaiting(a.page)).toBe(true);
    expect(await stillWaiting(b.page)).toBe(true);
  });

  test('an error broadcast tears down only the matching window', async ({ context }) => {
    const a = await openWaitingDialog(context, 'alice@idp.example');
    const b = await openWaitingDialog(context, 'bob@idp.example');

    const resumed = await context.newPage();
    await resumed.goto(RESUME + '#device_error=' + encodeURIComponent('handle refused') +
      '&device_pubkey=' + encodeURIComponent(a.pubX));

    await expect(a.page.locator('#error-screen.active')).toContainText('handle refused', { timeout: 15000 });
    expect(await stillWaiting(b.page)).toBe(true);
    expect(b.popup.isClosed()).toBe(false);
  });

  test('an unpairable error broadcast tears down nobody', async ({ context }) => {
    const a = await openWaitingDialog(context, 'alice@idp.example');

    // An IdP that sends no device_pubkey with its failure gets ignored rather
    // than allowed to close whichever window happens to be listening.
    const resumed = await context.newPage();
    await resumed.goto(RESUME + '#device_error=' + encodeURIComponent('unattributable'));

    await expect(resumed.locator('#error-screen.active')).toBeVisible({ timeout: 10000 });
    expect(await stillWaiting(a.page)).toBe(true);
  });

  /**
   * The announcement that keeps the dialog waiting through the OAuth hop. The
   * IdP page's top-level redirect takes the popup to a COOP: same-origin PDS,
   * which severs the handle and makes `popup.closed` read true — identical to
   * a user closing the window. The IdP says so first, over postMessage to the
   * opener (BroadcastChannel could not cross the origin boundary), and the
   * dialog then treats the close as expected.
   */
  test('an announced handoff survives the popup looking closed', async ({ context }) => {
    const a = await openWaitingDialog(context, 'alice@idp.example');
    const b = await openWaitingDialog(context, 'bob@idp.example');

    // Only A's key is announced.
    await a.popup.evaluate(
      ([pubX, dialogOrigin]) => window.opener.postMessage(
        { type: 'browserid:device_auth_pending', device_pubkey: pubX }, dialogOrigin),
      [a.pubX, new URL(a.page.url()).origin]
    );
    await a.popup.close();
    await b.popup.close();

    // B never heard an announcement, so its close is a real cancel.
    await expect(b.page.locator('#error-screen.active')).toContainText('closed', { timeout: 15000 });
    // A keeps waiting for the handoff that is still coming.
    expect(await stillWaiting(a.page)).toBe(true);

    // ...and when it arrives, A completes on its normal path (here: fails on
    // the unsigned certs, which is still proof the listener was alive).
    const resumed = await context.newPage();
    await resumed.goto(RESUME + '#device_cert=' + certFor(a.pubX) + '&config_cert=' + certFor(a.pubX));
    await expect(a.page.locator('#error-screen.active')).toBeVisible({ timeout: 15000 });
    await expect(a.page.locator('#error-screen')).not.toContainText('closed');
  });

  test('an announcement for another window does not suppress this one\'s close', async ({ context }) => {
    const a = await openWaitingDialog(context, 'alice@idp.example');
    const b = await openWaitingDialog(context, 'bob@idp.example');

    // A's popup announces B's key — pairing must reject it, so A's own close
    // still counts.
    await a.popup.evaluate(
      ([pubX, dialogOrigin]) => window.opener.postMessage(
        { type: 'browserid:device_auth_pending', device_pubkey: pubX }, dialogOrigin),
      [b.pubX, new URL(a.page.url()).origin]
    );
    await a.popup.close();

    await expect(a.page.locator('#error-screen.active')).toContainText('closed', { timeout: 15000 });
    expect(await stillWaiting(b.page)).toBe(true);
  });
});

/**
 * Cold-login holder repair over the resume channel (browserid-ng-i8a2).
 *
 * A cold sign-in (no broker session yet) can't tell the IdP which holder this
 * browser uses, so the IdP self-assigns one. When the account already has a
 * `browsers` namespace, that self-assigned prefix can't be adopted and the
 * broker schedules a move — the browser must re-issue under the target or it
 * stays uncategorized (and renders as an "agent").
 *
 * The repair may NOT depend on opening a window: on the OAuth lane the dialog
 * has no live IdP window, and a gesture-less `window.open` is exactly what
 * popup blockers refuse. Instead the dialog tells the resumed page — a window
 * it already owns — to navigate ITSELF back to the provider.
 */
test.describe('device-auth resume handback: holder repair', () => {
  const b64url = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const certFor = (pubX: string) =>
    b64url({ alg: 'EdDSA', typ: 'JWT' }) + '.' +
    b64url({
      typ: 'browserid-device-cert', iss: 'idp.example', iat: 0, exp: 9999999999,
      purpose: 'device', holder: 'brcold.0011223344', identities: ['a@idp.example'],
      'public-key': { algorithm: 'Ed25519', publicKey: pubX }
    }) + '.sig';
  const STUB_IDP = 'http://127.0.0.1:3000/e2e-stub-idp.html';

  async function openWaitingDialog(context: any, email: string) {
    const page = await context.newPage();
    await page.route('**/wsapi/address_info*', (route: any) =>
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          type: 'primary', state: 'known',
          device_auth: STUB_IDP,
          access_mint: 'http://127.0.0.1:3000/e2e-stub-mint'
        })
      }));
    await context.route('**/e2e-stub-idp.html*', (route: any) =>
      route.fulfill({ contentType: 'text/html', body: '<title>stub idp</title>' }));
    await page.goto('/dialog/dialog.html?origin=http://example.com');
    await page.waitForSelector('#email-screen.active');
    const popupPromise = page.waitForEvent('popup');
    await page.fill('#email', email);
    await page.click('#email-form button[type="submit"]');
    const popup = await popupPromise;
    const pubX = new URLSearchParams(new URL(popup.url()).hash.slice(1)).get('device_pubkey')!;
    expect(pubX).toBeTruthy();
    await expect(page.locator('#loading.active')).toBeVisible();
    return { page, popup, pubX };
  }

  test('sends the resumed window back to the provider with the holder pinned, opening nothing', async ({ context }) => {
    const a = await openWaitingDialog(context, 'alice@idp.example');
    // The broker reports that this cold holder has been reassigned into the
    // account's `browsers` namespace.
    await a.page.route('**/wsapi/holder_assignment*', (route: any) =>
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ success: true, status: 'moved', new_holder: 'brcanon.deadbeef01' })
      }));
    let popupsOpened = 0;
    a.page.on('popup', () => { popupsOpened++; });

    const resumed = await context.newPage();
    await resumed.goto(RESUME + '#device_cert=' + certFor(a.pubX) + '&config_cert=' + certFor(a.pubX));

    await expect.poll(() => resumed.url(), { timeout: 20000 }).toContain('e2e-stub-idp.html');
    const frag = new URLSearchParams(new URL(resumed.url()).hash.slice(1));
    expect(frag.get('holder')).toBe('brcanon.deadbeef01');
    // The SAME keys are re-certified — a repair, not a new device slot.
    expect(frag.get('device_pubkey')).toBe(a.pubX);
    expect(frag.get('return_url')).toContain('resume=device_auth');
    // The whole point: no window.open, so no popup blocker to lose to.
    expect(popupsOpened).toBe(0);
  });

  test('closes the resumed window when no repair is needed', async ({ context }) => {
    const a = await openWaitingDialog(context, 'alice@idp.example');
    // Holder is current — nothing to re-issue, so the held window is released.
    await a.page.route('**/wsapi/holder_assignment*', (route: any) =>
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ success: true, status: 'current' })
      }));
    await a.page.route('**/wsapi/browser_holder*', (route: any) =>
      route.fulfill({ contentType: 'application/json', body: JSON.stringify({ prefix: 'brcold' }) }));

    const resumed = await context.newPage();
    await resumed.goto(RESUME + '#device_cert=' + certFor(a.pubX) + '&config_cert=' + certFor(a.pubX));

    // It must not hop anywhere, and must not strand itself claiming lost state.
    // (The resumed page scrubs its own URL, so identity is "still on the
    // dialog, not at the provider".)
    await a.page.waitForTimeout(5000);
    if (!resumed.isClosed()) {
      expect(resumed.url()).not.toContain('e2e-stub-idp');
      await expect(resumed.locator('#error-screen.active')).toHaveCount(0);
    }
  });

  test('refuses a re-issue hop to an insecure URL', async ({ context }) => {
    // The channel is same-origin by construction, but the resumed window still
    // refuses to be navigated anywhere but a secure provider URL.
    const listener = await context.newPage();
    await listener.goto('/dialog/dialog.html?origin=http://example.com');
    await listener.evaluate((channel) => {
      const w = window as any;
      w.__sent = false;
      const chan = new BroadcastChannel(channel);
      chan.onmessage = (ev: MessageEvent) => {
        const m = ev.data;
        if (!m || m.type !== 'browserid:device_auth_resume' || w.__sent) return;
        w.__sent = true;
        chan.postMessage({ type: 'browserid:device_auth_resume_ack', nonce: m.nonce, hold: true });
        chan.postMessage({
          type: 'browserid:device_auth_reissue', nonce: m.nonce,
          url: 'http://evil.example/steal'
        });
      };
    }, CHANNEL);

    const resumed = await context.newPage();
    await resumed.goto(RESUME + FRAG);

    await expect.poll(() => listener.evaluate(() => (window as any).__sent), { timeout: 10000 }).toBe(true);
    await resumed.waitForTimeout(3000);
    expect(resumed.isClosed()).toBe(false);
    expect(resumed.url()).not.toContain('evil.example');
  });
});
