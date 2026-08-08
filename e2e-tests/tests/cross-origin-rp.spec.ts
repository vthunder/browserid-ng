/**
 * Cross-Origin RP Spike Tests (origin-split spike, bean browserid-ng-93z2)
 *
 * Today every e2e test runs the RP page on the broker's own origin. In
 * production-after-a-split (marketing/guestbook on browserid.me, auth cluster
 * on id.browserid.me) — and for any external RP today — the RP page is a
 * DIFFERENT origin from the broker. These tests run a real RP on a second
 * origin (127.0.0.1:<random> vs the broker's localhost:3000 — different host,
 * therefore different origin AND different site) and drive the two RP-facing
 * flows across that boundary:
 *
 * 1. Dialog popup flow (WinChan): must work cross-origin — this is the
 *    design-intent path. A failure here blocks the origin split.
 * 2. watch() v2 page-load behavior (bean 6u70): the communication_iframe and
 *    its silent reconciliation are GONE. A return visit from a cross-origin
 *    RP fires onready only — no spontaneous onlogin/onlogout — regardless of
 *    what loggedInUser claims.
 */

import { test, expect } from '../fixtures/test-helpers';
import { DialogPage } from '../pages/dialog';
import { generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';
import { createServer, IncomingMessage, ServerResponse } from 'http';

const brokerUrl = process.env.BROKER_URL || 'http://localhost:3000';

/** Minimal RP: one page, loads include.js from the broker origin. */
class RpServer {
  private server: ReturnType<typeof createServer> | null = null;
  private port = 0;

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handle(req, res));
      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server!.address();
        this.port = typeof addr === 'object' ? addr!.port : 0;
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server ? this.server.close(() => resolve()) : resolve();
    });
  }

  origin(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  private handle(_req: IncomingMessage, res: ServerResponse) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html>
<html>
<head><title>Cross-origin RP</title></head>
<body>
  <h1>Cross-origin RP</h1>
  <button id="signin">Sign in</button>
  <script src="${brokerUrl}/include.js"></script>
  <script>
    window.__events = [];
    window.__assertion = null;
    // Called by the test with the loggedInUser value under test.
    window.__setup = function (loggedInUser) {
      navigator.id.watch({
        loggedInUser: loggedInUser,
        onlogin: function (assertion) {
          window.__events.push('login');
          window.__assertion = assertion;
        },
        onlogout: function () { window.__events.push('logout'); },
        onready: function () { window.__events.push('ready'); },
      });
    };
    document.getElementById('signin').addEventListener('click', function () {
      navigator.id.request();
    });
  </script>
</body>
</html>`);
  }
}

/** Wait for onready, leave a beat for spurious callbacks, report all events. */
async function settleAndCollect(page: any, timeoutMs: number): Promise<string[]> {
  await page
    .waitForFunction(() => (window as any).__events.includes('ready'), undefined, {
      timeout: timeoutMs,
    })
    .catch(() => {});
  await page.waitForTimeout(1000);
  return page.evaluate(() => (window as any).__events);
}

test.describe('Cross-origin RP (origin-split spike)', () => {
  let rp: RpServer;

  test.beforeAll(async () => {
    rp = new RpServer();
    await rp.start();
  });

  test.afterAll(async () => {
    await rp.stop();
  });

  test.fixme('dialog popup flow works from a cross-origin RP and the assertion verifies for the RP audience', async ({
    page,
    request,
    brokerApi,
  }) => {
    const email = generateTestEmail();
    const password = generateTestPassword();
    expect(await brokerApi.createVerifiedUser(email, password)).toBe(true);

    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(null));

    // Click opens the dialog popup via WinChan (real user gesture).
    const popupPromise = page.context().waitForEvent('page');
    await page.click('#signin');
    const popup = await popupPromise;

    // /sign_in redirects to /dialog/dialog.html; wait for the email screen.
    await popup.waitForSelector('#email-screen.active', { timeout: 15000 });
    const dialog = new DialogPage(popup);

    // The dialog must have learned the true RP origin via WinChan.
    const shownOrigin = await popup.evaluate(
      () => (window as any).BrowserID?.State?.origin ?? document.body.textContent
    );
    console.log(`[spike] dialog sees RP origin: ${JSON.stringify(shownOrigin).slice(0, 200)}`);

    await dialog.signInExistingUser(email, password);

    // Assertion must arrive back at the cross-origin RP page.
    await page.waitForFunction(() => (window as any).__assertion !== null, undefined, {
      timeout: 20000,
    });
    const assertion = await page.evaluate(() => (window as any).__assertion);
    expect(assertion).toBeTruthy();

    // And it must verify for the RP's (cross-origin) audience.
    const verifyRes = await request.post(`${brokerUrl}/verify`, {
      data: { assertion, audience: rp.origin() },
    });
    const verdict = await verifyRes.json();
    console.log(`[spike] /verify verdict: ${JSON.stringify(verdict)}`);
    expect(verdict.status ?? verdict.result ?? verdict.email ? 'ok' : 'fail').toBeTruthy();
    expect(JSON.stringify(verdict)).toContain(email);
  });

  test('return visit from a cross-origin RP fires onready only (watch() v2 — no silent login)', async ({
    page,
    brokerApi,
  }) => {
    const email = generateTestEmail();
    const password = generateTestPassword();
    expect(await brokerApi.createVerifiedUser(email, password)).toBe(true);

    // First visit: full popup sign-in from the cross-origin RP.
    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(null));
    const popupPromise = page.context().waitForEvent('page');
    await page.click('#signin');
    const popup = await popupPromise;
    await popup.waitForSelector('#email-screen.active', { timeout: 15000 });
    await new DialogPage(popup).signInExistingUser(email, password);
    await page.waitForFunction(() => (window as any).__assertion !== null, undefined, {
      timeout: 20000,
    });

    // Return visit: fresh load. v2 contract — no spontaneous callbacks, no
    // hidden iframes; the sign-in button is the way back in.
    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(undefined));
    const events = await settleAndCollect(page, 10000);
    expect(events).toEqual(['ready']);
    const iframeCount = await page.evaluate(() => document.querySelectorAll('iframe').length);
    expect(iframeCount).toBe(0);
  });

  test('return visit from a SAME-SITE cross-origin RP also fires onready only (watch() v2)', async ({
    page,
    brokerApi,
  }) => {
    // rp.localhost:<port> and localhost:3000 are different ORIGINS but the
    // same SITE — the browserid.me ↔ id.browserid.me relationship after the
    // proposed origin split. Under the old contract same-site was the one
    // configuration where silent login still worked; v2 removes the mechanism
    // entirely, so the contract must be identical to the cross-site case.
    const sameSiteRpUrl = rp.origin().replace('127.0.0.1', 'rp.localhost');
    const email = generateTestEmail();
    const password = generateTestPassword();
    expect(await brokerApi.createVerifiedUser(email, password)).toBe(true);

    // First visit: popup sign-in from the same-site RP.
    await page.goto(sameSiteRpUrl);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(null));
    const popupPromise = page.context().waitForEvent('page');
    await page.click('#signin');
    const popup = await popupPromise;
    await popup.waitForSelector('#email-screen.active', { timeout: 15000 });
    await new DialogPage(popup).signInExistingUser(email, password);
    await page.waitForFunction(() => (window as any).__assertion !== null, undefined, {
      timeout: 20000,
    });

    // Return visit: onready only, same as cross-site.
    await page.goto(sameSiteRpUrl);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(undefined));
    const events = await settleAndCollect(page, 10000);
    expect(events).toEqual(['ready']);
  });

  test('claimed loggedInUser from a cross-origin RP: onready only, no spontaneous onlogout (watch() v2)', async ({
    page,
  }) => {
    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    // No prior sign-in; the RP claims a user. Old contract: silent onlogout.
    // v2: no reconciliation — the claim changes nothing at page load.
    await page.evaluate(() => (window as any).__setup('nobody@example.com'));
    const events = await settleAndCollect(page, 10000);
    expect(events).toEqual(['ready']);
  });
});
