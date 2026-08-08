import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';
import { DialogPage } from '../pages/dialog';
import { createServer, IncomingMessage, ServerResponse } from 'http';

/**
 * watch() v2 contract (bean browserid-ng-6u70) — formerly the silent-assertion
 * suite. The hidden communication_iframe and its silent reconciliation
 * (onmatch / spontaneous onlogin / spontaneous onlogout) are GONE — third-party
 * storage partitioning killed the mechanism, and the RP-side alternatives were
 * rejected as holder-shaped. The v2 contract this file specifies:
 *
 * - No spontaneous callbacks at page load: without a user-triggered flow (or
 *   FedCM auto-reauthn, opt-in, browser-mediated) watch() fires onready only.
 * - onready = "the automatic phase has settled".
 * - logout() delivers onlogout to the calling tab AND to every other
 *   same-origin tab (BroadcastChannel/storage ping).
 * - Revocation is observable: include.js stashes the access cert's status ref
 *   at login and polls it through the broker's caching status proxy; a revoked
 *   device flips an open tab to onlogout without a reload. UX only — the RP
 *   backend enforces via /status/check.
 */

const brokerUrl = process.env.BROKER_URL || 'http://localhost:3000';

/** Minimal RP on its own origin, loading include.js from the broker. */
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
<head><title>watch() v2 RP</title></head>
<body>
  <h1>watch() v2 RP</h1>
  <button id="signin">Sign in</button>
  <script src="${brokerUrl}/include.js"></script>
  <script>
    window.__events = [];
    window.__presentation = null;
    window.__setup = function (loggedInUser) {
      navigator.id.watch({
        loggedInUser: loggedInUser,
        onlogin: function (presentation) {
          window.__events.push('login');
          window.__presentation = presentation;
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

/** Full popup sign-in through include.js on the RP page. */
async function signInViaPopup(page: any, email: string, password: string) {
  const popupPromise = page.context().waitForEvent('page');
  await page.click('#signin');
  const popup = await popupPromise;
  await popup.waitForSelector('#email-screen.active', { timeout: 15000 });
  await new DialogPage(popup).signInExistingUser(email, password);
  await page.waitForFunction(() => (window as any).__presentation !== null, undefined, {
    timeout: 20000,
  });
}

test.describe('watch() v2 contract', () => {
  let rp: RpServer;

  test.beforeAll(async () => {
    rp = new RpServer();
    await rp.start();
  });

  test.afterAll(async () => {
    await rp.stop();
  });

  test('page load with no session fires onready only — no spontaneous callbacks', async ({
    page,
  }) => {
    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(undefined));

    await page.waitForFunction(() => (window as any).__events.includes('ready'), undefined, {
      timeout: 10000,
    });
    // Give any spurious callback a beat to arrive, then assert there was none.
    await page.waitForTimeout(1000);
    const events = await page.evaluate(() => (window as any).__events);
    expect(events).toEqual(['ready']);
  });

  test('claimed loggedInUser does NOT produce a spontaneous onlogout (or anything else)', async ({
    page,
  }) => {
    // Old contract: RP claims a user, broker disagrees → silent onlogout.
    // v2: no silent reconciliation exists; the page still just gets onready.
    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup('nobody@example.com'));

    await page.waitForFunction(() => (window as any).__events.includes('ready'), undefined, {
      timeout: 10000,
    });
    await page.waitForTimeout(1000);
    const events = await page.evaluate(() => (window as any).__events);
    expect(events).toEqual(['ready']);
  });

  test('explicit sign-in delivers onlogin with a 4-part access presentation', async ({
    page,
    brokerApi,
  }) => {
    const email = generateTestEmail();
    const password = generateTestPassword();
    expect(await brokerApi.createVerifiedUser(email, password)).toBe(true);

    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(null));
    await signInViaPopup(page, email, password);

    const presentation = await page.evaluate(() => (window as any).__presentation);
    expect(presentation.split('~')).toHaveLength(4);

    // The login stashed a revocation pointer (uri+idx, no key material) for
    // the status poll.
    const ref = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('browserid_status_ref') || 'null')
    );
    expect(ref).toBeTruthy();
    expect(ref.uri).toContain('/.well-known/browserid-status');
    expect(typeof ref.idx).toBe('number');
  });

  test('logout() fires onlogout in the calling tab', async ({ page, brokerApi }) => {
    const email = generateTestEmail();
    const password = generateTestPassword();
    expect(await brokerApi.createVerifiedUser(email, password)).toBe(true);

    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(null));
    await signInViaPopup(page, email, password);

    await page.evaluate(() => (navigator as any).id.logout());
    await page.waitForFunction(() => (window as any).__events.includes('logout'), undefined, {
      timeout: 5000,
    });
    // The stashed status ref is dropped with the session.
    const ref = await page.evaluate(() => localStorage.getItem('browserid_status_ref'));
    expect(ref).toBeNull();
  });

  test('logout() propagates onlogout to another same-origin tab', async ({ page, brokerApi }) => {
    const email = generateTestEmail();
    const password = generateTestPassword();
    expect(await brokerApi.createVerifiedUser(email, password)).toBe(true);

    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(null));
    await signInViaPopup(page, email, password);

    const otherTab = await page.context().newPage();
    await otherTab.goto(rp.origin());
    await otherTab.waitForFunction(() => typeof (navigator as any).id === 'object');
    await otherTab.evaluate(() => (window as any).__setup(null));
    await otherTab.waitForFunction(() => (window as any).__events.includes('ready'), undefined, {
      timeout: 10000,
    });

    await page.evaluate(() => (navigator as any).id.logout());

    await otherTab.waitForFunction(() => (window as any).__events.includes('logout'), undefined, {
      timeout: 5000,
    });
    await otherTab.close();
  });

  test('revoking the device flips an open tab to onlogout via the status poll', async ({
    page,
    brokerApi,
  }) => {
    const email = generateTestEmail();
    const password = generateTestPassword();
    expect(await brokerApi.createVerifiedUser(email, password)).toBe(true);

    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(null));
    await signInViaPopup(page, email, password);

    // Revoke this session's device cert from a broker-origin tab (the popup's
    // session cookie lives in this browser context).
    const brokerTab = await page.context().newPage();
    await brokerTab.goto(`${brokerUrl}/dialog/test.html`);
    const revoked = await brokerTab.evaluate(async () => {
      const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) =>
        r.json()
      );
      const certs = await fetch('/wsapi/device_certs', { credentials: 'include' }).then((r) =>
        r.json()
      );
      const active = (certs.certs || []).filter((c: any) => !c.revoked);
      if (!active.length) return { ok: false, reason: 'no active device certs' };
      const results = [];
      for (const cert of active) {
        const res = await fetch('/wsapi/revoke_device_cert', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ csrf: sc.csrf_token, id: cert.id }),
        });
        results.push(res.status);
      }
      return { ok: results.every((s) => s === 200), results };
    });
    await brokerTab.close();
    expect(revoked.ok).toBe(true);

    // Reload the RP tab (localStorage ref survives), arm a fast poll, watch().
    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => {
      (window as any).BROWSERID_STATUS_POLL_MS = 250;
      (window as any).__setup('claimed@example.com');
    });

    await page.waitForFunction(() => (window as any).__events.includes('logout'), undefined, {
      timeout: 15000,
    });
    // The ref is cleared after the revocation fired, so the poll stops.
    const ref = await page.evaluate(() => localStorage.getItem('browserid_status_ref'));
    expect(ref).toBeNull();
  });
});
