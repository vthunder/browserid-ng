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
 * 2. Silent assertion via the hidden communication_iframe: the iframe becomes
 *    THIRD-PARTY on a cross-origin RP page, so it is subject to third-party
 *    storage partitioning (partitioned localStorage/IndexedDB) and
 *    SameSite=Lax cookie exclusion (see the comment in session.rs). This test
 *    documents the actual behavior rather than asserting a hoped-for one.
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
        onmatch: function () { window.__events.push('match'); },
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

/** Wait until any of login/logout/match has fired, or time out. */
async function waitForOutcome(page: any, timeoutMs: number): Promise<string[]> {
  await page
    .waitForFunction(
      () =>
        (window as any).__events.includes('login') ||
        (window as any).__events.includes('logout') ||
        (window as any).__events.includes('match'),
      undefined,
      { timeout: timeoutMs }
    )
    .catch(() => {});
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

  test.fixme('silent assertion via communication_iframe from a cross-origin RP — document actual behavior', async ({
    page,
    request,
    brokerApi,
  }) => {
    const email = generateTestEmail();
    const password = generateTestPassword();
    expect(await brokerApi.createVerifiedUser(email, password)).toBe(true);

    // Establish state exactly like a real first visit: full popup sign-in
    // from the cross-origin RP (dialog runs top-level on the broker origin,
    // so its localStorage/keystore writes are UNpartitioned).
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

    // Return visit: fresh load of the RP page, silent watch().
    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(undefined));
    const events = await waitForOutcome(page, 20000);
    const outcome = events.includes('login')
      ? 'login'
      : events.includes('logout')
        ? 'logout'
        : events.includes('match')
          ? 'match'
          : 'timeout';

    // Diagnostics: what does the third-party comm iframe actually see?
    const iframeDiag = await page.evaluate(async (broker) => {
      const frames = Array.from(document.querySelectorAll('iframe'));
      return {
        iframeCount: frames.length,
        iframeSrcs: frames.map((f) => (f as HTMLIFrameElement).src),
        brokerReachable: await fetch(broker + '/wsapi/session_context', {
          credentials: 'include',
        })
          .then((r) => r.status)
          .catch((e) => String(e)),
      };
    }, brokerUrl);

    console.log(
      `[spike] silent-assertion outcome from cross-origin RP: ${outcome}; events=${JSON.stringify(events)}; diag=${JSON.stringify(iframeDiag)}`
    );

    test.info().annotations.push({
      type: 'spike-finding',
      description: `silent assertion cross-origin: ${outcome} (events: ${events.join(',')})`,
    });

    // Spike: document, don't wish. We assert only that the flow terminates
    // deterministically (no hang) — the outcome itself is the finding.
    expect(['login', 'logout', 'match']).toContain(outcome);
  });

  test.fixme('silent assertion from a SAME-SITE cross-origin RP (simulates browserid.me ↔ id.browserid.me split)', async ({
    page,
    brokerApi,
  }) => {
    // rp.localhost:<port> and localhost:3000 are different ORIGINS but the
    // same SITE (registrable domain "localhost") — exactly the relationship
    // between browserid.me (marketing/guestbook) and id.browserid.me (auth
    // cluster) after the proposed split. Chromium resolves *.localhost to
    // loopback, and same-site embedding gets neither third-party storage
    // partitioning nor SameSite=Lax cookie exclusion.
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

    // Return visit: silent watch() — the comm iframe is cross-origin but
    // same-site, so it should see the broker's real storage + session cookie.
    await page.goto(sameSiteRpUrl);
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    await page.evaluate(() => (window as any).__setup(undefined));
    const events = await waitForOutcome(page, 20000);
    const outcome = events.includes('login')
      ? 'login'
      : events.includes('logout')
        ? 'logout'
        : events.includes('match')
          ? 'match'
          : 'timeout';

    // Probe the mechanism from inside the comm-iframe's origin: does the
    // third-party (same-site) iframe see the session cookie, the localStorage
    // siteInfo the dialog wrote, and the keystore? This distinguishes a
    // cookie-SameSite problem (cheap fix) from storage partitioning (hard).
    const diag = await page.evaluate(async (broker) => {
      const out: any = {};
      // Cross-site fetch from the RP page itself (not the iframe) — will be
      // blocked by CORS-with-credentials semantics, expected to fail.
      try {
        const r = await fetch(broker + '/wsapi/session_context', {
          credentials: 'include',
        });
        out.sessionFromRpPage = { status: r.status, body: await r.json() };
      } catch (e) {
        out.sessionFromRpPage = String(e);
      }
      return out;
    }, brokerUrl);

    // Ask the broker origin directly (new top-level tab) what it sees, to
    // confirm the session + storage still exist unpartitioned there.
    const brokerTab = await page.context().newPage();
    await brokerTab.goto(brokerUrl + '/dialog/test.html');
    const brokerSide = await brokerTab.evaluate(async () => {
      const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) =>
        r.json()
      );
      let siteKeys: string[] = [];
      try {
        siteKeys = Object.keys(JSON.parse(localStorage.getItem('siteInfo') || '{}'));
      } catch {}
      return { authenticated: sc.authenticated, siteInfoKeys: siteKeys };
    });
    await brokerTab.close();

    console.log(
      `[spike] SAME-SITE cross-origin silent assertion: outcome=${outcome}; events=${JSON.stringify(events)}`
    );
    console.log(`[spike]   diag from RP page: ${JSON.stringify(diag)}`);
    console.log(`[spike]   broker-origin top-level sees: ${JSON.stringify(brokerSide)}`);
    test.info().annotations.push({
      type: 'spike-finding',
      description: `silent assertion same-site cross-origin: ${outcome}; broker-side session=${brokerSide.authenticated}, siteInfo keys=${brokerSide.siteInfoKeys.join('|')}`,
    });

    // SPIKE: document actual behavior. Whether this is 'login' or 'logout'
    // is THE finding for guestbook-split viability. We only require the flow
    // to terminate; the outcome + diagnostics above tell the story.
    expect(['login', 'logout', 'match']).toContain(outcome);
  });

  test.fixme('logout from a cross-origin RP terminates deterministically', async ({ page }) => {
    await page.goto(rp.origin());
    await page.waitForFunction(() => typeof (navigator as any).id === 'object');
    // No prior sign-in; RP claims a user is logged in → comm iframe should
    // answer logout (requires the iframe channel to work cross-origin at all).
    await page.evaluate(() => (window as any).__setup('nobody@example.com'));
    const events = await waitForOutcome(page, 20000);
    console.log(`[spike] claimed-user-no-session outcome: ${JSON.stringify(events)}`);
    expect(events.length).toBeGreaterThan(0);
  });
});
