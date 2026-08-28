/**
 * Device-authorization return_url origin validation (bean 9it0).
 *
 * The certs issued by the device-authorize page certify the pubkeys carried
 * in the URL fragment, so the return_url delivery lane must never navigate
 * to an origin other than the validated return_origin — otherwise an
 * attacker page can open this page with its own pubkeys and its own
 * return_url, let the victim complete a legitimate first-party sign-in, and
 * collect a valid config cert for the victim's identity bound to the
 * attacker's keys.
 *
 * These tests stub the page's same-origin backend (/idp/whoami,
 * /idp/device_cert) so no real tenant session is needed; what is under test
 * is purely the client-side delivery decision.
 */

import { test, expect, Page } from '@playwright/test';

const PAGE = '/idp/device-authorize';

function frag(params: Record<string, string>): string {
  return '#' + Object.entries(params)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');
}

async function stubIdpBackend(page: Page) {
  await page.route('**/idp/whoami', (route) =>
    route.fulfill({ contentType: 'application/json', body: JSON.stringify({ email: 'user@tenant.example' }) }));
  await page.route('**/idp/device_cert', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ success: true, device_cert: 'dev.cert.sig', config_cert: 'cfg.cert.sig' }),
    }));
}

test.describe('device-authorize return_url validation', () => {
  test('delivers certs over a same-origin return_url', async ({ page, baseURL }) => {
    await stubIdpBackend(page);
    // The return target only needs to be reachable; content is irrelevant.
    await page.route('**/wallet-return', (route) =>
      route.fulfill({ contentType: 'text/html', body: '<html><body>return</body></html>' }));

    await page.goto(PAGE + frag({
      email: 'user@tenant.example',
      device_pubkey: 'devpub',
      config_pubkey: 'cfgpub',
      return_origin: baseURL!,
      return_url: `${baseURL}/wallet-return`,
    }));

    await page.waitForURL((url) => url.pathname === '/wallet-return', { timeout: 10000 });
    expect(page.url()).toContain('device_cert=dev.cert.sig');
    expect(page.url()).toContain('config_cert=cfg.cert.sig');
  });

  test('never navigates to a cross-origin return_url', async ({ page, baseURL }) => {
    await stubIdpBackend(page);
    let evilHit = false;
    await page.route('https://evil.example/**', (route) => {
      evilHit = true;
      return route.fulfill({ contentType: 'text/html', body: '<html></html>' });
    });

    await page.goto(PAGE + frag({
      email: 'user@tenant.example',
      device_pubkey: 'devpub',
      config_pubkey: 'cfgpub',
      return_origin: baseURL!,
      return_url: 'https://evil.example/collect',
    }));

    // Give the page time to run whoami → device_cert → deliver. With the
    // cross-origin return_url rejected and no window.opener, delivery is a
    // no-op and the page stays put.
    await page.waitForTimeout(3000);
    expect(evilHit).toBe(false);
    expect(new URL(page.url()).pathname).toBe(PAGE);
  });

  test('rejects a return_url that mismatches a foreign return_origin', async ({ page }) => {
    // Both parameters attacker-supplied but inconsistent with each other:
    // the same-origin rule strips return_url, and with no window.opener the
    // page has no delivery lane at all — it must stay put.
    await stubIdpBackend(page);
    let evilHit = false;
    await page.route('https://evil.example/**', (route) => {
      evilHit = true;
      return route.fulfill({ contentType: 'text/html', body: '<html></html>' });
    });

    await page.goto(PAGE + frag({
      email: 'user@tenant.example',
      device_pubkey: 'devpub',
      config_pubkey: 'cfgpub',
      return_origin: 'http://not-evil.example',
      return_url: 'https://evil.example/collect',
    }));

    await page.waitForTimeout(3000);
    expect(evilHit).toBe(false);
    expect(new URL(page.url()).pathname).toBe(PAGE);
  });
});
