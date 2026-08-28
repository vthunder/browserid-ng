/**
 * Fallback-IdP device-authorization page (beans d0xb / 2jfh).
 *
 * The broker's own ceremony page at /device-authorize implements the same
 * fragment/return contract a primary's page does (fallback-idp-api-v1 §3):
 * a wallet opens it with pubkeys in the fragment, the user authenticates
 * first-party (broker password), and the certs come back through the
 * return_url delivery lane. Issuance goes through the /device/issue core —
 * one issuance implementation for every consumer.
 *
 * These tests run the REAL flow: real signup, real password auth, real
 * issuance and delivery. Plus the two guarantees the page must keep: a live
 * session still requires an explicit consent click (bean mxcn — never
 * silent), and a cross-origin return_url is never navigated to (bean 9it0).
 */

import { test, expect, BrowserContext, Page } from '@playwright/test';
import { generateKeyPairSync } from 'crypto';

const PASSWORD = 'e2e-password-1';

function randB64Key(): string {
  // A REAL Ed25519 public key, raw 32 bytes base64url — the server rejects
  // byte strings that don't decompress to a curve point.
  const { publicKey } = generateKeyPairSync('ed25519');
  const der = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  return der.subarray(der.length - 32).toString('base64url');
}

function pageUrl(baseURL: string, email: string, opts: { returnUrl?: string } = {}): string {
  const params = [
    `email=${encodeURIComponent(email)}`,
    `device_pubkey=${encodeURIComponent(randB64Key())}`,
    `config_pubkey=${encodeURIComponent(randB64Key())}`,
    `return_origin=${encodeURIComponent(baseURL)}`,
    `return_url=${encodeURIComponent(opts.returnUrl ?? `${baseURL}/wallet-return`)}`,
  ];
  return `/device-authorize#${params.join('&')}`;
}

async function createAccount(context: BrowserContext, baseURL: string, email: string) {
  const r1 = await context.request.post(`${baseURL}/wsapi/stage_signin_code`, {
    data: { email, pass: PASSWORD },
  });
  expect(r1.ok()).toBeTruthy();
  const pending = await (
    await context.request.get(
      `${baseURL}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=signin_code`
    )
  ).json();
  expect(pending.code).toBeDefined();
  const r2 = await context.request.post(`${baseURL}/wsapi/complete_signin_code`, {
    data: { email, token: pending.code },
  });
  expect(r2.ok()).toBeTruthy();
}

async function stubReturn(page: Page) {
  await page.route('**/wallet-return', (route) =>
    route.fulfill({ contentType: 'text/html', body: '<html><body>return</body></html>' }));
}

function uniqueEmail(tag: string): string {
  return `fb-da-${tag}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
}

test.describe('fallback device-authorize ceremony', () => {
  test('password sign-in issues and delivers certs over return_url', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('cold');
    await createAccount(context, baseURL!, email);
    await context.clearCookies(); // cold wallet hop: no session

    await stubReturn(page);
    await page.goto(pageUrl(baseURL!, email));
    await expect(page.locator('#login-form')).toBeVisible();
    await expect(page.locator('#subtitle')).toContainText(email);
    await page.fill('#password', PASSWORD);
    await page.click('#login-btn');

    await page.waitForURL((url) => url.pathname === '/wallet-return', { timeout: 15000 });
    const frag = new URL(page.url()).hash;
    expect(frag).toContain('device_cert=');
    expect(frag).toContain('config_cert=');
    expect(frag).not.toContain('device_error');
  });

  test('a live session needs an explicit click — never silent issuance', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('warm');
    await createAccount(context, baseURL!, email);
    // complete_signin_code leaves no session cookie guarantee — sign in
    // explicitly so the session-skip path is what we exercise.
    const r = await context.request.post(`${baseURL}/wsapi/authenticate_user`, {
      data: { email, pass: PASSWORD },
    });
    expect(r.ok()).toBeTruthy();

    await stubReturn(page);
    await page.goto(pageUrl(baseURL!, email));
    await expect(page.locator('#confirm-form')).toBeVisible();
    // No navigation without the gesture.
    await page.waitForTimeout(1500);
    expect(new URL(page.url()).pathname).toBe('/device-authorize');

    await page.click('#confirm-btn');
    await page.waitForURL((url) => url.pathname === '/wallet-return', { timeout: 15000 });
    expect(new URL(page.url()).hash).toContain('device_cert=');
  });

  test('cancel returns device_error=cancelled', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('cancel');
    await createAccount(context, baseURL!, email);
    await context.clearCookies();

    await stubReturn(page);
    await page.goto(pageUrl(baseURL!, email));
    await expect(page.locator('#login-form')).toBeVisible();
    await page.click('#login-cancel');
    await page.waitForURL((url) => url.pathname === '/wallet-return', { timeout: 10000 });
    expect(new URL(page.url()).hash).toContain('device_error=cancelled');
  });

  test('never navigates to a cross-origin return_url', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('evil');
    await createAccount(context, baseURL!, email);
    const r = await context.request.post(`${baseURL}/wsapi/authenticate_user`, {
      data: { email, pass: PASSWORD },
    });
    expect(r.ok()).toBeTruthy();

    let evilHit = false;
    await page.route('https://evil.example/**', (route) => {
      evilHit = true;
      return route.fulfill({ contentType: 'text/html', body: '<html></html>' });
    });
    await page.goto(pageUrl(baseURL!, email, { returnUrl: 'https://evil.example/collect' }));
    await expect(page.locator('#confirm-form')).toBeVisible();
    await page.click('#confirm-btn');
    // With return_url stripped (9it0) and no opener, delivery is a no-op.
    await page.waitForTimeout(2500);
    expect(evilHit).toBe(false);
    expect(new URL(page.url()).pathname).toBe('/device-authorize');
  });

  test('wrong password shows an error and stays put', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('wrongpw');
    await createAccount(context, baseURL!, email);
    await context.clearCookies();

    await stubReturn(page);
    await page.goto(pageUrl(baseURL!, email));
    await expect(page.locator('#login-form')).toBeVisible();
    await page.fill('#password', 'not-the-password');
    await page.click('#login-btn');
    await expect(page.locator('#login-err')).not.toHaveText('', { timeout: 10000 });
    expect(new URL(page.url()).pathname).toBe('/device-authorize');
  });
});
