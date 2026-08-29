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

  test('stale verification demands a fresh mailbox code before issuing (uboq)', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('stale');
    await createAccount(context, baseURL!, email);
    const bd = await context.request.post(`${baseURL}/wsapi/test/set_verified_at`, {
      data: { email, days_ago: 120 },
    });
    expect((await bd.json()).success).toBeTruthy();
    const r = await context.request.post(`${baseURL}/wsapi/authenticate_user`, {
      data: { email, pass: PASSWORD },
    });
    expect(r.ok()).toBeTruthy();

    await stubReturn(page);
    await page.goto(pageUrl(baseURL!, email));
    await expect(page.locator('#confirm-form')).toBeVisible();
    await page.click('#confirm-btn');

    // Issuance is refused (verification expired) → the page stages a fresh
    // mailbox code instead of delivering.
    await expect(page.locator('#verify-form')).toBeVisible({ timeout: 10000 });
    const pending = await (
      await context.request.get(
        `${baseURL}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=add_email`
      )
    ).json();
    expect(pending.code).toBeDefined();
    await page.fill('#code', pending.code);
    await page.click('#verify-btn');

    await page.waitForURL((url) => url.pathname === '/wallet-return', { timeout: 15000 });
    expect(new URL(page.url()).hash).toContain('device_cert=');
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

// ---------------------------------------------------------------------------
// Bridge-verified (E2) identities — bean n5ty. The local broker has no
// Google credentials, so discovery is stubbed to proof=oidc and the claim
// popup is faked; the broker session and the issuance behind the page stay
// REAL (the account is password-backed, so the mint allows once the page
// believes the bridge hop succeeded).
test.describe('fallback device-authorize: bridge-verified identities', () => {
  async function stubOidcDiscovery(page: Page, baseURL: string, email: string) {
    await page.context().route('**/wsapi/address_info**', (route) =>
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          type: 'secondary', issuer: 'localhost:3000', disabled: false,
          normalizedEmail: email, proof: 'oidc', claim: `${baseURL}/oidc/claim`,
        }),
      }));
  }

  function fakeClaimPopup(page: Page, result: Record<string, unknown>) {
    // The popup stands in for the broker's post-OAuth resume page: it
    // broadcasts the claim result on the dialog's same-origin channel.
    return page.context().route('**/oidc/claim**', (route) =>
      route.fulfill({
        contentType: 'text/html',
        body: `<html><body><script>
          const chan = new BroadcastChannel('browserid:oidc_claim_resume');
          let n = 0;
          const t = setInterval(() => {
            chan.postMessage(Object.assign({ type: 'browserid:oidc_claim_result',
              nonce: 'test-' + n }, ${JSON.stringify(result)}));
            if (++n > 10) clearInterval(t);
          }, 200);
        </script></body></html>`,
      }));
  }

  test('routes a bridge-verified identity to the bridge screen, never the password form', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('bridge-route');
    await createAccount(context, baseURL!, email);
    await context.clearCookies();
    await stubOidcDiscovery(page, baseURL!, email);

    await stubReturn(page);
    await page.goto(pageUrl(baseURL!, email));
    await expect(page.locator('#bridge-form')).toBeVisible();
    await expect(page.locator('#bridge-btn')).toContainText('Continue with Google');
    await expect(page.locator('#login-form')).toBeHidden();
    // No issuance without the gesture.
    await page.waitForTimeout(1200);
    expect(new URL(page.url()).pathname).toBe('/device-authorize');

    await page.click('#bridge-cancel');
    await page.waitForURL((url) => url.pathname === '/wallet-return', { timeout: 10000 });
    expect(new URL(page.url()).hash).toContain('device_error=cancelled');
  });

  test('bridge hop → issuance → delivery (claim simulated, session + mint real)', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('bridge-ok');
    await createAccount(context, baseURL!, email);
    const r = await context.request.post(`${baseURL}/wsapi/authenticate_user`, {
      data: { email, pass: PASSWORD },
    });
    expect(r.ok()).toBeTruthy();
    await stubOidcDiscovery(page, baseURL!, email);
    await fakeClaimPopup(page, { ok: true, email });

    await stubReturn(page);
    await page.goto(pageUrl(baseURL!, email));
    await expect(page.locator('#bridge-form')).toBeVisible();
    await page.click('#bridge-btn');

    await page.waitForURL((url) => url.pathname === '/wallet-return', { timeout: 15000 });
    const frag = new URL(page.url()).hash;
    expect(frag).toContain('device_cert=');
    expect(frag).toContain('config_cert=');
  });

  test('claim refused with password-required runs the attach leg: password, then the bridge again', async ({ context, page, baseURL }) => {
    const email = uniqueEmail('bridge-pw');
    await createAccount(context, baseURL!, email);
    await context.clearCookies();
    await stubOidcDiscovery(page, baseURL!, email);
    await fakeClaimPopup(page, { ok: false, email, reason: 'password required' });

    await stubReturn(page);
    await page.goto(pageUrl(baseURL!, email));
    await expect(page.locator('#bridge-form')).toBeVisible();
    await page.click('#bridge-btn');

    // kts0: the page collects the password, then offers the bridge again.
    await expect(page.locator('#login-form')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#login-err')).toContainText('Confirm your password');
    await page.fill('#password', PASSWORD);
    await page.click('#login-btn');
    await expect(page.locator('#bridge-form')).toBeVisible({ timeout: 10000 });
  });
});
