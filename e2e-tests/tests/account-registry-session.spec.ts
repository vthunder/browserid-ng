/**
 * /account as its own device (registry-api-v1 §4.2, handoff 2026-09-09):
 * a password sign-in logs the page in to the registry with this browser's
 * login key; the "Signed in to this account" card lists it (labelled from
 * the User-Agent); a reload is headless (stored_key); the current browser
 * has no sign-out in the card; without a key the page signs out rather
 * than fall back to the cookie.
 */
import { test, expect } from '@playwright/test';

const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

async function createAccount(request: any) {
  const email = `acct-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.test`;
  const pass = 'Password123!';
  await request.post(`${baseUrl}/wsapi/stage_signin_code`, { data: { email, pass } });
  const pending = await (
    await request.get(`${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=signin_code`)
  ).json();
  await request.post(`${baseUrl}/wsapi/complete_signin_code`, { data: { email, token: pending.code } });
  return { email, pass };
}

test('the account page logs in as its own device and can sign itself out', async ({ page, request }) => {
  const { email, pass } = await createAccount(request);
  await page.goto(`${baseUrl}/account`);
  await page.fill('#si-email', email);
  await page.click('#si-btn');
  await page.fill('#si-pass', pass);
  await page.click('#si-btn');
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });

  // The password sign-in enrolled this page's login key: listed, no prompt.
  const list = page.locator('#lk-list');
  await expect(list).toContainText('(this browser)', { timeout: 10000 });
  await expect(list).toContainText('Chrome');

  // A reload is headless: stored_key, still listed.
  await page.reload();
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
  await expect(list).toContainText('(this browser)', { timeout: 10000 });

  // The registry agrees: one live login key on the account.
  const keys = await page.evaluate(async () => {
    const r = await (window as any).Registry.call('GET', '/api/v1/login-keys');
    return r.login_keys.filter((k: any) => !k.revoked).map((k: any) => k.current);
  });
  expect(keys).toEqual([true]);

  // This browser's own key has no sign-out here (the navbar does that).
  await expect(list.locator('.lk-revoke')).toHaveCount(0);
  await expect(list).toContainText('(this browser)');

  // Without a login key the page does not fall back to the cookie: it
  // signs out, and the sign-in card says why.
  await page.evaluate(async () => {
    await (window as any).Registry.call('POST', '/api/v1/login-keys/revoke', { kid: (window as any).Registry.loginKid() });
    await (window as any).Registry.forgetLoginKey();
  });
  await page.reload();
  await expect(page.locator('#signin')).toBeVisible({ timeout: 10000 });
  await expect(page.locator('#si-lead')).toContainText('sign in again');

  // Signing in again enrols a fresh key and the card is back.
  await page.fill('#si-email', email);
  await page.click('#si-btn');
  await page.fill('#si-pass', pass);
  await page.click('#si-btn');
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
  await expect(list).toContainText('(this browser)', { timeout: 10000 });
});
