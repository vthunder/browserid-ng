/**
 * /account as its own device (registry-api-v1 §4.2, handoff 2026-09-09):
 * a password sign-in logs the page in to the registry with a page-local
 * login key; the "Signed in to this account" card lists it; a reload is
 * headless (stored_key, no password asked); signing that key out ends the
 * page's session and the card asks for the password again.
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
  await expect(list).toContainText('This browser', { timeout: 10000 });
  await expect(page.locator('#lk-pass-form')).toBeHidden();

  // A reload is headless: stored_key, still listed, still no prompt.
  await page.reload();
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
  await expect(list).toContainText('This browser', { timeout: 10000 });
  await expect(page.locator('#lk-pass-form')).toBeHidden();

  // The registry agrees: one live login key on the account.
  const keys = await page.evaluate(async () => {
    const r = await (window as any).Registry.call('GET', '/api/v1/login-keys');
    return r.login_keys.filter((k: any) => !k.revoked).map((k: any) => k.label);
  });
  expect(keys).toEqual(['This browser']);

  // Sign the page's own key out (in-content confirm): the session ends and
  // the card asks for the password.
  const revoke = list.locator('.lk-revoke').first();
  await revoke.click();
  await expect(revoke).toHaveText('Confirm sign-out');
  await revoke.click();
  await expect(page.locator('#lk-pass-form')).toBeVisible({ timeout: 10000 });

  // The password brings it back with a fresh key.
  await page.fill('#lk-pass', 'wrong-password');
  await page.click('#lk-go');
  await expect(page.locator('#lk-status')).toContainText('Wrong password', { timeout: 10000 });
  await page.fill('#lk-pass', pass);
  await page.click('#lk-go');
  await expect(page.locator('#lk-pass-form')).toBeHidden({ timeout: 10000 });
  await expect(list).toContainText('This browser');
});
