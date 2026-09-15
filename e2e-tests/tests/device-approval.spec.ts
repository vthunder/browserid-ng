/**
 * Approve a new device from an enrolled one (registry-api-v1 §5.2.8, bean
 * puo8): the login page, opened by a "new device" with no password at hand,
 * shows a code; the account page on an enrolled browser lists the waiting
 * device, takes the code, and the login page returns a login token to the
 * device's return URL. A wrong code is refused in place; deny ends it.
 */
import { test, expect } from '@playwright/test';

const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

async function createAccount(request: any) {
  const email = `appr-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.test`;
  const pass = 'Password123!';
  await request.post(`${baseUrl}/wsapi/stage_signin_code`, { data: { email, pass } });
  const pending = await (
    await request.get(`${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=signin_code`)
  ).json();
  await request.post(`${baseUrl}/wsapi/complete_signin_code`, { data: { email, token: pending.code } });
  return { email, pass };
}

async function signIn(page: any, email: string, pass: string) {
  await page.fill('#si-email', email);
  await page.click('#si-btn');
  await page.fill('#si-pass', pass);
  await page.click('#si-btn');
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
}

test('a new device joins by a code typed on the account page', async ({ browser, page, request }) => {
  const { email, pass } = await createAccount(request);
  await page.goto(`${baseUrl}/account`);
  await signIn(page, email, pass);
  await expect(page.locator('#sections')).toContainText('this device', { timeout: 10000 });
  const account: string = await page.evaluate(() => fetch('/wsapi/session_context', { credentials: 'same-origin' }).then(r => r.json()).then(j => j.account));
  expect(account).toBeTruthy();

  // The "new device": a fresh browser context, no cookies, opens the login
  // page the way a wallet would and picks approval.
  const fresh = await browser.newContext();
  const dev = await fresh.newPage();
  const returnUrl = `${baseUrl}/registry-login-return`;
  await dev.goto(`${baseUrl}/registry-login#account=${encodeURIComponent(account)}&return_origin=${encodeURIComponent(baseUrl)}&return_url=${encodeURIComponent(returnUrl)}`);
  await dev.click('#to-approval');
  const codeEl = dev.locator('#approval-code');
  await expect(codeEl).not.toHaveText('···-···', { timeout: 10000 });
  const code = (await codeEl.textContent())!.trim();
  expect(code).toMatch(/^[A-Z2-9]{3}-[A-Z2-9]{3}$/);

  // The account page lists it within its refresh; a wrong code is refused.
  const form = page.locator('#sections form[data-approval]');
  await expect(form).toHaveCount(1, { timeout: 20000 });
  await form.locator('input[name=code]').fill('ZZZ-999');
  await form.locator('button[type=submit]').click();
  await expect(form.locator('.err')).toContainText('not the code', { timeout: 10000 });
  // The right one, typed loosely.
  await form.locator('input[name=code]').fill(code.toLowerCase().replace('-', ''));
  await form.locator('button[type=submit]').click();
  await expect(page.locator('#sections form[data-approval]')).toHaveCount(0, { timeout: 10000 });

  // The new device's poll picks up the token and returns it.
  await dev.waitForURL((u) => u.toString().startsWith(returnUrl), { timeout: 15000 });
  const frag = new URLSearchParams(new URL(dev.url()).hash.slice(1));
  expect(frag.get('login')).toBeTruthy();
  expect(frag.get('login_error')).toBeNull();
  await fresh.close();
});

test('deny from the account page ends the new device\'s wait', async ({ browser, page, request }) => {
  const { email, pass } = await createAccount(request);
  await page.goto(`${baseUrl}/account`);
  await signIn(page, email, pass);
  const account: string = await page.evaluate(() => fetch('/wsapi/session_context', { credentials: 'same-origin' }).then(r => r.json()).then(j => j.account));

  const fresh = await browser.newContext();
  const dev = await fresh.newPage();
  await dev.goto(`${baseUrl}/registry-login#account=${encodeURIComponent(account)}&return_origin=${encodeURIComponent(baseUrl)}&method=approval`);
  await expect(dev.locator('#approval-code')).not.toHaveText('···-···', { timeout: 10000 });

  const form = page.locator('#sections form[data-approval]');
  await expect(form).toHaveCount(1, { timeout: 20000 });
  await form.locator('[data-approval-deny]').click();
  await expect(page.locator('#sections form[data-approval]')).toHaveCount(0, { timeout: 10000 });
  await expect(dev.locator('#approval-err')).toContainText('said no', { timeout: 10000 });
  await fresh.close();
});
