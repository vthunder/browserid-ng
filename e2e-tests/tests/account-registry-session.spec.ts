/**
 * /account as its own device (registry-api-v1 §2, §4.2): a password sign-in
 * logs the page in to the registry with this browser's login key; the
 * roster's "You, on your devices" draws one row per login key (labelled from
 * the User-Agent), this browser marked and shown even with no certs; a
 * reload is headless (stored_key); renaming goes through login-keys/rename;
 * without a key the page signs out rather than fall back to the cookie.
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

async function signIn(page: any, email: string, pass: string) {
  await page.fill('#si-email', email);
  await page.click('#si-btn');
  await page.fill('#si-pass', pass);
  await page.click('#si-btn');
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
}

test('the roster lists this browser by its login key and the page signs out without one', async ({ page, request }) => {
  const { email, pass } = await createAccount(request);
  await page.goto(`${baseUrl}/account`);
  await signIn(page, email, pass);

  // One device row: this browser's login key, named from the User-Agent,
  // with no certs yet (the page enrolled it, no dialog ran here).
  const sections = page.locator('#sections');
  await expect(sections).toContainText('this device', { timeout: 10000 });
  await expect(sections).toContainText('Chrome');
  await expect(sections).toContainText('account page only');
  await expect(page.locator('#sections .arow')).toHaveCount(1);
  // The old card is gone.
  await expect(page.locator('#lk-list')).toHaveCount(0);

  // The registry agrees: one live login key, the current one, no certs.
  const state = await page.evaluate(async () => {
    const R = (window as any).Registry;
    const keys = (await R.call('GET', '/api/v1/login-keys')).login_keys.filter((k: any) => !k.revoked);
    const certs = (await R.call('GET', '/api/v1/certs')).certs;
    return { keys: keys.map((k: any) => k.current), certs: certs.length };
  });
  expect(state).toEqual({ keys: [true], certs: 0 });

  // A reload is headless: stored_key, still one row.
  await page.reload();
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
  await expect(sections).toContainText('this device', { timeout: 10000 });

  // Rename it from the detail view (login-keys/rename).
  await page.locator('#sections .rowtoggle').first().click();
  await page.locator('#sections .managelink').first().click();
  await expect(page.locator('#detail-card')).toBeVisible();
  await page.click('#rn-edit');
  await page.fill('#rn-input', 'My test browser');
  await page.click('#rn-save');
  await expect(page.locator('#detail-card')).toContainText('My test browser', { timeout: 10000 });
  await page.click('#detail-back');
  await expect(sections).toContainText('My test browser', { timeout: 10000 });

  // Without a login key the page does not fall back to the cookie: it
  // signs out, and the sign-in card says why.
  await page.evaluate(async () => {
    const R = (window as any).Registry;
    await R.call('POST', '/api/v1/login-keys/revoke', { kid: R.loginKid() });
    await R.forgetLoginKey();
  });
  await page.reload();
  await expect(page.locator('#signin')).toBeVisible({ timeout: 10000 });
  await expect(page.locator('#si-lead')).toContainText('sign in again');

  // Signing in again enrols a fresh key: one row again, fresh name.
  await signIn(page, email, pass);
  await expect(sections).toContainText('this device', { timeout: 10000 });
  await expect(page.locator('#sections .arow')).toHaveCount(1);
  await expect(sections).not.toContainText('My test browser');
});
