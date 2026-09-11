/**
 * Account page: remove an address (registry detach, registry-api-v1 §5.2.5;
 * bean 38im). The rail offers a per-address remove with an in-page
 * confirmation; the identity leaves the account (on hold) and disappears from
 * the list. The last address has no remove control.
 */
import { test, expect, generateTestEmail, generateTestPassword } from '../fixtures/test-helpers';

const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

async function createAccount(request: any, email: string, pass: string) {
  await request.post(`${baseUrl}/wsapi/stage_signin_code`, { data: { email, pass } });
  const pending = await (
    await request.get(`${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=signin_code`)
  ).json();
  await request.post(`${baseUrl}/wsapi/complete_signin_code`, { data: { email, token: pending.code } });
}

// Sign in on /account via its own form (session cookie + registry login key).
async function signIn(page: any, email: string, pass: string) {
  await page.goto(`${baseUrl}/account`);
  await page.fill('#si-email', email);
  await page.click('#si-btn');
  await page.fill('#si-pass', pass);
  await page.click('#si-btn');
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
}

async function addAddress(page: any, request: any, email: string) {
  const staged = await page.evaluate(async (e: string) => {
    const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) => r.json());
    return fetch('/wsapi/stage_email', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
      body: JSON.stringify({ email: e, csrf: sc.csrf_token }),
    }).then((r) => r.json());
  }, email);
  expect(staged.success).toBeTruthy();
  const pending = await (
    await request.get(`${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=add_email`)
  ).json();
  const done = await page.evaluate(async ({ token, e }: any) => {
    const sc = await fetch('/wsapi/session_context', { credentials: 'include' }).then((r) => r.json());
    return fetch('/wsapi/complete_email_addition', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
      body: JSON.stringify({ email: e, token, csrf: sc.csrf_token }),
    }).then((r) => r.json());
  }, { token: pending.code, e: email });
  expect(done.success).toBeTruthy();
}

test('remove an address from the rail; the last one cannot be removed', async ({ page, request }) => {
  test.setTimeout(60000);
  const first = generateTestEmail();
  const second = generateTestEmail();
  const pass = generateTestPassword();
  await createAccount(request, first, pass);
  await signIn(page, first, pass);
  await addAddress(page, request, second);
  await page.reload();
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
  await expect(page.locator('#addrlist')).toContainText(second, { timeout: 10000 });

  // Two addresses: both removable. Ask for the second, then confirm in-page.
  await page.click(`[data-remove="${second}"]`);
  await expect(page.locator('.addr-confirm')).toContainText(second);
  await page.click(`[data-remove-go="${second}"]`);
  await expect(page.locator('#addrlist')).not.toContainText(second, { timeout: 15000 });
  await expect(page.locator('#addrlist')).toContainText(first);

  // One address left: no remove control.
  await expect(page.locator('[data-remove]')).toHaveCount(0);
});
