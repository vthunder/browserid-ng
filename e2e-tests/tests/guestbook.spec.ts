/**
 * Agent guestbook end-to-end: an agent provisions (paired), gets a `sign`
 * warrant for the guestbook, signs it, and the message appears in the public
 * feed attributed to the agent AND its human. Exercises the whole stack — SDK,
 * paired provisioning, warrant consent, the guestbook RP.
 */
import { test, expect } from '@playwright/test';
import { Agent } from '../../sdk/agent/index.mjs';

const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
const guestbookAud = `${baseUrl}/guestbook`;

async function createAccount(request: any) {
  const email = `gb-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.test`;
  const pass = 'Password123!';
  await request.post(`${baseUrl}/wsapi/stage_user`, { data: { email, pass } });
  const pending = await (
    await request.get(`${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=new_account`)
  ).json();
  await request.post(`${baseUrl}/wsapi/complete_user_creation`, { data: { email, token: pending.code } });
  return { email, pass };
}

async function signIn(page: any, email: string, pass: string) {
  await page.goto(`${baseUrl}/account`);
  await page.fill('#si-email', email);
  await page.click('#si-btn');
  await page.fill('#si-pass', pass);
  await page.click('#si-btn');
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
}

// Approve whatever pending request is showing (provision panel or consent page).
async function approveAt(page: any, url: string, approveSelector: string) {
  await page.goto(url);
  const btn = page.locator(approveSelector).first();
  await expect(btn).toBeVisible({ timeout: 10000 });
  await expect(btn).toBeEnabled({ timeout: 5000 }); // consent has an arming delay
  await btn.click();
}

test('agent provisions, gets a sign warrant, and signs the public guestbook', async ({ page, request }) => {
  test.setTimeout(90000);
  const { email, pass } = await createAccount(request);
  await signIn(page, email, pass);
  const handle = `gb${Date.now().toString(36)}`;

  // 1. Provision (paired) → minted agent.
  const pairing = await Agent.bootstrap({ broker: baseUrl, requestedHandles: { names: [handle] }, label: 'guestbook agent' });
  await page.goto(pairing.verificationUriComplete);
  await expect(page.locator('#provision')).toBeVisible();
  await page.selectOption('#pv-identity', email);
  await page.fill('#pv-handles', handle);
  await page.click('#pv-approve');
  await expect(page.locator('#pv-status')).toContainText('Approved', { timeout: 20000 });
  const agent = await pairing.ready;

  // 2. Obtain a `sign` warrant for the guestbook (consent page approval).
  let consentUrl: string | undefined;
  const warrant = agent.obtainWarrant(guestbookAud, ['sign'], (u: string) => { consentUrl = u; });
  await expect.poll(() => consentUrl, { timeout: 10000 }).toBeTruthy();
  await approveAt(page, consentUrl!, 'button.approve');
  await warrant;

  // 3. Sign the guestbook with a warrant-backed assertion.
  const assertion = await agent.assertionFor(guestbookAud);
  const message = `hello from ${handle} at ${Date.now()}`;
  const res = await request.post(`${baseUrl}/guestbook`, { data: { assertion, message } });
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(body.success).toBe(true);
  expect(body.agent).toBe(`${handle}@${baseUrl.replace(/^https?:\/\//, '')}`);
  expect(body.parent).toBe(email);

  // 4. The public feed shows it, attributed to agent + human.
  const feed = await (await request.get(`${baseUrl}/guestbook/feed`)).json();
  const entry = feed.entries.find((e: any) => e.message === message);
  expect(entry).toBeTruthy();
  expect(entry.parent).toBe(email);
  expect(entry.scopes).toContain('sign');

  // 5. The HTML page renders the message + attribution.
  await page.goto(`${baseUrl}/guestbook`);
  await expect(page.locator('body')).toContainText(message);
  await expect(page.locator('body')).toContainText(email);
});

test('guestbook rejects a non-agent / bad assertion', async ({ request }) => {
  const res = await request.post(`${baseUrl}/guestbook`, { data: { assertion: 'not-real', message: 'hi' } });
  expect(res.status()).toBeGreaterThanOrEqual(400);
  expect((await res.json()).success).toBe(false);
});
