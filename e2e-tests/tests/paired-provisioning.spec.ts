/**
 * Paired agent provisioning end-to-end (bean 74u1).
 *
 * Drives BOTH sides in one test: the agent side is the Node SDK
 * (`Agent.bootstrap`), the human side is the browser (approve on
 * `/account?provision=<code>`). Proves the full loop — pair → human approves →
 * agent picks up the delegation and mints — with the provisioning key never
 * leaving the SDK.
 */
import { test, expect } from '@playwright/test';
// The agent-side SDK, run in the Node test process.
import { Agent } from '../../sdk/agent/index.mjs';

const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';

// A verified broker account with a password, via the test-only endpoints.
async function createAccount(request: any) {
  const email = `paired-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.test`;
  const pass = 'Password123!';
  await request.post(`${baseUrl}/wsapi/stage_user`, { data: { email, pass } });
  const pending = await (
    await request.get(`${baseUrl}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=new_account`)
  ).json();
  await request.post(`${baseUrl}/wsapi/complete_user_creation`, { data: { token: pending.code } });
  return { email, pass };
}

// Sign in on /account via its own form (establishes the session cookie).
async function signIn(page: any, email: string, pass: string) {
  await page.goto(`${baseUrl}/account`);
  await page.fill('#si-email', email);
  await page.click('#si-btn'); // reveals the password field
  await page.fill('#si-pass', pass);
  await page.click('#si-btn'); // authenticate → reload
  await expect(page.locator('#app')).toBeVisible({ timeout: 10000 });
}

test.describe('Paired agent provisioning (74u1)', () => {
  test('pair → human approves → agent mints, no downloaded credential', async ({ page, request }) => {
    test.setTimeout(60000);
    const { email, pass } = await createAccount(request);
    await signIn(page, email, pass);

    // Unique handle so reservations from earlier runs don't collide.
    const handle = `agt${Date.now().toString(36)}`;

    // AGENT SIDE: start pairing (generates the provisioning key locally).
    const pairing = await Agent.bootstrap({
      broker: baseUrl,
      requestedHandles: { names: [handle] },
      label: 'e2e agent',
    });
    expect(pairing.verificationUriComplete).toContain('/account?provision=');
    expect(pairing.fingerprint).toMatch(/^[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}$/);

    // HUMAN SIDE: open the approval page and approve. The common case (A1)
    // asks nothing: the requested handle is prefilled in the "By" row and
    // one click approves.
    await page.goto(pairing.verificationUriComplete);
    await expect(page.locator('#provision')).toBeVisible();
    await page.selectOption('#pv-identity', email);
    await page.click('#pv-approve');
    await expect(page.locator('#provision')).toContainText('Your agent has an address now', { timeout: 20000 });

    // AGENT SIDE: the bootstrap picks up the delegation and mints. Agent
    // identities sub-address their owner: `<owner-local>+<tag>@<owner-domain>`.
    const local = email.split('@')[0];
    const domain = email.split('@')[1];
    const agent = await pairing.ready;
    expect(agent.email).toBe(`${local}+${handle}@${domain}`);
    expect(agent.identity().names).toContain(`${local}+${handle}`);
  });

  test('deny → the agent bootstrap rejects', async ({ page, request }) => {
    test.setTimeout(60000);
    const { email, pass } = await createAccount(request);
    await signIn(page, email, pass);
    const handle = `agt${Date.now().toString(36)}d`;

    const pairing = await Agent.bootstrap({ broker: baseUrl, requestedHandles: { names: [handle] }, label: 'e2e deny' });
    await page.goto(pairing.verificationUriComplete);
    await expect(page.locator('#provision')).toBeVisible();
    await page.click('#pv-deny');
    await expect(page.locator('#provision')).toContainText('Nothing was authorized');

    await expect(pairing.ready).rejects.toThrow();
  });
});
