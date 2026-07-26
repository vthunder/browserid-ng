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
import { requestProvision } from '../../sdk/agent/src/device.mjs';

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

    // HUMAN SIDE: Flow I (agent flows v2, bean eywc) — the fingerprint check
    // is its own step (I1), then name + address (I2, both prefilled from the
    // request), then the meet-your-agent done screen (I3). A grant-less
    // request never mentions permissions until I3 says there are none yet.
    await page.goto(pairing.verificationUriComplete);
    await expect(page.locator('#provision')).toBeVisible();
    await expect(page.locator('#provision')).toContainText('Is this your agent?');
    await expect(page.locator('#provision')).toContainText(pairing.fingerprint);
    await page.click('#pv-match');
    await expect(page.locator('#provision')).toContainText('Give your agent a name and an address');
    await page.click('#pv-approve'); // "Create its identity"
    await expect(page.locator('#provision')).toContainText('Meet', { timeout: 20000 });
    await expect(page.locator('#provision')).toContainText('no permissions yet');

    // AGENT SIDE: the bootstrap picks up the delegation and mints. Agent
    // identities sub-address their owner: `<owner-local>+<tag>@<owner-domain>`.
    const local = email.split('@')[0];
    const domain = email.split('@')[1];
    const agent = await pairing.ready;
    expect(agent.email).toBe(`${local}+${handle}@${domain}`);
    expect(agent.identity().names).toContain(`${local}+${handle}`);
  });

  test('bundled grants: identity stage, then the permission screen, one pickup (eywc)', async ({ page, request }) => {
    test.setTimeout(90000);
    const { email, pass } = await createAccount(request);
    await signIn(page, email, pass);
    const handle = `agt${Date.now().toString(36)}g`;

    // AGENT SIDE: one bundled request — identity + a grant, name + message.
    const pending = await requestProvision(baseUrl, {
      handle,
      grants: [{ audience: 'https://notes.example.com', scopes: ['post'] }],
      label: 'Bluesky poster',
      message: 'I post your daily summary thread each morning.',
    });

    // HUMAN SIDE: Flow I first — the word "permission" appears nowhere until
    // the identity exists — then the same code continues into Flow P.
    await page.goto(pending.verificationUriComplete);
    await expect(page.locator('#provision')).toContainText('Is this your agent?');
    await page.click('#pv-match');
    await expect(page.locator('#provision')).toContainText('Give your agent a name and an address');
    await expect(page.locator('#pv-name')).toHaveValue('Bluesky poster');
    await page.click('#pv-approve'); // "Create its identity"
    await expect(page.locator('#provision')).toContainText('Meet Bluesky poster', { timeout: 20000 });
    await page.click('#pv-toperm'); // "View permission request"
    await expect(page.locator('#provision')).toContainText('Bluesky poster wants permission');
    await expect(page.locator('#provision')).toContainText('I post your daily summary thread each morning.');
    await expect(page.locator('#provision')).toContainText('notes.example.com');
    await expect(page.locator('#provision')).toContainText('on behalf of');
    await page.click('#pv-approve'); // "Allow for 90 days"
    await expect(page.locator('#provision')).toContainText('See my agents', { timeout: 20000 });

    // AGENT SIDE: one pickup delivers credential + warrant together.
    const result = await pending.wait();
    const local = email.split('@')[0];
    const domain = email.split('@')[1];
    expect(result.credential.identity).toBe(`${local}+${handle}@${domain}`);
    expect(result.grants.length).toBe(1);
    expect(result.grants[0].audience).toBe('https://notes.example.com');
    expect(result.grantsDenied).toBeUndefined();
  });

  test('deny → the agent bootstrap rejects', async ({ page, request }) => {
    test.setTimeout(60000);
    const { email, pass } = await createAccount(request);
    await signIn(page, email, pass);
    const handle = `agt${Date.now().toString(36)}d`;

    const pairing = await Agent.bootstrap({ broker: baseUrl, requestedHandles: { names: [handle] }, label: 'e2e deny' });
    await page.goto(pairing.verificationUriComplete);
    await expect(page.locator('#provision')).toBeVisible();
    // I1's "It doesn't — stop" is the deny path: nothing has been created.
    await page.click('#pv-nomatch');
    await expect(page.locator('#provision')).toContainText('Nothing was created');

    await expect(pairing.ready).rejects.toThrow();
  });
});
