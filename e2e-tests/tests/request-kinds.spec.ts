/**
 * Request kinds over the mediator (spec §7.3, docs/specs/request-kinds/;
 * bean g69e).
 *
 * `navigator.id.request(kind, args)` returns a promise of the kind's
 * artefact. `warrant` (present lane, self-grant) rides the sign-in to learn
 * who signs, shows the one warrant card, and returns the signed records;
 * `signature` signs a typed object under the stored covering record with no
 * sign-in, auto scopes silently and prompt scopes after the in-dialog
 * approval; an unknown kind answers `unsupported_kind`.
 *
 * One test: the record lives in the dialog's first-party localStorage, which
 * a fresh per-test context would drop.
 */
import { test, expect, generateTestPassword } from '../fixtures/test-helpers';
import { DialogPage } from '../pages/dialog';

const BROKER = process.env.BROKER_URL || 'http://localhost:3000';
const AUDIENCE = 'sbo+raw://avail:turing:506/';
const GRANTS = [{ audience: AUDIENCE, scopes: ['sign:sbo:post', { scope: 'sign:sbo:delete', mode: 'prompt' }] }];

function envelope(action: string, owner?: string) {
  return {
    action,
    owner,
    path: '/communities/cooks/spaces/general/',
    id: 'e2e-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8),
    public_key: 'ed25519:' + '00'.repeat(32),
    content_schema: 'post.v1',
    payload: Array.from(new TextEncoder().encode(JSON.stringify({ body: 'hi' }))),
    hlc: `${Date.now()}.0`,
  };
}

function claimsOf(jws: string) {
  return JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString());
}

test.describe('request(kind, args)', () => {
  const uniqueId = `${Date.now()}-${Math.random().toString(36).substring(7)}`;
  const email = `req-kind-${uniqueId}@example.com`;
  const password = generateTestPassword();

  test.beforeAll(async ({ request }) => {
    const stage = await request.post(`${BROKER}/wsapi/stage_signin_code`, { data: { email, pass: password } });
    expect(stage.ok()).toBeTruthy();
    const pending = await request
      .get(`${BROKER}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=signin_code`)
      .then(r => r.json());
    const done = await request.post(`${BROKER}/wsapi/complete_signin_code`, { data: { email, token: pending.code } });
    expect(done.ok()).toBeTruthy();
  });

  test('warrant then signature, one signer, promise results', async ({ page }) => {
    test.setTimeout(120000);
    await page.goto('/');
    await page.addScriptTag({ url: `${BROKER}/include.js` });
    await page.waitForFunction(() => typeof (navigator as any).id?.request === 'function');

    // Each request stashes its settled outcome on window so the test can
    // read it after driving the popup.
    const start = (kind: string, args: any, slot: string) =>
      page.evaluate(([k, a, s]) => {
        const w = window as any;
        w[s] = { pending: true };
        (navigator as any).id.request(k, a).then(
          (r: any) => { w[s] = { ok: r }; },
          (e: any) => { w[s] = { err: e }; });
      }, [kind, args, slot] as const);
    const outcome = (slot: string) =>
      page.waitForFunction(s => !(window as any)[s].pending, slot, { timeout: 30000 })
        .then(() => page.evaluate(s => (window as any)[s], slot));

    // ---- 1. warrant: sign in, the card, the records ----
    let popupP = page.context().waitForEvent('page');
    await start('warrant', { grants: GRANTS }, '__w');
    let popup = await popupP;
    await popup.waitForSelector('#email-screen.active', { timeout: 15000 });
    await new DialogPage(popup).signInExistingUser(email, password);
    await popup.waitForSelector('#sbo-consent-screen.active', { timeout: 20000 });
    await expect(popup.locator('#sbo-consent-audiences')).toContainText(AUDIENCE);
    await expect(popup.locator('#sbo-consent-scopes')).toContainText('signed automatically');
    await expect(popup.locator('#sbo-consent-scopes')).toContainText('approve each one');
    await popup.click('#sbo-consent-allow');
    const w = await outcome('__w');
    expect(w.ok, JSON.stringify(w)).toBeTruthy();
    expect(w.ok.warrants).toHaveLength(1);
    expect(w.ok.config_cert).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(w.ok.email).toBe(email);
    const c = claimsOf(w.ok.warrants[0]);
    expect(c.typ).toBe('browserid-warrant-v2');
    expect(c.grantor).toBe(email);
    expect(c.grantee).toBe(email);
    expect(c.audience).toBe(AUDIENCE);
    expect(c.binding.map((e: any) => e.kind).sort()).toEqual(['holder', 'requester']);
    expect(c.binding.find((e: any) => e.kind === 'requester').origin).toBe(BROKER);
    expect(c.scopes).toEqual(GRANTS[0].scopes);
    expect(typeof c.status?.idx).toBe('number');

    // ---- 2. signature, auto scope: no UI, stamped and bound ----
    await start('signature', { audience: AUDIENCE, object: envelope('post', email) }, '__s1');
    const s1 = await outcome('__s1');
    expect(s1.ok, JSON.stringify(s1)).toBeTruthy();
    expect(s1.ok.signature).toMatch(/^[0-9a-f]+$/);
    expect(s1.ok.pubkey).toMatch(/^ed25519:[0-9a-f]{64}$/);
    const parts = String(s1.ok.presentation).split('~');
    expect(parts).toHaveLength(4);
    expect(parts[2]).toBe(w.ok.warrants[0]);
    const assertion = claimsOf(parts[1]);
    expect(assertion.req_origin).toBe(BROKER);
    expect(assertion.aud).toBe(AUDIENCE);

    // ---- 3. signature, prompt scope: decline, then approve ----
    popupP = page.context().waitForEvent('page');
    await start('signature', { audience: AUDIENCE, object: envelope('delete', email) }, '__s2');
    popup = await popupP;
    await popup.waitForSelector('#sign-prompt-screen.active', { timeout: 15000 });
    await expect(popup.locator('#sign-prompt-title')).toContainText('delete');
    await popup.click('#sign-prompt-decline');
    const s2 = await outcome('__s2');
    expect(s2.err?.error).toBe('denied');

    popupP = page.context().waitForEvent('page');
    await start('signature', { audience: AUDIENCE, object: envelope('delete', email) }, '__s3');
    popup = await popupP;
    await popup.waitForSelector('#sign-prompt-screen.active', { timeout: 15000 });
    await popup.click('#sign-prompt-approve');
    const s3 = await outcome('__s3');
    expect(s3.ok, JSON.stringify(s3)).toBeTruthy();

    // ---- 4. typed refusals ----
    await start('signature', { audience: 'sbo+raw://avail:turing:999/', object: envelope('post', email) }, '__s4');
    expect((await outcome('__s4')).err?.error).toBe('no_grant');
    await start('signature', { audience: AUDIENCE, object: envelope('transfer', email) }, '__s5');
    expect((await outcome('__s5')).err?.error).toBe('scope_not_granted');
    await start('bogus', {}, '__s6');
    expect((await outcome('__s6')).err?.error).toBe('unsupported_kind');
    await start('warrant', { grants: [] }, '__s7');
    expect((await outcome('__s7')).err?.error).toBe('bad_request');
  });

  test('admission: the resource files, the page hands over the code, the record arrives by poll', async ({ page, request }) => {
    test.setTimeout(120000);
    // The resource (audience origin == this page's origin) files over the
    // generic endpoint and never publishes the well-known proof.
    const audience = `${BROKER}/mcp-e2e-${uniqueId}`;
    const filed = await (await request.post(`${BROKER}/api/v1/requests`, { data: {
      kind: 'admission', type: 'connection', audience, scopes: ['tool:read_file'],
      client: { client_host: 'claude.ai', client_name: 'Claude' },
      return_url: `${BROKER}/authorize/return?st=e2e`,
    } })).json();
    expect(filed.code, JSON.stringify(filed)).toBeTruthy();
    expect((await (await request.get(`${BROKER}/api/v1/requests/${filed.code}`)).json()).status).toBe('pending');

    await page.goto('/');
    await page.addScriptTag({ url: `${BROKER}/include.js` });
    await page.waitForFunction(() => typeof (navigator as any).id?.request === 'function');
    const popupP = page.context().waitForEvent('page');
    await page.evaluate((code) => {
      const w = window as any;
      w.__a = { pending: true };
      (navigator as any).id.request('admission', { code }).then(
        (r: any) => { w.__a = { ok: r }; }, (e: any) => { w.__a = { err: e }; });
    }, filed.code);
    const popup = await popupP;
    await popup.waitForSelector('#email-screen.active', { timeout: 15000 });
    await new DialogPage(popup).signInExistingUser(email, password);
    await popup.waitForSelector('#admission-screen.active', { timeout: 20000 });
    await expect(popup.locator('#admission-title')).toContainText('Connect Claude to this site?');
    await expect(popup.locator('#admission-lead')).toContainText(audience);
    await expect(popup.locator('#admission-foot')).toContainText('as reported by the site');
    await popup.click('#admission-approve');
    await page.waitForFunction(() => !(window as any).__a.pending, undefined, { timeout: 30000 });
    const a = await page.evaluate(() => (window as any).__a);
    expect(a.ok, JSON.stringify(a)).toBeTruthy();
    expect(a.ok.status).toBe('approved');
    expect(a.ok.return_url).toContain('/authorize/return');
    // The page never saw the record; the resource's poll delivers it.
    expect(Object.keys(a.ok)).not.toContain('warrants');
    await new Promise(r => setTimeout(r, 5500)); // the lane's poll interval
    const poll = await (await request.get(`${BROKER}/api/v1/requests/${filed.code}`)).json();
    expect(poll.status, JSON.stringify(poll)).toBe('approved');
    const c = claimsOf(poll.grants[0].warrant.split('~')[0]);
    expect(c.typ).toBe('browserid-warrant-v2');
    expect(c.grantor).toBe(email);
    expect(c.binding.kind).toBe('connection');
    expect(c.binding.client_host).toBe('claude.ai');
    expect(c.audience).toBe(audience);
  });
});
