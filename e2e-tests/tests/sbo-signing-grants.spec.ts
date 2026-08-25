/**
 * SBO signing grants (spec §5/§7.5; audit M9, bean ttn3).
 *
 * The consent card mints a durable browserid-warrant-v2 record — binding set
 * {holder: this device, requester: the RP origin}, sign:sbo:* scopes with an
 * inline prompt-mode parameter, a registrar status ref — stores it for the
 * signer popup and registers it (ledger row). The popup signs ONLY under a
 * covering stored record: auto scopes silently, prompt scopes after an
 * in-window approval; everything else refuses with the typed error
 * vocabulary. Revocation flips the registry bit.
 *
 * The whole flow lives in one test: the record sits in the dialog's
 * first-party localStorage, which a fresh per-test context would drop.
 */
import { test, expect, generateTestPassword } from '../fixtures/test-helpers';

const BROKER = process.env.BROKER_URL || 'http://localhost:3000';
const AUDIENCE = 'sbo+raw://avail:turing:506/';
const REQUEST = {
  audiences: [AUDIENCE],
  scopes: ['sign:sbo:post', { scope: 'sign:sbo:delete', mode: 'prompt' }],
};
const REQUEST_B64 = Buffer.from(JSON.stringify(REQUEST)).toString('base64url');

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

test.describe('SBO signing grants', () => {
  const uniqueId = `${Date.now()}-${Math.random().toString(36).substring(7)}`;
  const email = `sbo-grant-${uniqueId}@example.com`;
  const password = generateTestPassword();

  test.beforeAll(async ({ request }) => {
    const stage = await request.post(`${BROKER}/wsapi/stage_signin_code`, {
      data: { email, pass: password },
    });
    expect(stage.ok()).toBeTruthy();
    const pending = await request
      .get(`${BROKER}/wsapi/test/pending_verification?email=${encodeURIComponent(email)}&type=signin_code`)
      .then(r => r.json());
    expect(pending.code).toBeDefined();
    const done = await request.post(`${BROKER}/wsapi/complete_signin_code`, {
      data: { email, token: pending.code },
    });
    expect(done.ok()).toBeTruthy();
  });

  test('consent mints the record; the popup enforces it end to end', async ({ page, dialogPage }) => {
    test.setTimeout(120000);

    // ---- 1. Consent: dialog with a declared grant request ----
    await page.goto(
      `/dialog/dialog.html?origin=${encodeURIComponent(BROKER)}&sbo_request=${REQUEST_B64}`
    );
    await page.waitForSelector('#email-screen.active', { timeout: 10000 });
    await dialogPage.signInExistingUser(email, password);
    await page.waitForSelector('#sbo-consent-screen.active', { timeout: 20000 });

    // The card states the standing authority plainly, per scope.
    await expect(page.locator('#sbo-consent-audiences')).toContainText(AUDIENCE);
    await expect(page.locator('#sbo-consent-scopes')).toContainText('signed automatically');
    await expect(page.locator('#sbo-consent-scopes')).toContainText('approve each one');
    await expect(page.locator('#sbo-consent-screen .email-display')).toContainText(email);

    await page.click('#sbo-consent-allow');
    await page.waitForSelector('#success-screen.active', { timeout: 20000 });

    // ---- 2. The stored record is a well-formed signing grant ----
    const stored = await page.evaluate(
      ([origin, aud]) => {
        const si = JSON.parse(localStorage.getItem('siteInfo') || '{}');
        const jws = si[origin]?.signing_grants?.[aud];
        if (!jws) return null;
        const claims = JSON.parse(atob(jws.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        // The retired boolean must not resurface.
        const legacy = !!si[origin]?.sbo_sign_granted;
        return { jws, claims, legacy };
      },
      [BROKER, AUDIENCE] as const
    );
    expect(stored).not.toBeNull();
    const c = stored!.claims;
    expect(stored!.legacy).toBe(false);
    expect(c.typ).toBe('browserid-warrant-v2');
    expect(c.grantor).toBe(email);
    expect(c.grantee).toBe(email);
    expect(Array.isArray(c.binding)).toBe(true);
    expect(c.binding.map((e: any) => e.kind).sort()).toEqual(['holder', 'requester']);
    expect(c.binding.find((e: any) => e.kind === 'requester').origin).toBe(BROKER);
    expect(c.binding.find((e: any) => e.kind === 'holder').matcher).toMatch(/\S/);
    expect(c.scopes).toEqual(REQUEST.scopes);
    expect(typeof c.status?.idx).toBe('number');

    // ---- 3. Registered: the ledger row carries the requester origin ----
    const warrants = await page.request.get(`${BROKER}/wsapi/warrants`).then(r => r.json());
    const row = (warrants.warrants || []).find((w: any) => w.audience === AUDIENCE);
    expect(row).toBeTruthy();
    expect(row.requester_origin).toBe(BROKER);
    expect(row.status_idx).not.toBeNull();
    expect(row.warrant).toBe(stored!.jws);

    // ---- 4. Open the signer popup from a broker-origin RP page ----
    await page.goto('/');
    const popupPromise = page.waitForEvent('popup');
    await page.evaluate((broker) => {
      const w = window as any;
      w.__signs = new Map();
      w.__readyResolve = null;
      w.__ready = new Promise((res) => { w.__readyResolve = res; });
      window.addEventListener('message', (e: any) => {
        const d = e.data || {};
        if (d.type === 'sbo:signer-ready') { w.__readyResolve(); return; }
        const p = d.id != null && w.__signs.get(d.id);
        if (p) { w.__signs.delete(d.id); p(d); }
      });
      w.__signer = window.open(broker + '/sign', 'sbo-signer', 'width=380,height=360');
    }, BROKER);
    const popup = await popupPromise;
    await page.evaluate(() => (window as any).__ready);

    const send = (msg: any) =>
      page.evaluate(
        ([broker, m]) =>
          new Promise((res) => {
            const w = window as any;
            w.__signs.set(m.id, res);
            w.__signer.postMessage(m, broker);
          }),
        [BROKER, msg] as const
      ) as Promise<any>;

    // ---- 5. Auto scope: a post signs silently, stamped and bound ----
    const signed = await send({ type: 'sbo:sign', id: 1, email, envelope: envelope('post', email), audience: AUDIENCE });
    expect(signed.type).toBe('sbo:signed');
    expect(signed.signature).toMatch(/^[0-9a-f]+$/);
    const parts = String(signed.cert).split('~');
    expect(parts).toHaveLength(4);
    // The presentation carries the STORED warrant (never a fabricated one)…
    expect(parts[2]).toBe(stored!.jws);
    // …and the fresh assertion stamps the requesting origin (invariant 13).
    const assertion = JSON.parse(
      Buffer.from(parts[1].split('.')[1], 'base64url').toString()
    );
    expect(assertion.req_origin).toBe(BROKER);
    expect(assertion.aud).toBe(AUDIENCE);

    // ---- 6. Typed refusals: wrong audience, ungranted scope ----
    const wrongAud = await send({
      type: 'sbo:sign', id: 2, email, envelope: envelope('post', email),
      audience: 'sbo+raw://avail:turing:999/',
    });
    expect(wrongAud.type).toBe('sbo:sign-error');
    expect(wrongAud.error).toBe('not_granted');

    const wrongScope = await send({
      type: 'sbo:sign', id: 3, email, envelope: envelope('transfer', email), audience: AUDIENCE,
    });
    expect(wrongScope.type).toBe('sbo:sign-error');
    expect(wrongScope.error).toBe('scope_not_granted');

    // ---- 7. Prompt scope: decline, then approve ----
    const declineP = send({ type: 'sbo:sign', id: 4, email, envelope: envelope('delete', email), audience: AUDIENCE });
    await popup.waitForSelector('#prompt.active', { timeout: 10000 });
    await expect(popup.locator('#prompt-title')).toContainText('delete');
    await popup.click('#prompt-decline');
    const declined = await declineP;
    expect(declined.type).toBe('sbo:sign-error');
    expect(declined.error).toBe('prompt_declined');

    const approveP = send({ type: 'sbo:sign', id: 5, email, envelope: envelope('delete', email), audience: AUDIENCE });
    await popup.waitForSelector('#prompt.active', { timeout: 10000 });
    await popup.click('#prompt-approve');
    const approved = await approveP;
    expect(approved.type).toBe('sbo:signed');

    // ---- 8. Grant introspection: the asking origin's facts only ----
    const info = await send({ type: 'sbo:grant-info', id: 6 });
    expect(info.type).toBe('sbo:grant-info');
    expect(info.grants).toHaveLength(1);
    expect(info.grants[0]).toMatchObject({ email, audience: AUDIENCE });
    expect(info.grants[0].scopes).toEqual(REQUEST.scopes);

    // ---- 9. Revocation flips the registry bit ----
    const ctx = await page.request.get(`${BROKER}/wsapi/session_context`).then(r => r.json());
    const revoke = await page.request.post(`${BROKER}/wsapi/revoke_warrant`, {
      data: { csrf: ctx.csrf_token, id: row.id },
    });
    expect(revoke.ok()).toBeTruthy();
    const after = await page.request.get(`${BROKER}/wsapi/warrants`).then(r => r.json());
    const revokedRow = (after.warrants || []).find((w: any) => w.id === row.id);
    expect(revokedRow.revoked).toBe(true);
  });

  test('a boolean sboSign request grants nothing', async ({ page, dialogPage }) => {
    // The legacy lane: sbo_sign=1 no longer declares a grant request — the
    // consent card never shows and the response reports no grant.
    await page.goto(`/dialog/dialog.html?origin=${encodeURIComponent(BROKER)}&sbo_sign=1`);
    await page.waitForSelector('#email-screen.active', { timeout: 10000 });
    await dialogPage.signInExistingUser(email, password);
    await page.waitForSelector('#success-screen.active', { timeout: 20000 });
    const grants = await page.evaluate((origin) => {
      const si = JSON.parse(localStorage.getItem('siteInfo') || '{}');
      return {
        legacy: !!si[origin]?.sbo_sign_granted,
        count: Object.keys(si[origin]?.signing_grants || {}).length,
      };
    }, BROKER);
    expect(grants.legacy).toBe(false);
    expect(grants.count).toBe(0);
  });
});
