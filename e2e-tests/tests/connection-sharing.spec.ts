/**
 * Connection warrants end to end (spec §5/§6.4/§6.5/§7.5, bean aaka):
 * a credential-less gate; the OWNER shares to the MEMBER's email at the
 * broker's authoring consent card; the MEMBER connects through a simulated
 * OAuth host and approves the CONNECTION consent card; a real tool call runs
 * attributed to the member under the owner's grant, scoped to S ∩ S′; then
 * both revocation axes — the member kills their own connection (and can
 * reconnect), the owner kills the member's access entirely.
 *
 * Both consent cards are driven in a REAL browser: keystore config-cert
 * self-heal + client-side browserid-warrant-v2 signing included.
 */
import { test, expect } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';

const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
const GATE_PORT = 43510;
const ADMIN_PORT = GATE_PORT + 1;
const CATCHER_PORT = 43513;
const GATE = `http://127.0.0.1:${GATE_PORT}`;
const ADMIN = `http://127.0.0.1:${ADMIN_PORT}`;
const REDIRECT = `http://127.0.0.1:${CATCHER_PORT}/cb`;

async function createAccount(request: any) {
  const email = `share-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.test`;
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

/** Revoke a registry row through the account session (the wsapi the account
 *  page's Revoke button posts). */
async function revokeWarrant(page: any, pick: (w: any) => boolean) {
  const ctx = await (await page.request.get(`${baseUrl}/wsapi/session_context`)).json();
  const list = await (await page.request.get(`${baseUrl}/wsapi/warrants`)).json();
  const row = (list.warrants || []).find(pick);
  expect(row, `no matching warrant row in ${JSON.stringify(list.warrants?.map((w: any) => ({ id: w.id, audience: w.audience, binding: w.binding_id })))}`).toBeTruthy();
  const r = await page.request.post(`${baseUrl}/wsapi/revoke_warrant`, {
    data: { csrf: ctx.csrf_token, id: row.id },
  });
  expect(r.ok()).toBeTruthy();
  return row;
}

const pkce = () => {
  const verifier = randomBytes(48).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier, 'ascii').digest('base64url') };
};

let gate: ChildProcess;
let catcher: Server;
let caughtCode: ((code: string) => void) | null = null;

test.beforeAll(async () => {
  // The simulated OAuth host's redirect catcher.
  catcher = createServer((rq, res) => {
    const u = new URL(rq.url || '/', REDIRECT);
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<title>host callback</title>ok — you can close this tab');
    if (u.pathname === '/cb' && caughtCode) {
      const err = u.searchParams.get('error');
      caughtCode(err ? `ERROR:${err}:${u.searchParams.get('error_description')}` : u.searchParams.get('code')!);
      caughtCode = null;
    }
  });
  await new Promise<void>((r) => catcher.listen(CATCHER_PORT, r));
});

test.afterAll(async () => {
  gate?.kill();
  await new Promise((r) => catcher.close(r));
});

/** One full member connect: DCR + PKCE authorize → the member approves the
 *  connection card in their browser → code lands on the catcher → tokens. */
async function connectMember(memberPage: any, request: any) {
  const reg = await (
    await request.post(`${GATE}/register`, { data: { redirect_uris: [REDIRECT], client_name: 'Claude' } })
  ).json();
  const p = pkce();
  const codePromise = new Promise<string>((resolve) => { caughtCode = resolve; });
  await memberPage.goto(
    `${GATE}/authorize?client_id=${reg.client_id}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
      `&response_type=code&code_challenge=${p.challenge}&code_challenge_method=S256&state=h1` +
      `&scope=${encodeURIComponent('tool:read_text_file tool:list_directory')}`
  );
  // The broker's CONNECTION consent card: names the connection, marks the
  // client name as the site's own report, and shows the full audience.
  await expect(memberPage.locator('#list .pvcard')).toContainText('Connect Claude to this site?');
  await expect(memberPage.locator('#list .pvcard')).toContainText('127.0.0.1');
  await expect(memberPage.locator('#list .pvcard')).toContainText('as reported by the site');
  await memberPage.click('button.approve:enabled', { timeout: 5000 });
  // The page signs the v2 record, then auto-bounces through the gate's
  // return leg to the host redirect (the catcher).
  const code = await codePromise;
  expect(code, code).not.toMatch(/^ERROR:/);
  const tok = await (
    await request.post(`${GATE}/token`, {
      data: {
        grant_type: 'authorization_code',
        code,
        client_id: reg.client_id,
        redirect_uri: REDIRECT,
        code_verifier: p.verifier,
      },
    })
  ).json();
  return tok;
}

const callTool = (request: any, token: string, name: string, args: any) =>
  request.post(`${GATE}/mcp`, {
    headers: { authorization: `Bearer ${token}`, accept: 'application/json, text/event-stream' },
    data: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
  });

test('owner shares to a member email; member connects, works under S ∩ S′, both sides can revoke', async ({ browser, request }) => {
  test.setTimeout(180000);
  const owner = await createAccount(request);
  const member = await createAccount(request);

  // Boot the credential-less gate with the owner pinned as policy authority.
  gate = spawn(process.execPath, [join(__dirname, '..', 'fixtures', 'gate-server.mjs'), String(GATE_PORT), baseUrl, owner.email], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise<void>((resolve, reject) => {
    gate.stdout!.on('data', (d) => { if (String(d).includes('READY')) resolve(); });
    gate.on('exit', (c) => reject(new Error(`gate exited ${c}`)));
    setTimeout(() => reject(new Error('gate boot timeout')), 30000);
  });

  const ownerCtx = await browser.newContext();
  const memberCtx = await browser.newContext();
  const ownerPage = await ownerCtx.newPage();
  const memberPage = await memberCtx.newPage();
  await signIn(ownerPage, owner.email, owner.pass);
  await signIn(memberPage, member.email, member.pass);

  // 1. OWNER SHARES: the gate raises the authoring ceremony; the owner signs
  //    the policy record at the broker's consent card.
  const share = await (
    await request.post(`${ADMIN}/share`, { data: { grantee: member.email, scopes: ['tool:read_text_file'] } })
  ).json();
  expect(share.consent_uri).toContain(`${baseUrl}/consent/`);
  await ownerPage.goto(share.consent_uri);
  await expect(ownerPage.locator('#list .pvcard')).toContainText('Sign this access grant?');
  await expect(ownerPage.locator('#list .pvcard')).toContainText(member.email);
  await ownerPage.click('button.approve:enabled', { timeout: 5000 });
  await expect(ownerPage.locator('#list .status.ok')).toContainText('Approved', { timeout: 15000 });
  await expect.poll(async () => JSON.stringify(await (await request.get(`${ADMIN}/share/${share.request_id}`)).json()), { timeout: 15000 }).toContain('"done"');

  // 2. MEMBER CONNECTS and works — scoped to S ∩ S′ (read yes, list no).
  const tokens = await connectMember(memberPage, request);
  expect(tokens.access_token, JSON.stringify(tokens)).toBeTruthy();
  expect(tokens.scope).toBe('tool:read_text_file');
  expect(tokens.refresh_token).toMatch(/^mrt_/);
  const ok = await callTool(request, tokens.access_token, 'read_text_file', { path: 'hello.txt' });
  expect(await ok.text()).toContain('shared notes from the vault');
  const denied = await callTool(request, tokens.access_token, 'list_directory', { path: '.' });
  expect(await denied.text()).toContain('INSUFFICIENT_SCOPE');

  // 3. MEMBER-SIDE REVOCATION: the member kills their own connection at
  //    their account; the live bearer dies fail-closed and refresh mints
  //    nothing — but the policy grant survives, so RECONNECTING works.
  await revokeWarrant(memberPage, (w) => !!w.binding_id && String(w.audience).startsWith(GATE));
  await expect.poll(async () => (await callTool(request, tokens.access_token, 'read_text_file', { path: 'hello.txt' })).status(), { timeout: 15000 }).toBe(401);
  const deadRefresh = await (
    await request.post(`${GATE}/token`, { data: { grant_type: 'refresh_token', refresh_token: tokens.refresh_token } })
  ).json();
  expect(deadRefresh.error).toBe('invalid_grant');
  const tokens2 = await connectMember(memberPage, request);
  expect(tokens2.access_token, JSON.stringify(tokens2)).toBeTruthy();
  const okAgain = await callTool(request, tokens2.access_token, 'read_text_file', { path: 'hello.txt' });
  expect(await okAgain.text()).toContain('shared notes from the vault');

  // 4. OWNER-SIDE REVOCATION: the owner revokes the policy record; the
  //    member's access dies everywhere — live bearer (dual status refs,
  //    fail-closed), refresh (freshness-backed mint), and any new connect.
  await revokeWarrant(ownerPage, (w) => !w.binding_id && String(w.audience).startsWith(GATE));
  await expect.poll(async () => (await callTool(request, tokens2.access_token, 'read_text_file', { path: 'hello.txt' })).status(), { timeout: 15000 }).toBe(401);
  const deadRefresh2 = await (
    await request.post(`${GATE}/token`, { data: { grant_type: 'refresh_token', refresh_token: tokens2.refresh_token } })
  ).json();
  expect(deadRefresh2.error).toBe('invalid_grant');

  await ownerCtx.close();
  await memberCtx.close();
});
