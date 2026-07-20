// REAL-BROWSER e2e of the FULL-PAGE REDIRECT fallback (Arc / blocked popups).
// window.open is stubbed to null so include.js's popup attempt reports
// 'popup blocked' and engages the redirect flow.
//
// Test A (fallback path): broker-demo → same-tab dialog → create-account
//   (password + emailed code) → redirect back with #browserid= → include
//   delivers via watch() → /verify-access okay.
// Test B (primary same-tab hop): mock primary IdP (registered via the test
//   endpoint) → dialog hops THIS TAB to the mock device-authorize page →
//   returns to /dialog/dialog.html?resume=device_auth with certs → dialog
//   finishes and redirects back to the RP. (Verification fails downstream —
//   the mock domain has no DNSSEC — but the whole navigation chain and
//   presentation delivery are asserted.)
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { webcrypto as crypto } from 'node:crypto';

const BASE = 'http://localhost:3199';
const LOG = new URL('./broker.log', import.meta.url).pathname;
let failed = false;
const must = (n, ok, d = '') => { console.log(`${ok ? '✓' : '✗'} ${n}${d ? ' — ' + d : ''}`); if (!ok) failed = true; };

// ---------- mock primary IdP ------------------------------------------------
const b64uj = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const HDR = b64uj({ alg: 'EdDSA', typ: 'JWT' });
const idpKp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
async function signJws(claims) {
  const p = b64uj(claims);
  const sig = Buffer.from(await crypto.subtle.sign({ name: 'Ed25519' }, idpKp.privateKey, new TextEncoder().encode(`${HDR}.${p}`))).toString('base64url');
  return `${HDR}.${p}.${sig}`;
}
const MOCK_DOMAIN = 'mockidp.test';
const hits = [];
const mock = createServer(async (req, res) => {
  hits.push(req.url.split('#')[0].split('?')[0]);
  const now = Math.floor(Date.now() / 1000);
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'POST, OPTIONS',
      'access-control-allow-headers': 'content-type, accept',
    });
    return res.end();
  }
  if (req.url.startsWith('/device-authorize')) {
    res.writeHead(200, { 'content-type': 'text/html' });
    // Auto-approving device-authorize page implementing the redirect-return
    // protocol: parse fragment, ask the server to issue for the pubkeys,
    // navigate back to return_url with the certs in the fragment.
    res.end(`<!doctype html><script>
      (async () => {
        const p = new URLSearchParams(location.hash.slice(1));
        const r = await fetch('/issue', { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email: p.get('email'), device_pubkey: p.get('device_pubkey'), config_pubkey: p.get('config_pubkey') }) });
        const b = await r.json();
        location.replace(p.get('return_url') + '#device_cert=' + encodeURIComponent(b.device_cert) + '&config_cert=' + encodeURIComponent(b.config_cert));
      })();
    </script>`);
  } else if (req.url.startsWith('/issue')) {
    let raw = ''; req.on('data', (c) => raw += c);
    req.on('end', async () => {
      const b = JSON.parse(raw);
      const device_cert = await signJws({ typ: 'browserid-device-cert-v1', iss: MOCK_DOMAIN, iat: now, exp: now + 86400 * 90, purpose: 'authentication', subject: 'user', identities: [b.email], 'public-key': { algorithm: 'Ed25519', publicKey: b.device_pubkey } });
      const config_cert = await signJws({ typ: 'browserid-device-cert-v1', iss: MOCK_DOMAIN, iat: now, exp: now + 86400 * 90, purpose: 'authorization', subject: 'user', identities: [b.email], 'public-key': { algorithm: 'Ed25519', publicKey: b.config_pubkey } });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ device_cert, config_cert }));
    });
  } else if (req.url.startsWith('/access/mint')) {
    let raw = ''; req.on('data', (c) => raw += c);
    req.on('end', async () => {
      const b = JSON.parse(raw);
      const areq = JSON.parse(Buffer.from(b.access_request.split('.')[1], 'base64url').toString());
      const access_cert = await signJws({ typ: 'browserid-access-cert-v1', iss: MOCK_DOMAIN, iat: now, exp: now + 86400, identity: areq.identity, subject: areq.subject, 'public-key': areq['access-key'] });
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
      res.end(JSON.stringify({ access_cert }));
    });
  } else { res.writeHead(404); res.end(); }
});
await new Promise((r) => mock.listen(3299, r));

// Register the mock primary with the local broker.
const reg = await fetch(BASE + '/wsapi/test/set_mock_primary_idp', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ domain: MOCK_DOMAIN, base_url: 'http://localhost:3299', auth_path: '/auth', prov_path: '/prov' }),
});
must('mock primary registered', reg.ok);

const browser = await chromium.launch();
// Fresh context per test (no shared broker session), window.open killed so
// include.js must fall back to redirect mode.
async function freshCtx() {
  const c = await browser.newContext();
  await c.addInitScript(() => { window.open = () => null; });
  return c;
}

// ---------- Test A: redirect fallback, create-account path ------------------
{
  const email = `redirect-${Date.now()}@example.com`;
  const ctx = await freshCtx();
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  await page.goto(BASE + '/broker-demo');
  await page.click('#login');
  await page.waitForURL('**/dialog/dialog.html?rp_redirect=1*', { timeout: 15000 });
  must('A: tab navigated to redirect-mode dialog', true);

  await page.waitForSelector('#email-screen.active', { timeout: 10000 });
  await page.fill('#email', email);
  await page.click('#email-form button[type=submit]');
  await page.waitForSelector('#create-screen.active', { timeout: 15000 });
  await page.fill('#create-password', 'redirect-pass1!');
  await page.fill('#confirm-password', 'redirect-pass1!');
  await page.click('#create-form button[type=submit]');
  await page.waitForSelector('#verify-screen.active', { timeout: 15000 });
  await new Promise((r) => setTimeout(r, 300));
  const log = readFileSync(LOG, 'utf8');
  const m = [...log.matchAll(new RegExp(`VERIFICATION CODE FOR: ${email.replace(/[+.]/g, '\\$&')}\\n\\s+CODE: (\\d{6})`, 'g'))].pop();
  must('A: code scraped', !!m);
  await page.fill('#verification-code', m[1]);
  await page.click('#verify-form button[type=submit]');

  // Dialog redirects back to broker-demo; include delivers via watch().
  await page.waitForURL('**/broker-demo', { timeout: 20000 });
  await page.waitForFunction(() => document.getElementById('out').textContent.includes('"status"'), null, { timeout: 20000 });
  const out = JSON.parse(await page.textContent('#out'));
  must('A: presentation delivered + verified after redirect return', out.status === 'okay' && out.email === email, JSON.stringify(out));
  must('A: fragment stripped from the URL', !page.url().includes('#browserid='));
  await ctx.close();
}

// ---------- Test B: primary same-tab hop ------------------------------------
{
  const email = `user@${MOCK_DOMAIN}`;
  const ctx = await freshCtx();
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  await page.goto(BASE + '/broker-demo');
  await page.click('#login');
  await page.waitForURL('**/dialog/dialog.html?rp_redirect=1*', { timeout: 15000 });
  await page.waitForSelector('#email-screen.active', { timeout: 10000 });
  await page.fill('#email', email);
  await page.click('#email-form button[type=submit]');

  // Same tab: dialog → mock device-authorize → dialog resume → back to RP.
  await page.waitForURL('**/broker-demo', { timeout: 30000 });
  must('B: full same-tab chain returned to the RP', true);
  must('B: mock device-authorize + issue + mint were exercised',
    hits.some((h) => h.startsWith('/device-authorize')) && hits.includes('/issue') && hits.some((h) => h.startsWith('/access/mint')),
    JSON.stringify(hits));
  await page.waitForFunction(() => document.getElementById('out').textContent.includes('"status"'), null, { timeout: 20000 });
  const out = JSON.parse(await page.textContent('#out'));
  // Verification legitimately fails (mockidp.test has no DNSSEC) — the point
  // is that a presentation ARRIVED through the whole redirect chain.
  must('B: a presentation was delivered through the chain', typeof out.status === 'string', JSON.stringify(out));
  await ctx.close();
}

await browser.close();
mock.close();
console.log(failed ? '\nREDIRECT E2E FAILED' : '\nREDIRECT E2E OK');
process.exit(failed ? 1 : 0);
