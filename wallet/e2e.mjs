// Full-loop e2e: Electron wallet app + MV3 extension + local broker.
//   The e2e serves its OWN tiny RP page (cross-origin from the broker, like
//   a real site). Chromium (extension loaded) -> click sign in -> extension
//   routes to the app on 127.0.0.1:8873 -> app builds the presentation ->
//   the RP's server lane verifies via the broker's /verify -> logged in.
//   Plus the registry-API lane: the wallet's inbox poll and warrant
//   allocation/registration run over token+proof, no cookies.
//
// Prereqs: local broker on :3000 (DISABLE_SMTP=1 AGENT_PROVISIONING=1
// ADMIN_TOKEN=localtest-admin cargo run -p browserid-broker), then:
//   node e2e.mjs
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(here, '../e2e-tests/package.json'));
const { chromium } = require('playwright');
const requireLocal = createRequire(path.join(here, 'package.json'));

const BROKER = process.env.WALLET_BROKER || 'http://localhost:3000';
const ADMIN = process.env.ADMIN_TOKEN || 'localtest-admin';
const email = `wallet-e2e-${Date.now()}@example.com`;
const pass = 'wallet-e2e-passw0rd!';

let failed = false;
const must = (name, ok, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failed = true;
};

// 1. seed a broker account
let r = await fetch(`${BROKER}/admin/create_account`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-admin-token': ADMIN },
  body: JSON.stringify({ email, pass }),
});
must('seed account', r.status === 200);

// 2. launch the Electron wallet app (fresh userData, test lanes on).
// The port must be free FIRST: a leftover wallet instance (e.g. the
// packaged app from interactive testing) also answers /status, and the
// suite then talks to the wrong process and fails with "unknown endpoint"
// on the /test/* lanes. Fail loudly instead.
try {
  await fetch('http://127.0.0.1:8873/status');
  must('port 8873 free before spawn', false,
    'another wallet instance is already listening — kill it (lsof -ti :8873) and re-run');
  process.exit(1);
} catch { /* free — good */ }
const userData = fs.mkdtempSync('/tmp/wallet-e2e-');
const electron = requireLocal('electron');
const app = spawn(electron, ['.'], {
  cwd: here,
  env: {
    ...process.env,
    WALLET_BROKER: BROKER, WALLET_TEST: '1', WALLET_AUTO_APPROVE: '1',
    ELECTRON_USER_DATA: userData,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
app.stdout.on('data', (d) => process.stdout.write(`[app] ${d}`));
app.stderr.on('data', (d) => process.stderr.write(`[app!] ${d}`));

// wait for the localhost server
let up = false;
for (let i = 0; i < 40; i++) {
  try { await fetch('http://127.0.0.1:8873/status'); up = true; break; }
  catch { await new Promise((s) => setTimeout(s, 250)); }
}
must('wallet app server up', up);

// pair (test lanes sit behind the token gate too)
const pairRes = await fetch('http://127.0.0.1:8873/pair', { method: 'POST' });
const { token: walletToken } = await pairRes.json();
const wallet = (p, body) =>
  fetch(`http://127.0.0.1:8873${p}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'content-type': 'application/json', 'x-wallet-token': walletToken },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

// 3. bootstrap via the password test lane (single-login secondary path)
r = await wallet('/test/bootstrap', { email, pass });
const boot = await r.json();
must('wallet bootstrapped (single login at the issuer)', r.status === 200 && boot.email === email,
  JSON.stringify(boot).slice(0, 120));

// 4. registry API lane: the approvals inbox over token+proof (no cookies)
r = await wallet('/test/inbox', {});
const inbox = await r.json();
must('inbox over the registry token lane', r.status === 200 && Array.isArray(inbox.requests),
  JSON.stringify(inbox).slice(0, 120));
must('inbox names the status list', typeof inbox.status_uri === 'string' && inbox.status_uri.includes('browserid-status'));

// 4b. §5.4 lane: the wallet renames its own holder from the UA product-token
//     default ("BrowserID-Wallet") to a friendly per-OS label.
r = await wallet('/test/label', {});
const lab = await r.json();
must('device label healed to a friendly name', r.status === 200 && /^Wallet on /.test(lab.label || ''),
  JSON.stringify(lab));

// 5. A tiny RP of our own, cross-origin from the broker (client page +
//    server-side verify lane, the realistic RP shape).
const RP_PORT = 8899;
const RP_ORIGIN = `http://127.0.0.1:${RP_PORT}`;
const rpHtml = `<!doctype html><html><body>
<h1>Wallet E2E RP</h1>
<pre id="out">(not signed in)</pre>
<p><button id="login">Sign in</button></p>
<script src="${BROKER}/include.js"></script>
<script>
  var out = document.getElementById('out');
  navigator.id.watch({ loggedInUser: null,
    onlogin: function (p) {
      out.textContent = 'verifying…';
      fetch('/verify-local', { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ presentation: p }) })
        .then(function (r) { return r.json(); })
        .then(function (j) { out.textContent = JSON.stringify(j, null, 2); });
    },
    onlogout: function () {} });
  document.getElementById('login').onclick = function () {
    navigator.id.request({ siteName: 'Wallet E2E RP' });
  };
</script></body></html>`;
const rp = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/verify-local') {
    let body = '';
    for await (const c of req) body += c;
    const v = await fetch(`${BROKER}/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ presentation: JSON.parse(body).presentation, audience: RP_ORIGIN }),
    });
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(await v.json()));
  } else {
    res.setHeader('content-type', 'text/html');
    res.end(rpHtml);
  }
});
await new Promise((s) => rp.listen(RP_PORT, '127.0.0.1', s));

// 6. Chromium with the extension, on our RP
const profile = fs.mkdtempSync('/tmp/wallet-e2e-profile-');
const extPath = path.join(here, 'extension');
const ctx = await chromium.launchPersistentContext(profile, {
  headless: false, // extensions need a headed (or --headless=new) browser
  args: [`--disable-extensions-except=${extPath}`, `--load-extension=${extPath}`],
});
const page = await ctx.newPage();
page.on('console', (m) => { if (m.type() === 'error' || m.text().includes('wallet')) console.log(`[page] ${m.text()}`); });
await page.goto(`${RP_ORIGIN}/`);

const shimActive = await page.evaluate(() => !!(navigator.id && navigator.id.__menubarWallet));
must('shim owns navigator.id (include.js did not displace it)', shimActive);

// 7. click sign in, expect logged-in UI without any popup
const pagesBefore = ctx.pages().length;
await page.click('button#login');
await page.waitForTimeout(4000);
const pagesAfter = ctx.pages().length;
must('no popup opened', pagesAfter === pagesBefore, `${pagesBefore} -> ${pagesAfter}`);

const bodyText = await page.evaluate(() => document.body.innerText);
must('page shows logged-in state with the email', bodyText.includes(email), bodyText.slice(0, 300).replace(/\n+/g, ' | '));

// 8. The login's site warrant closed the prototype gap: it carries an
//    allocated status ref (per-site revocation bit) and was registered.
//    NOTE: the extension paired itself during the click, which ROTATED the
//    pairing token (single-token model) — re-pair before asking.
const repair = await (await fetch('http://127.0.0.1:8873/pair', { method: 'POST' })).json();
const wallet2 = (p, body) =>
  fetch(`http://127.0.0.1:8873${p}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-wallet-token': repair.token },
    body: JSON.stringify(body),
  });
r = await wallet2('/test/state', {});
const state = await r.json();
const ref = (state.warrantRefs || {})[RP_ORIGIN];
must('site warrant has an allocated status ref', !!ref && typeof ref.idx === 'number', JSON.stringify(ref));
const siteWarrant = (state.warrants || {})[RP_ORIGIN];
const wClaims = siteWarrant
  ? JSON.parse(Buffer.from(siteWarrant.split('.')[1], 'base64url').toString())
  : {};
must('signed warrant embeds the ref', !!wClaims.status && wClaims.status.idx === ref?.idx,
  JSON.stringify(wClaims.status));
must('keys never leave the app (/test/state redacts them)', !('deviceKey' in state) && !('configKey' in state));

// 9. Hostile callers are refused (b8q0/bd19 hardening).
//    9a. Server-side origin gate: a request carrying a non-allowlisted web
//    origin is 403'd before the pairing dialog can fire — the current token
//    survives (a processed /pair would have rotated it, AUTO_APPROVE is on).
r = await fetch('http://127.0.0.1:8873/pair', {
  method: 'POST', headers: { origin: 'https://evil.example' },
});
must('web-origin /pair refused', r.status === 403);
must('refusal happened before pairing (token not rotated)',
  (await wallet2('/test/state', {})).status === 200);

//    9b. Same gate on the token lane: a valid token presented from a
//    disallowed origin is still refused.
r = await fetch('http://127.0.0.1:8873/status', {
  headers: { origin: 'https://evil.example', 'x-wallet-token': repair.token },
});
must('web-origin token use refused', r.status === 403);

//    9c. Token↔origin binding: a token paired under one origin is refused
//    from another (here: paired with no origin, replayed as an extension).
r = await fetch('http://127.0.0.1:8873/status', {
  headers: { origin: `chrome-extension://${'a'.repeat(32)}`, 'x-wallet-token': repair.token },
});
must('token bound to pairing origin', r.status === 401);

//    9d. CORS reflects the specific allowed caller — never *.
must('no wildcard CORS on allowed callers',
  r.headers.get('access-control-allow-origin') === `chrome-extension://${'a'.repeat(32)}`);

//    9e. A real cross-origin web page in the browser can't reach the bridge.
const evil = await ctx.newPage();
await evil.route('http://evil.example/', (route) =>
  route.fulfill({ contentType: 'text/html', body: '<!doctype html><h1>evil</h1>' }));
await evil.goto('http://evil.example/');
const evilResult = await evil.evaluate(() =>
  fetch('http://127.0.0.1:8873/pair', { method: 'POST' })
    .then((r) => `reachable:${r.status}`, (e) => `blocked:${e.name}`));
must('hostile web page cannot drive /pair', evilResult.startsWith('blocked:'), evilResult);
must('hostile page attempt did not rotate the token',
  (await wallet2('/test/state', {})).status === 200);

await ctx.close();
rp.close();
app.kill();
console.log(failed ? '\nE2E FAILED' : '\nE2E OK');
process.exit(failed ? 1 : 0);
