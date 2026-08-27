// Full-loop e2e: Electron wallet app + MV3 extension + local broker.
//   broker-demo page in Chromium (extension loaded) -> click sign in ->
//   extension routes to the app on 127.0.0.1:8873 -> app builds the
//   presentation -> page verifies via /verify -> logged in.
//
// Prereqs: local broker on :3000 (ADMIN_TOKEN=localtest-admin), then:
//   node e2e.mjs
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(here, '../../e2e-tests/package.json'));
const { chromium } = require('playwright');

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

// 2. launch the Electron wallet app (fresh userData, test lanes on)
const userData = fs.mkdtempSync('/tmp/wallet-e2e-');
const electron = require2('electron');
function require2(m) { return createRequire(path.join(here, 'app/package.json'))(m); }
const app = spawn(electron, ['.'], {
  cwd: path.join(here, 'app'),
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

// 3. bootstrap the wallet via the test lane
r = await fetch('http://127.0.0.1:8873/test/bootstrap', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-wallet-token': 'unpaired' },
  body: JSON.stringify({ email, pass }),
});
// /test/bootstrap sits behind the token gate; pair first if 401
if (r.status === 401) {
  const pairRes = await fetch('http://127.0.0.1:8873/pair', { method: 'POST' });
  const { token } = await pairRes.json();
  r = await fetch('http://127.0.0.1:8873/test/bootstrap', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-wallet-token': token },
    body: JSON.stringify({ email, pass }),
  });
}
const boot = await r.json();
must('wallet bootstrapped', r.status === 200 && boot.email === email, JSON.stringify(boot).slice(0, 120));

// 4. Chromium with the extension, on the broker-demo RP
const profile = fs.mkdtempSync('/tmp/wallet-e2e-profile-');
const extPath = path.join(here, 'extension');
const ctx = await chromium.launchPersistentContext(profile, {
  headless: false, // extensions need a headed (or --headless=new) browser
  args: [`--disable-extensions-except=${extPath}`, `--load-extension=${extPath}`],
});
const page = await ctx.newPage();
page.on('console', (m) => { if (m.type() === 'error' || m.text().includes('wallet')) console.log(`[page] ${m.text()}`); });
await page.goto(`${BROKER}/broker-demo`);

const shimActive = await page.evaluate(() => !!(navigator.id && navigator.id.__menubarWallet));
must('shim owns navigator.id (include.js did not displace it)', shimActive);

// 5. click sign in, expect logged-in UI without any popup
const pagesBefore = ctx.pages().length;
await page.click('#signin, button#login, [data-signin], button:has-text("Sign in")').catch(async () => {
  // fall back: click the first button on the page
  await page.click('button');
});
await page.waitForTimeout(4000);
const pagesAfter = ctx.pages().length;
must('no popup opened', pagesAfter === pagesBefore, `${pagesBefore} -> ${pagesAfter}`);

const bodyText = await page.evaluate(() => document.body.innerText);
must('page shows logged-in state with the email', bodyText.includes(email), bodyText.slice(0, 300).replace(/\n+/g, ' | '));

await ctx.close();
app.kill();
console.log(failed ? '\nE2E FAILED' : '\nE2E OK');
process.exit(failed ? 1 : 0);
