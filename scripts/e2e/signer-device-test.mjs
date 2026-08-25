// e2e for the DEVICE-MODEL SBO signer (/sign popup): log in (deposits device
// certs), grant the origin, drive /sign with a real SBO envelope + audience,
// and verify the returned PRESENTATION via /verify (proves the browserid
// half — access-cert mint, warrant, join, access-key binding). The envelope
// signature itself is sbo-wasm/daemon territory; here we prove the presentation.
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';

const BASE = 'http://localhost:3199';
const LOG = new URL('./broker.log', import.meta.url).pathname;
const email = `signer-${Date.now()}@example.com`;
const AUDIENCE = 'sbo+raw://avail:turing:506/';
let failed = false;
const must = (n, ok, d = '') => { console.log(`${ok ? '✓' : '✗'} ${n}${d ? ' — ' + d : ''}`); if (!ok) failed = true; };

const browser = await chromium.launch();
const ctx = await browser.newContext();
const page = await ctx.newPage();
page.on('pageerror', (e) => console.log('[page]', e.message));

// 1. Log in on broker-demo (same origin as the broker locally) → device certs
//    land in the broker keystore.
await page.goto(BASE + '/broker-demo');
const [dialog] = await Promise.all([ page.waitForEvent('popup'), page.click('#login') ]);
await dialog.waitForSelector('#email-screen.active', { timeout: 10000 });
await dialog.fill('#email', email);
await dialog.click('#email-form button[type=submit]');
await dialog.waitForSelector('#create-screen.active', { timeout: 15000 });
await dialog.fill('#create-password', 'signer-pass1!');
await dialog.fill('#confirm-password', 'signer-pass1!');
await dialog.click('#create-form button[type=submit]');
await dialog.waitForSelector('#verify-screen.active', { timeout: 15000 });
await new Promise((r) => setTimeout(r, 300));
const m = [...readFileSync(LOG, 'utf8').matchAll(new RegExp(`VERIFICATION CODE FOR: ${email.replace(/[+.]/g, '\\$&')}\\n\\s+CODE: (\\d{6})`, 'g'))].pop();
await dialog.fill('#verification-code', m[1]);
await dialog.click('#verify-form button[type=submit]');
await page.waitForFunction(() => document.getElementById('out').textContent.includes('"status"'), null, { timeout: 20000 });
must('logged in (device certs deposited)', JSON.parse(await page.textContent('#out')).status === 'okay');

// 2. Grant this origin SBO signing (what the dialog's SBO-consent screen sets).
await page.evaluate(() => {
  const s = JSON.parse(localStorage.getItem('siteInfo') || '{}');
  s[location.origin] = s[location.origin] || {};
  s[location.origin].sbo_sign_granted = true;
  localStorage.setItem('siteInfo', JSON.stringify(s));
});

// 3. Drive the signer popup from the page (same origin → grant applies).
const result = await page.evaluate(async ({ email, audience }) => {
  const wasm = await import('/common/js/sbo-wasm/sbo_wasm.js').then((m) => Promise.resolve(m.default && m.default()).then(() => m));
  // A minimal owned content write spec (the shape mingo builds).
  const payload = wasm.payloadPost('hello from the device signer', null, BigInt(Math.floor(Date.now() / 1000)));
  const spec = {
    action: '', path: `/u/${email}/posts/`, id: 'p-' + Date.now(),
    public_key: 'ed25519:' + '00'.repeat(32), // set by the signer
    content_schema: 'post.v1', payload: Array.from(payload),
    hlc: `${Date.now()}.0`, prev: null, owner: email,
    content_type: 'application/json'
  };
  const signer = window.open('/sign', 'sbo-signer', 'width=360,height=200');
  await new Promise((res, rej) => {
    const to = setTimeout(() => rej(new Error('signer never ready')), 15000);
    window.addEventListener('message', function onready(e) {
      if (e.source === signer && e.data && e.data.type === 'sbo:signer-ready') {
        clearTimeout(to); window.removeEventListener('message', onready); res();
      }
    });
  });
  const signed = await new Promise((res, rej) => {
    const to = setTimeout(() => rej(new Error('sign timeout')), 20000);
    window.addEventListener('message', function onsigned(e) {
      if (e.source !== signer || !e.data) return;
      if (e.data.type === 'sbo:signed') { clearTimeout(to); window.removeEventListener('message', onsigned); res(e.data); }
      else if (e.data.type === 'sbo:sign-error') { clearTimeout(to); window.removeEventListener('message', onsigned); rej(new Error(e.data.error + ': ' + e.data.message)); }
    });
    signer.postMessage({ type: 'sbo:sign', id: 1, email, envelope: spec, audience }, location.origin);
  });
  return { signature: signed.signature, cert: signed.cert, pubkey: signed.pubkey };
}, { email, audience: AUDIENCE });

must('signer returned a signature', !!result.signature && /^[0-9a-f]+$/.test(result.signature));
must('pubkey is ed25519:<hex> (the access key)', /^ed25519:[0-9a-f]{64}$/.test(result.pubkey), result.pubkey);
must('cert is a 4-object presentation', (result.cert.match(/~/g) || []).length === 3);

// 4. The presentation must verify at the SBO audience as the user themself
//    (as-you: grantee == email).
const v = await page.evaluate(async ({ cert, audience }) => {
  const r = await fetch('/verify', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ presentation: cert, audience })
  });
  return r.json();
}, { cert: result.cert, audience: AUDIENCE });
must('presentation verifies at the SBO audience', v.status === 'okay' && v.email === email && (v.grantee || v.email) === email, JSON.stringify(v));

// 5. The verified access key must match the signer's returned pubkey.
const accessKeyB64 = JSON.parse(Buffer.from(result.cert.split('~')[0].split('.')[1], 'base64url').toString())['public-key'].publicKey;
const accessHex = 'ed25519:' + Buffer.from(accessKeyB64, 'base64url').toString('hex');
must('returned pubkey == access cert key (envelope-signer binding)', accessHex === result.pubkey);

await browser.close();
console.log(failed ? '\nSIGNER TEST FAILED' : '\nSIGNER TEST OK');
process.exit(failed ? 1 : 0);
