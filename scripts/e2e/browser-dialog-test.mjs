// REAL-BROWSER e2e of the ACCOUNT-BASED dialog on the device-cert model:
// 1. Cold start: /broker-demo → dialog → email → CREATE-ACCOUNT screen
//    (password + emailed code) → device issuance via the session → mint →
//    presentation → /verify-access okay.
// 2. Second login: dialog shows the EMAIL CHOOSER (all account identities,
//    radio list) → Sign In → verifies again (stored pair, no re-issue).
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';

const BASE = 'http://localhost:3199';
const LOG = new URL('./broker.log', import.meta.url).pathname;
const email = `browser-${Date.now()}@example.com`;
const PASS = 'e2e-passw0rd!';

const browser = await chromium.launch();
const ctx = await browser.newContext();
const page = await ctx.newPage();
page.on('console', (m) => { if (m.type() === 'error') console.log('[rp console]', m.text()); });

await page.goto(BASE + '/broker-demo');

// --- Login 1: cold start → create account ----------------------------------
const [dialog] = await Promise.all([
  page.waitForEvent('popup'),
  page.click('#login'),
]);
dialog.on('console', (m) => { if (m.type() === 'error') console.log('[dialog console]', m.text()); });
dialog.on('pageerror', (e) => console.log('[dialog pageerror]', e.message));

await dialog.waitForSelector('#email-screen.active', { timeout: 10000 });
await dialog.fill('#email', email);
await dialog.click('#email-form button[type=submit]');

// Unknown address → the create-account screen (password + confirm).
await dialog.waitForSelector('#create-screen.active', { timeout: 15000 });
console.log('✓ unknown email routed to the create-account screen');
await dialog.fill('#create-password', PASS);
await dialog.fill('#confirm-password', PASS);
await dialog.click('#create-form button[type=submit]');

// Code screen; scrape the staged-user code from the console email sender.
await dialog.waitForSelector('#verify-screen.active', { timeout: 15000 });
await new Promise((r) => setTimeout(r, 300));
const log = readFileSync(LOG, 'utf8');
const m = [...log.matchAll(new RegExp(`VERIFICATION CODE FOR: ${email.replace(/[+.]/g, '\\$&')}\\n\\s+CODE: (\\d{6})`, 'g'))].pop();
if (!m) { console.log('✗ no code in broker log'); process.exit(1); }
console.log('✓ create-account code screen; code', m[1]);
await dialog.fill('#verification-code', m[1]);
await dialog.click('#verify-form button[type=submit]');

await page.waitForFunction(
  () => document.getElementById('out').textContent.includes('"status"'),
  null, { timeout: 20000 }
);
const out1 = JSON.parse(await page.textContent('#out'));
const ok1 = out1.status === 'okay' && out1.email === email && (out1.grantee || out1.email) === email;
console.log(ok1 ? '✓ cold-start create-account login verified:' : '✗ FAILED:', JSON.stringify(out1));
if (!ok1) process.exit(1);

// --- Login 2: session → email chooser --------------------------------------
await page.evaluate(() => { document.getElementById('out').textContent = '(cleared)'; });
const [dialog2] = await Promise.all([
  page.waitForEvent('popup'),
  page.click('#login'),
]);
dialog2.on('pageerror', (e) => console.log('[dialog2 pageerror]', e.message));

// The signed-in chooser: radio list of ALL account identities.
await dialog2.waitForSelector('#pick-email-screen.active', { timeout: 10000 });
const listed = await dialog2.$$eval('#email-list input[name="selected-email"]', (els) => els.map((e) => e.value));
console.log('✓ chooser shown with account identities:', JSON.stringify(listed));
if (!listed.includes(email)) { console.log('✗ chooser missing the account email'); process.exit(1); }
await dialog2.click('#pick-email-form button[type=submit]');

await page.waitForFunction(
  () => document.getElementById('out').textContent.includes('"status"'),
  null, { timeout: 20000 }
);
const out2 = JSON.parse(await page.textContent('#out'));
const ok2 = out2.status === 'okay' && out2.email === email;
console.log(ok2 ? '✓ chooser login verified:' : '✗ chooser login FAILED:', JSON.stringify(out2));

await browser.close();
console.log(ok1 && ok2 ? '\nBROWSER TEST OK' : '\nBROWSER TEST FAILED');
process.exit(ok1 && ok2 ? 0 : 1);
