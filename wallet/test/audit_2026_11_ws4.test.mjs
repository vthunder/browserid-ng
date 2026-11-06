// Security audit 2026-11, WS4 — native (Electron) wallet request lanes and
// the localhost bridge, run without Electron: request.js, store.js (state
// only), crypto.js and server.js are plain Node modules.
//
//   node --test wallet/test/audit_2026_11_ws4.test.mjs
//
// Tests that FAIL today are skipped with `AUDIT-2026-11 <id>: fails today`;
// un-skipping is the acceptance test for the fix. Everything else pins what
// the audit re-verified. No production code is changed.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';

// A dead broker: anything that reaches the network fails fast (and the
// wallet must fail CLOSED when it does).
process.env.WALLET_BROKER = 'http://127.0.0.1:1';
delete process.env.WALLET_AUTO_APPROVE;

const require = createRequire(import.meta.url);
const store = require('../src/store');
const request = require('../src/request');
const { generateKey, jws, nowS } = require('../src/crypto');

// store.init needs Electron; drive the in-memory state directly and make
// set() a pure in-memory patch (save() would write to a null path).
store.set = async (patch) => { Object.assign(store.state(), patch); };

const ORIGIN = 'https://site.example';
const AUD = 'sbo+raw://db.example/notes';
const HOLDER = 'br.wallet-1';

let identityKey;
async function seed({ identity = 'dan@example.com', holder = HOLDER } = {}) {
  identityKey = identityKey || (await generateKey());
  const configKey = { ...identityKey.privJwk, x: identityKey.x };
  const deviceCert = await jws(configKey, { typ: 'browserid-device-cert-v1', iat: nowS(), exp: nowS() + 86400, holder, managed: false });
  Object.assign(store.state(), {
    identity, holder, holderPrefix: holder.split('.')[0], domain: 'idp.example',
    deviceKey: configKey, deviceCert, configKey, configCert: 'cfg.cert.sig',
    signingGrants: {}, warrants: {}, warrantRefs: {},
  });
  return configKey;
}

function grantClaims(over = {}) {
  return {
    typ: 'browserid-warrant-v2', iat: nowS(), exp: nowS() + 86400,
    grantor: 'dan@example.com', grantee: 'dan@example.com',
    binding: [{ kind: 'holder', matcher: HOLDER }, { kind: 'requester', origin: ORIGIN }],
    audience: AUD, scopes: ['sign:sbo:post'],
    status: { uri: 'http://127.0.0.1:1/status/x', idx: 1 },
    ...over,
  };
}

async function storeGrant(claims, key) {
  const signed = await jws(key, claims);
  store.state().signingGrants = { [ORIGIN]: { [AUD]: signed } };
  return signed;
}

// ---------------------------------------------------------------------------
// D12 — "wallet signs under unverified stored grants"

test('D12 (pinned): coveringRecord enforces requester, holder, audience, grantee, scope and expiry', async () => {
  const key = await seed();
  await storeGrant(grantClaims(), key);
  assert.equal(request.coveringRecord(ORIGIN, AUD, 'post').mode, 'auto');
  assert.equal(request.coveringRecord('https://other.example', AUD, 'post').error, 'no_grant');
  assert.equal(request.coveringRecord(ORIGIN, 'sbo+raw://db.example/other', 'post').error, 'no_grant');
  assert.equal(request.coveringRecord(ORIGIN, AUD, 'delete').error, 'scope_not_granted');

  await storeGrant(grantClaims({ binding: [{ kind: 'holder', matcher: 'br.other' }, { kind: 'requester', origin: ORIGIN }] }), key);
  assert.match(request.coveringRecord(ORIGIN, AUD, 'post').message, /different device/);
  await storeGrant(grantClaims({ binding: [{ kind: 'holder', matcher: HOLDER }, { kind: 'requester', origin: 'https://evil.example' }] }), key);
  assert.match(request.coveringRecord(ORIGIN, AUD, 'post').message, /different requesting site/);
  await storeGrant(grantClaims({ grantee: 'mallory@example.com' }), key);
  assert.match(request.coveringRecord(ORIGIN, AUD, 'post').message, /covers something else/);
  await storeGrant(grantClaims({ exp: nowS() + 30 }), key);
  assert.match(request.coveringRecord(ORIGIN, AUD, 'post').message, /expired/);
  // A record lacking either channel entry is not a signing grant (spec §5).
  await storeGrant(grantClaims({ binding: [{ kind: 'requester', origin: ORIGIN }] }), key);
  assert.match(request.coveringRecord(ORIGIN, AUD, 'post').message, /not a signing grant/);
  // Unknown channel kinds are refused (§6.6 invariant 14).
  await storeGrant(grantClaims({ binding: [...grantClaims().binding, { kind: 'moon', phase: 'full' }] }), key);
  assert.match(request.coveringRecord(ORIGIN, AUD, 'post').message, /unknown channel kind/);
});

test('D12 (pinned, S7): a parameterised entry signs — parameters outside the wallet class pass through; an unknown mode refuses', async () => {
  const key = await seed();
  await storeGrant(grantClaims({ scopes: [{ scope: 'sign:sbo:post', mode: 'prompt', cap: { amount: '5', currency: 'USD' } }] }), key);
  assert.equal(request.coveringRecord(ORIGIN, AUD, 'post').mode, 'prompt');
  await storeGrant(grantClaims({ scopes: [{ scope: 'sign:sbo:post', mode: 'later' }] }), key);
  assert.equal(request.coveringRecord(ORIGIN, AUD, 'post').error, 'scope_not_granted');
});

// Defence in depth only: whoever can write the encrypted store already holds
// the config key that would sign a fresh record, so an unverified stored
// record buys the attacker nothing the store did not already give them.
test('D12 (defence in depth): a stored record whose signature is not the config key\'s is refused', async () => {
  await seed();
  const stranger = await generateKey();
  await storeGrant(grantClaims(), { ...stranger.privJwk, x: stranger.x });
  assert.equal(request.coveringRecord(ORIGIN, AUD, 'post').error, 'no_grant');
});

test('D12 (pinned): the signature lane fails CLOSED when the grant status cannot be checked', async () => {
  const key = await seed();
  await storeGrant(grantClaims(), key);
  const r = await request.handle({
    kind: 'signature', origin: ORIGIN, caller: 'test',
    args: { audience: AUD, object: { owner: 'dan@example.com', action: 'post', path: '/n/1', payload: 'hi' } },
    approve: async () => true,
  });
  assert.equal(r.error, 'sign_failed');
  assert.match(r.message, /fail-closed/);
});

test('D12 (pinned): no stored record, no signature — a page cannot sign without a prior consent', async () => {
  await seed();
  const r = await request.handle({
    kind: 'signature', origin: ORIGIN, caller: 'test',
    args: { audience: AUD, object: { owner: 'dan@example.com', action: 'post' } },
    approve: async () => true,
  });
  assert.equal(r.error, 'no_grant');
});

// ---------------------------------------------------------------------------
// Warrant lane input validation (request-kinds/warrant.json, spec §5)

test('warrant lane (pinned): only self-grants, ≤8 grants, unique audiences, no wildcard audience, known parameters only', () => {
  const g = (over) => request.normalizeGrants({ grants: [{ audience: AUD, scopes: ['sign:sbo:post'] }], ...over });
  assert.ok(g({}));
  assert.equal(g({ grantee: 'agent@example.com' }), null);
  assert.equal(request.normalizeGrants({ grants: Array.from({ length: 9 }, (_, i) => ({ audience: `${AUD}/${i}`, scopes: ['x'] })) }), null);
  assert.equal(request.normalizeGrants({ grants: [{ audience: AUD, scopes: ['x'] }, { audience: AUD, scopes: ['y'] }] }), null);
  assert.equal(request.normalizeGrants({ grants: [{ audience: 'sbo+raw://*/x', scopes: ['x'] }] }), null);
  assert.equal(request.normalizeGrants({ grants: [{ audience: AUD, scopes: [{ scope: 'sign:sbo:post', surprise: 1 }] }] }), null);
  assert.equal(request.normalizeGrants({ grants: [{ audience: AUD, scopes: [{ scope: 'sign:sbo:post', mode: 'always' }] }] }), null);
});

// ---------------------------------------------------------------------------
// W4-20 — native consent card does not call out auto/prompt mode

// Spec §5 "Signing grants": auto-mode scopes are standing authority and "the
// consent card MUST say so in its verb ... prompt-mode scopes called out";
// §7.5 "a verb per scope, prompt-mode scopes called out". main.js
// approveRequest renders request.js's `lines`, which carry bare scope names.
test('W4-20: the native warrant prompt distinguishes a standing (auto) grant from a prompt-mode one', async () => {
  await seed();
  let shown;
  const approve = async (p) => { shown = p; return false; };
  await request.handle({
    kind: 'warrant', origin: ORIGIN, caller: 'test',
    args: { grants: [{ audience: AUD, scopes: [{ scope: 'sign:sbo:post', mode: 'prompt' }, 'sign:sbo:delete'] }] },
    approve,
  });
  const text = shown.lines.join('\n');
  assert.match(text, /prompt|ask(s|ed)? (you )?each time/i, 'prompt-mode scope is called out');
  assert.match(text, /auto|without asking|silently|standing/i, 'auto-mode scope is named as standing authority');
});

test('W4-20 (pinned): what the warrant prompt does show — the browser-verified origin, the identity, and the caller', async () => {
  await seed();
  let shown;
  const r = await request.handle({
    kind: 'warrant', origin: ORIGIN, caller: 'a browser extension (chrome-extension://x)',
    args: { grants: [{ audience: AUD, scopes: ['sign:sbo:post'] }] },
    approve: async (p) => { shown = p; return false; },
  });
  assert.equal(r.error, 'denied');
  assert.equal(shown.origin, ORIGIN);
  assert.equal(shown.email, 'dan@example.com');
  assert.match(shown.lines[0], new RegExp(`^${AUD.replace(/[+./]/g, '\\$&')}:$`), 'the audience heads its entries');
  assert.match(shown.lines[1], /^\s+• sign:sbo:post — sign posts/, 'the entry renders through the scope-label table');
});

// ---------------------------------------------------------------------------
// W4-21 — localhost bridge: any loopback PAGE may pair, in production builds

after(() => { if (bridgeServer) { bridgeServer.closeAllConnections?.(); bridgeServer.close(); } });

const portFree = (port) => new Promise((resolve) => {
  const s = createServer();
  s.once('error', () => resolve(false));
  s.listen(port, '127.0.0.1', () => s.close(() => resolve(true)));
});

let bridgeServer = null;
async function bridge() {
  if (!(await portFree(8873))) return null; // a real wallet is running here
  // Capture the http.Server startServer creates so the test can close it.
  const http = require('node:http');
  const realCreate = http.createServer;
  http.createServer = (...a) => { bridgeServer = realCreate.apply(http, a); return bridgeServer; };
  const { startServer } = require('../src/server');
  http.createServer = realCreate;
  const calls = [];
  const port = await startServer({
    approvePair: async (p) => { calls.push(['pair', p.caller]); return true; },
    approveLogin: async () => false,
    approveRequest: async () => false,
    notify: () => {},
  });
  const post = (path, body, headers = {}) => fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body || {}),
  });
  return { post, calls };
}

test('bridge (pinned): a web page origin is refused before the pairing dialog; a token is bound to the origin it was paired under', async (t) => {
  const b = await bridge();
  if (!b) return t.skip('port 8873 is held by a running wallet');
  await seed();
  const evil = await b.post('/pair', {}, { origin: 'https://evil.example' });
  assert.equal(evil.status, 403);
  assert.equal(b.calls.length, 0, 'no pairing dialog fired');

  const ext = 'chrome-extension://' + 'a'.repeat(32);
  const ok = await b.post('/pair', {}, { origin: ext });
  assert.equal(ok.status, 200);
  const { token } = await ok.json();
  const other = 'chrome-extension://' + 'b'.repeat(32);
  const cross = await b.post('/request', { kind: 'login', origin: ORIGIN }, { origin: other, 'x-wallet-token': token });
  assert.equal(cross.status, 401, 'token from another extension origin');
  const none = await b.post('/request', { kind: 'login', origin: ORIGIN }, { 'x-wallet-token': token });
  assert.equal(none.status, 401, 'token presented with no Origin at all');
});

// server.js ALLOWED_ORIGIN admits http(s)://localhost:* and 127.0.0.1:* for
// the e2e harness, unconditionally. A page served by any local dev server
// (A9, loopback) can therefore open the pairing dialog, and once paired it
// forwards whatever `origin` it likes on /request — the requester channel
// every self-grant binds to. Gate the loopback-page allowance on WALLET_TEST.
test('W4-21: a loopback web page cannot pair with the bridge outside WALLET_TEST', async (t) => {
  const b = await bridge();
  if (!b) return t.skip('port 8873 is held by a running wallet');
  delete process.env.WALLET_TEST;
  const r = await b.post('/pair', {}, { origin: 'http://localhost:5173' });
  assert.equal(r.status, 403);
  assert.equal(b.calls.length, 0);
});


// The same rule, unit-level, so it is checked even while a real wallet holds
// port 8873 (the bridge tests above skip then).
test('W4-21: originAllowed admits loopback pages only under WALLET_TEST and honours a pinned extension id', () => {
  const { originAllowed } = require('../src/server');
  const saved = { t: process.env.WALLET_TEST, ids: process.env.WALLET_EXTENSION_IDS };
  try {
    delete process.env.WALLET_TEST; delete process.env.WALLET_EXTENSION_IDS;
    assert.equal(originAllowed('http://localhost:5173'), false);
    assert.equal(originAllowed('http://127.0.0.1:8080'), false);
    assert.equal(originAllowed('https://evil.example'), false);
    assert.equal(originAllowed('chrome-extension://' + 'a'.repeat(32)), true, 'unpinned dev build: any 32-letter id');
    process.env.WALLET_TEST = '1';
    assert.equal(originAllowed('http://localhost:5173'), true, 'the e2e harness');
    process.env.WALLET_EXTENSION_IDS = 'b'.repeat(32);
    assert.equal(originAllowed('chrome-extension://' + 'a'.repeat(32)), false, 'pinned: other ids refused');
    assert.equal(originAllowed('chrome-extension://' + 'b'.repeat(32)), true);
  } finally {
    if (saved.t === undefined) delete process.env.WALLET_TEST; else process.env.WALLET_TEST = saved.t;
    if (saved.ids === undefined) delete process.env.WALLET_EXTENSION_IDS; else process.env.WALLET_EXTENSION_IDS = saved.ids;
  }
});
