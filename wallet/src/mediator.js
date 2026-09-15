// The wallet answering navigator.id inside its own windows (beans e98a,
// d26p). Today one kind: `login` for the registry login page's "prove
// your identities" method. The held identity answers at once; a masked
// hint for another address runs that identity's issuer ceremony in a
// second window and holds the fresh pair UNATTACHED until the login the
// page is earning has opened a session — a bare attach of fresh certs
// would create a new account (registry-api-v1 §5.2.1). Re-entrancy is
// explicit: one request at a time per window, cancel unwinds the inner
// ceremony, and pairs held for a login that never completes are dropped.
const store = require('./store');
const broker = require('./broker');
const { nowS } = require('./crypto');

let installed = false;
// Pairs proven for a login in flight, keyed by email: attached once the
// session exists (deferredAttach), dropped on abandon.
const pending = new Map();
let busy = false;

function maskOf(email) {
  const i = email.indexOf('@');
  return i > 0 ? email[0] + '***' + email.slice(i) : '***';
}

function install({ askAddress }) {
  if (installed) return;
  installed = true;
  const { ipcMain } = require('electron');
  ipcMain.handle('wallet:mediator-request', async (event, kind, args) => {
    const url = event.senderFrame?.url || event.sender.getURL();
    if (!url.startsWith(`${broker.ORIGIN}/`)) return { error: 'unsupported_kind', message: 'mediator: wrong page' };
    if (kind !== 'login') return { error: 'unsupported_kind', kind: String(kind) };
    if (busy) return { error: 'busy', message: 'another request is in progress' };
    busy = true;
    try {
      return await answerLogin(args || {}, { askAddress });
    } catch (e) {
      return { error: e.reason || 'error', message: String(e.message || e) };
    } finally {
      busy = false;
    }
  });
}

// A presentation for this origin's own audience from `pair` (the held
// identity's, or one proven for this login). Self-contained on purpose: no
// registry call can run while the registry login itself is in flight (a
// status allocation would try to open a session, and with no account
// known could even create one), so the warrant is refless and unregistered.
async function presentationFor(pair, audience) {
  const { generateKey, jws, randHex } = require('./crypto');
  const warrant = await jws(pair.configKey, {
    typ: 'browserid-warrant-v1',
    iat: nowS(), exp: nowS() + 600,
    grantor: pair.identity, grantee: pair.identity,
    holder: `${pair.holderPrefix}.*`,
    audience, scopes: ['login', 'registry'],
  });
  const access = await generateKey();
  const areq = await jws(pair.deviceKey, {
    typ: 'browserid-access-request-v1',
    iat: nowS(), exp: nowS() + 600, jti: randHex(16),
    domain: pair.domain, identity: pair.identity, holder: pair.holder,
    'access-key': { algorithm: 'Ed25519', publicKey: access.x },
  });
  const res = await fetch(pair.mintUrl || `${broker.BROKER}/access/mint`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': broker.UA },
    body: JSON.stringify({ device_cert: pair.deviceCert, access_request: areq }),
  });
  const mint = await res.json().catch(() => ({}));
  if (res.status !== 200 || !mint.access_cert) throw new Error(`access/mint failed: ${res.status} ${mint.reason || ''}`);
  const assertion = await jws(access.privJwk, { exp: nowS() + 300, aud: audience });
  return `${mint.access_cert}~${assertion}~${warrant}~${pair.configCert}`;
}

function heldPair() {
  const s = store.state();
  return { identity: s.identity, domain: s.domain, mintUrl: s.mintUrl, holder: s.holder, holderPrefix: s.holderPrefix,
    deviceKey: s.deviceKey, deviceCert: s.deviceCert, configKey: s.configKey, configCert: s.configCert };
}

async function answerLogin(args, { askAddress }) {
  const audience = broker.ORIGIN;
  const s = store.state();
  if (!s.deviceCert) return { error: 'error', message: 'wallet not bootstrapped' };
  const hint = typeof args.hint === 'string' ? args.hint : null;
  // No hint, or the hint names the held identity: answer with it.
  if (!hint || maskOf(s.identity) === hint) {
    return { presentation: await presentationFor(heldPair(), audience), email: s.identity };
  }
  // A pair already proven for this login.
  for (const [email, pair] of pending) {
    if (maskOf(email) === hint) return { presentation: await presentationFor(pair, audience), email };
  }
  // Another address: the person names it (the hint is masked), and its
  // issuer's ceremony runs in a window of its own. Deferred attach.
  const email = process.env.WALLET_TEST_SECOND_IDENTITY || await askAddress(hint);
  if (!email) { const e = new Error('cancelled'); e.reason = 'cancelled'; throw e; }
  if (maskOf(email) !== hint) { const e = new Error('that address does not match'); e.reason = 'mismatch'; throw e; }
  const pair = await require('./bootstrap').proveIdentity(email, { testPassword: process.env.WALLET_TEST_SECOND_PASSWORD });
  pending.set(email.toLowerCase(), pair);
  return { presentation: await presentationFor(pair, audience), email };
}

// After the login the proofs earned has a session: record the proven pairs
// under it, and keep them as this wallet's extra identities.
async function deferredAttach() {
  if (!pending.size) return;
  const registry = require('./registry');
  const extras = { ...(store.state().extraIdentities || {}) };
  for (const [email, pair] of pending) {
    try {
      await registry.attachPair(pair, email);
      extras[email] = pair;
    } catch (e) {
      console.warn('[wallet] deferred attach failed for', email, e.message || e);
    }
  }
  pending.clear();
  await store.set({ extraIdentities: extras });
}

function abandon() { pending.clear(); }

module.exports = { install, deferredAttach, abandon, maskOf };
