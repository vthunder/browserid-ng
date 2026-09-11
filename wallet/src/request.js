// The native wallet's request handler — one entry per request kind (spec
// §7.3, docs/specs/request-kinds/). The extension background forwards
// `{ kind, origin, args }` over the localhost bridge; `origin` is the
// browser-attached sender origin (bean fta9), never page-claimed, and is
// the `requester` channel every self-grant binds to.
//
//   login     → login.js (unchanged ceremony)
//   warrant   → self-grant records (browserid-warrant-v2, {holder, requester}),
//               one per { audience, scopes }, registrar status ref first
//   signature → a typed SBO envelope under the covering stored record
//               (spec §6.6 invariant 9), prompt-mode scopes after approval
//
// Anything else answers `unsupported_kind`.
const path = require('path');
const fs = require('fs');
const { pathToFileURL } = require('url');
const store = require('./store');
const broker = require('./broker');
const { generateKey, jws, decodeJws, nowS } = require('./crypto');

const SCOPE_RE = /^[a-z0-9_:.-]{1,64}$/;

function scopeName(e) { return typeof e === 'string' ? e : (e && e.scope); }
function scopeMode(e) { return (e && typeof e === 'object' && e.mode) || 'auto'; }
function matcherCovers(matcher, holder) {
  if (!matcher || !holder) return false;
  if (matcher === '*') return true;
  if (matcher.endsWith('.*')) return holder.startsWith(matcher.slice(0, -1));
  return matcher === holder;
}

// request("warrant") args → [{ audience, scopes }] or null. Self-grants only.
function normalizeGrants(v) {
  if (!v || typeof v !== 'object' || !Array.isArray(v.grants)) return null;
  if (!v.grants.length || v.grants.length > 8) return null;
  if (v.grantee !== undefined && v.grantee !== 'self') return null;
  const seen = new Set();
  const out = [];
  for (const g of v.grants) {
    if (!g || typeof g !== 'object' || typeof g.audience !== 'string' || !g.audience) return null;
    if (g.audience.includes('*') || /\s/.test(g.audience) || g.audience.length > 512) return null;
    if (seen.has(g.audience)) return null;
    seen.add(g.audience);
    if (!Array.isArray(g.scopes) || !g.scopes.length || g.scopes.length > 32) return null;
    for (const sc of g.scopes) {
      const name = scopeName(sc);
      if (typeof name !== 'string' || !SCOPE_RE.test(name)) return null;
      if (typeof sc === 'object' && !Object.keys(sc).every((k) => k === 'scope' || k === 'mode')) return null;
      const mode = typeof sc === 'object' ? sc.mode : undefined;
      if (mode !== undefined && mode !== 'auto' && mode !== 'prompt') return null;
    }
    out.push({ audience: g.audience, scopes: g.scopes });
  }
  return out;
}

function storedGrant(origin, audience) {
  const all = store.state().signingGrants || {};
  return (all[origin] || {})[audience] || null;
}

async function storeGrant(origin, audience, warrant) {
  const all = { ...(store.state().signingGrants || {}) };
  all[origin] = { ...(all[origin] || {}), [audience]: warrant };
  await store.set({ signingGrants: all });
}

async function dropGrant(origin, audience) {
  const all = { ...(store.state().signingGrants || {}) };
  if (all[origin]) {
    const o = { ...all[origin] };
    delete o[audience];
    all[origin] = o;
    await store.set({ signingGrants: all });
  }
}

// --- warrant ---------------------------------------------------------------
async function warrant({ origin, args, caller, approve }) {
  const s = store.state();
  if (!s.deviceCert) return { error: 'wallet not bootstrapped' };
  const grants = normalizeGrants(args);
  if (!grants) return { error: 'bad_request', message: 'warrant needs { grants: [{ audience, scopes }] }' };

  const ok = process.env.WALLET_AUTO_APPROVE === '1' || (await approve({
    kind: 'warrant', origin, email: s.identity, caller,
    lines: grants.map((g) => `${g.audience}: ${g.scopes.map(scopeName).join(', ')}`),
  }));
  if (!ok) return { error: 'denied' };

  const registry = require('./registry');
  const warrants = [];
  for (const g of grants) {
    // No status ref ⇒ no record (a refless v2 record is malformed; the
    // wallet fails closed rather than signing an unrevocable grant).
    let ref;
    try {
      ref = await registry.allocateStatus(g.audience, g.scopes.map(scopeName));
    } catch (e) {
      return { error: 'sign_failed', message: `status allocation failed: ${e.message || e}` };
    }
    const claims = {
      typ: 'browserid-warrant-v2',
      iat: nowS(), exp: nowS() + 90 * 86400,
      grantor: s.identity, grantee: s.identity,
      binding: [
        { kind: 'holder', matcher: s.holder },
        { kind: 'requester', origin },
      ],
      audience: g.audience, scopes: g.scopes,
      status: ref,
    };
    const signed = await jws(s.configKey, claims);
    try {
      await registry.registerWarrant(signed);
    } catch (e) {
      return { error: 'sign_failed', message: `warrant registration failed: ${e.message || e}` };
    }
    await storeGrant(origin, g.audience, signed);
    warrants.push(signed);
  }
  return { warrants, config_cert: s.configCert, email: s.identity };
}

// --- signature -------------------------------------------------------------
// The covering record's channel set + scope, evaluated for this device.
function coveringRecord(origin, audience, action) {
  const s = store.state();
  const stored = storedGrant(origin, audience);
  const refuse = (error, message) => ({ error, message });
  if (!stored) return refuse('no_grant', `no signing grant for ${origin} → ${audience}`);
  let c;
  try { c = decodeJws(stored); } catch { c = null; }
  if (!c || c.typ !== 'browserid-warrant-v2') return refuse('no_grant', 'stored record is malformed');
  if (!c.exp || nowS() + 60 >= c.exp) return refuse('no_grant', 'signing grant expired');
  if (c.grantee !== s.identity || c.audience !== audience) return refuse('no_grant', 'signing grant covers something else');
  const entries = Array.isArray(c.binding) ? c.binding : [];
  let sawRequester = false, sawHolder = false;
  for (const e of entries) {
    if (!e || typeof e !== 'object') return refuse('no_grant', 'malformed channel entry');
    if (e.kind === 'requester') {
      sawRequester = true;
      if (e.origin !== origin) return refuse('no_grant', 'signing grant names a different requesting site');
    } else if (e.kind === 'holder') {
      sawHolder = true;
      if (!matcherCovers(e.matcher, s.holder)) return refuse('no_grant', 'signing grant covers a different device');
    } else {
      return refuse('no_grant', 'signing grant carries an unknown channel kind');
    }
  }
  if (!sawRequester || !sawHolder) return refuse('no_grant', 'stored record is not a signing grant');
  const want = `sign:sbo:${action}`;
  const entry = (c.scopes || []).find((e) => scopeName(e) === want);
  if (!entry) return refuse('scope_not_granted', `'${want}' is not in this site's grant`);
  const mode = scopeMode(entry);
  if (mode !== 'auto' && mode !== 'prompt') return refuse('scope_not_granted', 'unimplemented scope parameter');
  return { jws: stored, claims: c, mode };
}

async function checkStatus(claims) {
  if (!claims.status || !claims.status.uri) return 'unavailable';
  try {
    const r = await fetch(`${broker.BROKER}/status/check`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': broker.UA },
      body: JSON.stringify({ refs: [{ uri: claims.status.uri, idx: claims.status.idx }] }),
    });
    const j = await r.json();
    if (j && j.revoked) return 'revoked';
    if (j && j.ok) return 'valid';
  } catch { /* fall through */ }
  return 'unavailable';
}

// The SBO signing helpers live in the broker tree (shared with the web
// wallet). In a dev checkout they sit next to this package; a packaged app
// names the directory with WALLET_SBO_DIR. Without them `signature` answers
// unsupported_kind rather than pretending.
let sboLoad = null;
function loadSbo() {
  if (sboLoad) return sboLoad;
  sboLoad = (async () => {
    const dir = process.env.WALLET_SBO_DIR
      || path.join(__dirname, '..', '..', 'browserid-broker', 'static', 'common', 'js');
    const wasmDir = path.join(dir, 'sbo-wasm');
    const SboSign = require(path.join(dir, 'sbo-sign.js'));
    const mod = await import(pathToFileURL(path.join(wasmDir, 'sbo_wasm.js')).href);
    mod.initSync({ module: fs.readFileSync(path.join(wasmDir, 'sbo_wasm_bg.wasm')) });
    return { SboSign, sbo: mod };
  })();
  sboLoad.catch(() => { sboLoad = null; });
  return sboLoad;
}

async function signature({ origin, args, caller, approve }) {
  const s = store.state();
  if (!s.deviceCert) return { error: 'wallet not bootstrapped' };
  const audience = args && typeof args.audience === 'string' ? args.audience : '';
  const envelope = args && args.object;
  if (!audience || !envelope || typeof envelope !== 'object') {
    return { error: 'bad_request', message: 'signature needs { audience, object }' };
  }
  let action = 'post';
  if (envelope.action != null && envelope.action !== '') action = envelope.action;
  if (typeof action !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(action)) {
    return { error: 'bad_request', message: 'envelope carries no classifiable action' };
  }
  const rec = coveringRecord(origin, audience, action);
  if (rec.error) return rec;
  const st = await checkStatus(rec.claims);
  if (st === 'revoked') {
    await dropGrant(origin, audience);
    return { error: 'no_grant', message: 'the signing grant was revoked' };
  }
  if (st !== 'valid') return { error: 'sign_failed', message: 'grant status check unavailable (fail-closed)' };

  let sboMods;
  try { sboMods = await loadSbo(); } catch (e) {
    return { error: 'unsupported_kind', kind: 'signature', message: `SBO signing helpers unavailable: ${e.message || e}` };
  }

  if (rec.mode === 'prompt') {
    const summary = { action, path: envelope.path, id: envelope.id };
    if (envelope.payload != null) {
      const body = String(envelope.payload);
      summary.payload = body.length > 400 ? body.slice(0, 400) + '…' : body;
    }
    const ok = process.env.WALLET_AUTO_APPROVE === '1' || (await approve({
      kind: 'signature', origin, email: s.identity, caller,
      lines: [JSON.stringify(summary, null, 2)],
    }));
    if (!ok) return { error: 'denied', message: `the user declined this ${action}` };
  }

  // Fresh access cert + assertion stamping the requesting origin (invariant
  // 13), around the STORED record (invariant 11).
  const { mintAccess } = require('./login');
  const access = await mintAccess(audience);
  const assertion = await jws(access.privJwk, { exp: nowS() + 300, aud: audience, req_origin: origin });
  const presentation = `${access.cert}~${assertion}~${rec.jws}~${s.configCert}`;
  const accessX = access.privJwk.x;
  const identity = {
    email: s.identity,
    pubkeyHex: sboMods.SboSign.pubkeyHexFromJwkX(accessX),
    cert: presentation,
  };
  const { webcrypto } = require('node:crypto');
  const out = await sboMods.SboSign.signEnvelope(
    sboMods.sbo, envelope, identity, { d: access.privJwk.d, x: accessX }, webcrypto.subtle
  );
  return { signature: out.signature, presentation: out.cert, pubkey: out.pubkey, email: s.identity };
}

// --- admission -------------------------------------------------------------
// The resource filed the request; the page handed us the code. Claim with
// the browser-attached page origin (== audience origin ⇒ proven, no fetch),
// then the wallet-hosted card (jo0m) signs and responds; the page learns
// only the status.
async function admission({ origin, args }) {
  const s = store.state();
  if (!s.deviceCert) return { error: 'wallet not bootstrapped' };
  const code = args && typeof args.code === 'string' ? args.code : '';
  if (!code) return { error: 'bad_request', message: 'admission needs { code }' };
  const registry = require('./registry');
  let item;
  try {
    item = await registry.apiCall('POST', '/api/v1/requests/claim', { code, page_origin: origin });
  } catch (e) {
    return { error: 'not_found', message: `this request could not be claimed here: ${e.message || e}` };
  }
  if (!item || (item.kind !== 'connection' && item.kind !== 'authoring')) {
    return { error: 'unsupported_kind', kind: item && item.kind };
  }
  const testAction = process.env.WALLET_TEST === '1' && process.env.WALLET_AUTO_APPROVE === '1' ? 'approve' : undefined;
  const outcome = await require('./consent').hostConsent({ code, testAction });
  if (outcome === 'approved' || outcome === 'denied') return { status: outcome, email: s.identity };
  return { error: 'cancelled', message: `consent window ${outcome}` };
}

async function handle({ kind, origin, args, caller, approveLogin, approve, acceptedFallbacks }) {
  if (kind === 'login') {
    return require('./login').login({ origin, caller, approveLogin, acceptedFallbacks });
  }
  if (kind === 'warrant') return warrant({ origin, args, caller, approve });
  if (kind === 'signature') return signature({ origin, args, caller, approve });
  if (kind === 'admission') return admission({ origin, args });
  return { error: 'unsupported_kind', kind: String(kind) };
}

module.exports = { handle, normalizeGrants, coveringRecord };
