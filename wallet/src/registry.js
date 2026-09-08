// Registry API client (docs/specs/registry-api-v1.md §4–§5): the wallet as
// a first-class registry client. A SESSION (§4.5) comes from a LOGIN
// (§4.2): headlessly by this wallet's login cert (`stored_key`), or through
// the registry's login page at setup. Every call carries the session token
// plus a request proof signed by a member key (`kid` in the header, `bh`
// binding POST bodies). No cookies — the keys themselves authenticate.
const store = require('./store');
const broker = require('./broker');
const { proof, kidOf, nowS, randHex } = require('./crypto');

let token = null;
let tokenExp = 0;

async function postRaw(path, bodyStr, headers = {}) {
  const res = await fetch(broker.BROKER + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': broker.UA, ...headers },
    body: bodyStr,
  });
  const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

function took(body) {
  token = body.token;
  tokenExp = Math.floor(new Date(body.expires_at).getTime() / 1000) || (nowS() + 3600);
  if (body.account && body.account !== store.state().account) store.set({ account: body.account });
}

// The key a session call is signed with: the login key when the session
// holds it, else the config cert (a member once attached).
let memberKids = [];
function signer() {
  const s = store.state();
  if (s.loginKey && memberKids.includes(kidOf(s.loginKey.x))) return s.loginKey;
  if (memberKids.includes(kidOf(s.configKey.x))) return s.configKey;
  if (memberKids.includes(kidOf(s.deviceKey.x))) return s.deviceKey;
  return null;
}
function took(body) {
  token = body.token;
  tokenExp = Math.floor(new Date(body.expires_at).getTime() / 1000) || (nowS() + 3600);
  memberKids = (body.members || []).map((m) => m.kid);
  if (body.account && body.account !== store.state().account) store.set({ account: body.account });
}

// Possession proofs for the pair (+ the header proof by `signerKey`).
async function withCerts(path, extra, signerKey) {
  const s = store.state();
  const htu = broker.ORIGIN + path;
  const jti = randHex(12);
  const body = {
    identity: s.identity,
    certs: [
      { cert: s.deviceCert, proof: await proof(s.deviceKey, 'POST', htu, { jti, x: s.deviceKey.x }) },
      { cert: s.configCert, proof: await proof(s.configKey, 'POST', htu, { jti, x: s.configKey.x }) },
    ],
    ...(extra || {}),
  };
  const bodyStr = JSON.stringify(body);
  const key = signerKey || s.configKey;
  return { bodyStr, header: await proof(key, 'POST', htu, { body: bodyStr, jti, x: key.x }) };
}

// §5.2.1: the account holding this wallet's identity, or null.
async function lookupAccount() {
  const path = '/api/v1/accounts/lookup';
  const w = await withCerts(path, {});
  const r = await postRaw(path, w.bodyStr, { proof: w.header });
  if (r.ok && r.data.account) return r.data.account;
  if (r.status === 404) return null;
  throw apiError('POST', path, r);
}

// §5.2.1: a new account around the identity (the pair recorded by creation).
async function createAccount() {
  const path = '/api/v1/accounts';
  const w = await withCerts(path, {});
  const r = await postRaw(path, w.bodyStr, { proof: w.header });
  if (r.ok && r.data.token) { took(r.data); return; }
  throw apiError('POST', path, r);
}

// §4.2 stored_key: this wallet's login cert. False when the registry
// refuses (expired, revoked, or none minted yet).
async function loginStored(account) {
  const s = store.state();
  if (!s.loginKey || !s.loginCert) return false;
  const path = '/api/v1/login';
  const htu = broker.ORIGIN + path;
  const jti = randHex(12);
  const pp = await proof(s.loginKey, 'POST', htu, { jti, x: s.loginKey.x });
  const bodyStr = JSON.stringify({ account, method: 'stored_key', proof: pp });
  const r = await postRaw(path, bodyStr, { proof: await proof(s.loginKey, 'POST', htu, { body: bodyStr, jti, x: s.loginKey.x }) });
  if (r.ok && r.data.token) { took(r.data); return true; }
  return false;
}

// §4.2 login_page: the registry's page, run by `openPage(url, account)`
// (bootstrap.js: a BrowserWindow in the wallet's partition) → token.
async function loginPage(account, openPage) {
  const path = '/api/v1/login';
  const r = await postRaw(path, JSON.stringify({ account, method: 'login_page' }), {});
  if (!(r.status === 403 && r.data.reason === 'login_required' && r.data.url)) throw apiError('POST', path, r);
  if (!openPage) { const e = new Error('a login is needed: run setup'); e.reason = 'login_needed'; throw e; }
  const pageToken = await openPage(r.data.url, account);
  const r2 = await postRaw(path, JSON.stringify({ account, method: 'login_page', token: pageToken }), {});
  if (r2.ok && r2.data.token) { took(r2.data); return; }
  throw apiError('POST', path, r2);
}

// §5.2.4: record the pair under the session (idempotent on pubkey).
async function attach() {
  const path = '/api/v1/account/attach';
  const w = await withCerts(path, {}, signer() || store.state().configKey);
  const r = await postRaw(path, w.bodyStr, { proof: w.header, authorization: `Bearer ${token}` });
  if (r.ok && r.data.token) { took(r.data); return; }
  throw apiError('POST', path, r);
}

// §5.2.3: a login cert for this wallet's own login key, for headless logins.
async function ensureLoginKey() {
  const s = store.state();
  if (s.loginKey && s.loginCert) return;
  const { generateKey } = require('./crypto');
  const k = await generateKey();
  const r = await apiCall('POST', '/api/v1/login-keys', { pubkey: k.x, label: 'BrowserID Wallet' });
  await store.set({ loginKey: { ...k.privJwk, x: k.x }, loginCert: r.cert });
}

function apiError(method, path, r) {
  const e = new Error(`${method} ${path}: ${r.status} ${r.data.error_description || r.data.error || ''}`);
  e.status = r.status;
  e.reason = r.data.reason;
  return e;
}

// A live session with the pair attached. `openPage` is bootstrap's login
// window; without it (the steady state) a needed page login surfaces as
// an error and the wallet keeps working unattached until setup runs.
async function ensure({ openPage } = {}) {
  const s = store.state();
  if (!s.deviceCert) throw new Error('wallet not bootstrapped');
  if (token && nowS() < tokenExp - 60 && signer()) return token;
  token = null; memberKids = [];
  let account = s.account;
  if (account && await loginStored(account)) {
    if (!memberKids.includes(kidOf(s.configKey.x))) await attach();
    return token;
  }
  account = await lookupAccount();
  if (!account) {
    await createAccount();
  } else {
    await loginPage(account, openPage);
    await attach();
  }
  try { await ensureLoginKey(); } catch (e) { console.warn('[wallet] login key not minted:', e.message || e); }
  return token;
}

async function apiCall(method, path, body, retried = false) {
  await ensure();
  const key = signer();
  if (!key) throw new Error('no session member to sign with');
  const htu = broker.ORIGIN + path.split('?')[0];
  const bodyStr = body !== undefined ? JSON.stringify(body) : undefined;
  const res = await fetch(broker.BROKER + path, {
    method,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'user-agent': broker.UA,
      authorization: `Bearer ${token}`,
      proof: await proof(key, method, htu, { body: method === 'GET' ? null : (bodyStr || ''), x: key.x }),
    },
    body: bodyStr,
  });
  const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
  // A dead session (expired, ended, or a member re-checked revoked) → open
  // a new one once. Anything else surfaces.
  if (res.status === 401 && data.error === 'invalid_session' && !retried) {
    token = null;
    return apiCall(method, path, body, true);
  }
  if (res.status >= 400) {
    const e = new Error(`${method} ${path}: ${res.status} ${data.error_description || data.error || ''}`);
    e.status = res.status;
    e.reason = data.reason;
    throw e;
  }
  return data;
}

// --- §5.4: the pieces login.js uses to mint revocable site warrants ---

async function allocateStatus(audience, scopes) {
  const { uri, idx } = await apiCall('POST', '/api/v1/warrants/allocate_status', {
    grantee: store.state().identity,
    audience,
    scopes,
  });
  return { uri, idx };
}

async function registerWarrant(warrantJws) {
  return apiCall('POST', '/api/v1/warrants/register', {
    warrant: warrantJws,
    config_cert: store.state().configCert,
  });
}

// --- §5.6: the wallet's own device row ---

// Give this wallet's holder a friendly name. The broker's UA convention
// labels it with the bare product token ("BrowserID-Wallet"); the wallet
// knows better — "Wallet on macOS". Replaces only the machine defaults;
// anything the user chose on the account page is respected. Best-effort.
async function ensureDeviceLabel() {
  try {
    const holder = store.state().holder;
    if (!holder) return;
    const os =
      { darwin: 'macOS', win32: 'Windows', linux: 'Linux' }[process.platform] || process.platform;
    const want = `Wallet on ${os}`;
    const view = await apiCall('GET', '/api/v1/holders');
    const mine = [
      ...(view.namespaces || []).flatMap((n) => n.holders || []),
      ...(view.holders_without_namespace || []),
    ].find((h) => h.holder_id === holder);
    if (!mine) return; // attach hasn't landed yet — next launch heals it
    const isMachineDefault =
      mine.label === 'BrowserID-Wallet' || /^holder-/.test(mine.label || '');
    if (!isMachineDefault || mine.label === want) return;
    await apiCall('POST', '/api/v1/holders/rename', { holder_id: holder, label: want });
    console.log(`[wallet] device label set to "${want}"`);
  } catch (e) {
    console.warn('[wallet] device label check failed:', e.message || e);
  }
}

// --- §5.3: the approvals inbox ---

async function listRequests() {
  return apiCall('GET', '/api/v1/requests');
}

// Poll the inbox and native-notify on new pending requests; clicking opens
// the consent page (approval stays a browser ceremony for now — the API
// could sign it natively, but that UX is its own project).
let inboxTimer = null;
const seenCodes = new Set();

function startInboxWatch({ notify }) {
  if (inboxTimer || !store.state().deviceCert) return;
  ensureDeviceLabel(); // fire-and-forget: both startup paths converge here
  const { shell } = require('electron');
  const poll = async () => {
    try {
      const data = await listRequests();
      for (const req of data.requests || []) {
        if (seenCodes.has(req.code)) continue;
        seenCodes.add(req.code);
        if (req.kind === 'notice') {
          const n = req.notice || {};
          notify(`Identity ${n.reason === 'returned' ? 'returned' : 'left'}: ${n.identity}`, '', null);
          continue;
        }
        const who = req.label || req.grantee || req.agent_email || 'An agent';
        const what = (req.grants || []).map((g) => `${(g.scopes || []).join(',')} @ ${g.audience}`).join('; ');
        notify(`Approval requested: ${who}`, what || 'wants access', () =>
          shell.openExternal(`${broker.BROKER}/consent/${encodeURIComponent(req.code)}`)
        );
      }
    } catch (e) {
      // Offline, broker down, or not attached yet — stay quiet, keep polling.
      console.warn('[wallet] inbox poll failed:', e.message || e);
    }
  };
  inboxTimer = setInterval(poll, 60_000);
  poll();
}

module.exports = {
  ensure,
  apiCall,
  allocateStatus,
  registerWarrant,
  listRequests,
  startInboxWatch,
  ensureDeviceLabel,
  kidOf,
};
