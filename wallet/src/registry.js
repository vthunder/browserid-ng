// Registry API client (docs/specs/registry-api-v1.md §4–§5): the wallet as
// a first-class registry client. A SESSION (§4.5) is bound to this
// wallet's LOGIN KEY and comes from a LOGIN (§4.2): headlessly by that key
// (`stored_key`), or through the registry's login page at setup, which
// enrols it; `accounts` on first use enrols it too. Every call carries the
// session token plus a request proof signed by the login key (`kid` in the
// header, `bh` binding POST bodies). No cookies — the key authenticates.
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

// This wallet's login key, generated once and kept in the store.
async function loginKey() {
  const s = store.state();
  if (s.loginKey) return s.loginKey;
  const { generateKey } = require('./crypto');
  const k = await generateKey();
  const key = { ...k.privJwk, x: k.x };
  await store.set({ loginKey: key });
  return key;
}
async function loginKeyArg(htu, jti) {
  const key = await loginKey();
  return { pubkey: key.x, label: 'BrowserID Wallet', proof: await proof(key, 'POST', htu, { jti, x: key.x }) };
}

// Possession proofs for the pair (+ the login key's when `withKey`), and
// the header proof by `signerKey`.
async function withCerts(path, extra, signerKey, withKey) {
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
  if (withKey) body.login_key = await loginKeyArg(htu, jti);
  const bodyStr = JSON.stringify(body);
  const key = signerKey;
  return { bodyStr, header: await proof(key, 'POST', htu, { body: bodyStr, jti, x: key.x }) };
}

// §5.2.1: the account holding this wallet's identity, or null.
async function lookupAccount() {
  const path = '/api/v1/accounts/lookup';
  const w = await withCerts(path, {}, store.state().configKey, false);
  const r = await postRaw(path, w.bodyStr, { proof: w.header });
  if (r.ok && r.data.account) return r.data.account;
  if (r.status === 404) return null;
  throw apiError('POST', path, r);
}

// §5.2.1: a new account around the identity (the pair recorded and the
// login key enrolled by creation).
async function createAccount() {
  const path = '/api/v1/accounts';
  const w = await withCerts(path, {}, await loginKey(), true);
  const r = await postRaw(path, w.bodyStr, { proof: w.header });
  if (r.ok && r.data.token) { took(r.data); return; }
  throw apiError('POST', path, r);
}

// §4.2 stored_key: this wallet's login key. False when the registry sends
// us to the page (login_required: unknown, expired, or revoked key).
async function loginStored(account) {
  const key = store.state().loginKey;
  if (!key) return false;
  const path = '/api/v1/login';
  const htu = broker.ORIGIN + path;
  const jti = randHex(12);
  const pp = await proof(key, 'POST', htu, { jti, x: key.x });
  const bodyStr = JSON.stringify({ account, method: 'stored_key', proof: pp });
  const r = await postRaw(path, bodyStr, { proof: await proof(key, 'POST', htu, { body: bodyStr, jti, x: key.x }) });
  if (r.ok && r.data.token) { took(r.data); return true; }
  if (r.status === 403 && r.data.reason === 'login_required') return false;
  throw apiError('POST', path, r);
}

// §4.2 login_page: the registry's page, run by `openPage(url, account)`
// (bootstrap.js: a BrowserWindow in the wallet's partition) → token.
async function loginPage(account, openPage) {
  const path = '/api/v1/login';
  const r = await postRaw(path, JSON.stringify({ account, method: 'login_page' }), {});
  if (!(r.status === 403 && r.data.reason === 'login_required' && r.data.url)) throw apiError('POST', path, r);
  if (!openPage) { const e = new Error('a login is needed: run setup'); e.reason = 'login_needed'; throw e; }
  const pageToken = await openPage(r.data.url, account);
  // Login with the wallet's login key, which the registry enrols.
  const key = await loginKey();
  const htu = broker.ORIGIN + path;
  const jti = randHex(12);
  const bodyStr = JSON.stringify({ account, method: 'login_page', token: pageToken, login_key: await loginKeyArg(htu, jti) });
  const r2 = await postRaw(path, bodyStr, { proof: await proof(key, 'POST', htu, { body: bodyStr, jti, x: key.x }) });
  if (r2.ok && r2.data.token) { took(r2.data); return; }
  throw apiError('POST', path, r2);
}

// §5.2.4: record the pair under the session (idempotent on pubkey). The
// session is unchanged.
async function attach() {
  const path = '/api/v1/account/attach';
  const w = await withCerts(path, {}, store.state().loginKey, false);
  const r = await postRaw(path, w.bodyStr, { proof: w.header, authorization: `Bearer ${token}` });
  if (r.ok) return;
  throw apiError('POST', path, r);
}

function apiError(method, path, r) {
  const e = new Error(`${method} ${path}: ${r.status} ${r.data.error_description || r.data.error || ''}`);
  e.status = r.status;
  e.reason = r.data.reason;
  return e;
}

// A live session bound to this wallet's login key, the pair recorded under
// it. `openPage` is bootstrap's login window; without it (the steady state)
// a needed page login surfaces as an error and the wallet keeps working
// unattached until setup runs.
async function ensure({ openPage } = {}) {
  const s = store.state();
  if (!s.deviceCert) throw new Error('wallet not bootstrapped');
  if (token && nowS() < tokenExp - 60 && s.loginKey) return token;
  token = null;
  let account = s.account;
  if (account && await loginStored(account)) {
    await attach();
    return token;
  }
  account = await lookupAccount();
  if (!account) {
    await createAccount();
    return token;
  }
  await loginPage(account, openPage);
  await attach();
  return token;
}

async function apiCall(method, path, body, retried = false) {
  await ensure();
  const key = store.state().loginKey;
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
  // A dead session (expired, ended, or the key revoked) → open a new one
  // once (a revoked key ends at the page). Anything else surfaces.
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
