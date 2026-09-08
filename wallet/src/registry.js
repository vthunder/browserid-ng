// Registry API client (docs/specs/registry-api-v1.md §4–§5): the wallet as
// a first-class registry client. A SESSION (§4.5) is opened from possession
// proofs by this device's own keys against the account they were attached
// to; every call carries the session token plus a request proof signed
// with the config key (`kid` in the header, `bh` binding POST bodies). No
// cookies, no presentation exchange — the keys themselves authenticate.
const store = require('./store');
const broker = require('./broker');
const { proof, kidOf, nowS, randHex } = require('./crypto');

let token = null;
let tokenExp = 0;

function keyX(privJwk) { return privJwk.x; }

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

// §4.5: a session on the account this wallet was attached to.
async function openSession() {
  const s = store.state();
  if (!s.account || !s.deviceCert) return false;
  const path = '/api/v1/session';
  const htu = broker.ORIGIN + path;
  const jti = randHex(12);
  const proofs = [
    await proof(s.deviceKey, 'POST', htu, { jti, x: keyX(s.deviceKey) }),
    await proof(s.configKey, 'POST', htu, { jti, x: keyX(s.configKey) }),
  ];
  const bodyStr = JSON.stringify({ account: s.account, proofs });
  const r = await postRaw(path, bodyStr, { proof: await proof(s.configKey, 'POST', htu, { body: bodyStr, jti, x: keyX(s.configKey) }) });
  if (r.ok && r.data.token) { took(r.data); return true; }
  return false;
}

// §5.2.1: record this device's pair for its identity. `guard` is a token
// from the registry's guard page (bootstrap.js runs that page); without
// one, a held identity answers guard_required, which the caller handles.
async function attach({ guard = null } = {}) {
  const s = store.state();
  if (!s.deviceCert) throw new Error('wallet not bootstrapped');
  const path = '/api/v1/account/attach';
  const htu = broker.ORIGIN + path;
  const jti = randHex(12);
  const body = {
    identity: s.identity,
    certs: [
      { cert: s.deviceCert, proof: await proof(s.deviceKey, 'POST', htu, { jti, x: keyX(s.deviceKey) }) },
      { cert: s.configCert, proof: await proof(s.configKey, 'POST', htu, { jti, x: keyX(s.configKey) }) },
    ],
  };
  if (guard) body.guard = guard;
  if (s.account && token) body.account = s.account;
  const bodyStr = JSON.stringify(body);
  const headers = { proof: await proof(s.configKey, 'POST', htu, { body: bodyStr, jti, x: keyX(s.configKey) }) };
  if (token && s.account) headers.authorization = `Bearer ${token}`;
  const r = await postRaw(path, bodyStr, headers);
  if (r.ok && r.data.token) { took(r.data); return { ok: true }; }
  if (r.status === 403 && r.data.reason === 'guard_required') {
    const page = (r.data.guard_kinds || []).find((k) => k.kind === 'page' && k.url);
    return { ok: false, guardRequired: true, guardUrl: page ? page.url : null };
  }
  const e = new Error(`attach: ${r.status} ${r.data.error_description || r.data.error || ''}`);
  e.status = r.status;
  e.reason = r.data.reason;
  throw e;
}

async function ensure() {
  if (token && nowS() < tokenExp - 60) return token;
  token = null;
  if (await openSession()) return token;
  const r = await attach();
  if (!r.ok) {
    const e = new Error('this device is not attached to the account yet: run setup');
    e.reason = 'guard_required';
    e.guardUrl = r.guardUrl;
    throw e;
  }
  return token;
}

async function apiCall(method, path, body, retried = false) {
  await ensure();
  const s = store.state();
  const htu = broker.ORIGIN + path.split('?')[0];
  const bodyStr = body !== undefined ? JSON.stringify(body) : undefined;
  const res = await fetch(broker.BROKER + path, {
    method,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'user-agent': broker.UA,
      authorization: `Bearer ${token}`,
      proof: await proof(s.configKey, method, htu, { body: method === 'GET' ? null : (bodyStr || ''), x: keyX(s.configKey) }),
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
  attach,
  apiCall,
  allocateStatus,
  registerWarrant,
  listRequests,
  startInboxWatch,
  ensureDeviceLabel,
  kidOf,
};
