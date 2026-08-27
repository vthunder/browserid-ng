// Registry API client (docs/specs/registry-api-v1.md): the wallet as a
// first-class registry client. A presentation for the broker's own audience
// is exchanged for a short-lived sender-constrained token (§3.1); every call
// carries the token plus a DPoP-style proof signed with the config key
// (§3.2). No cookies — this replaces the prototype's borrowed-session
// approvals polling entirely.
const store = require('./store');
const broker = require('./broker');
const { proof, nowS } = require('./crypto');

let token = null;
let tokenExp = 0;

async function getToken() {
  if (token && nowS() < tokenExp - 60) return token;
  const p = await require('./login').buildBrokerPresentation();
  const r = await broker.bare('/api/v1/token', { method: 'POST', body: { presentation: p } });
  if (r.status !== 200 || !r.data.access_token) {
    throw new Error(`token exchange failed: ${r.status} ${r.data.error_description || r.data.error || ''}`);
  }
  token = r.data.access_token;
  tokenExp = nowS() + (r.data.expires_in || 0);
  return token;
}

async function apiCall(method, path, body, retried = false) {
  const t = await getToken();
  const htu = broker.ORIGIN + path;
  const res = await fetch(broker.BROKER + path, {
    method,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'user-agent': broker.UA,
      authorization: `DPoP ${t}`,
      dpop: await proof(store.state().configKey, method, htu, t),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  // A dead token (expired early, or its cert re-checked revoked mid-life) →
  // drop it and re-exchange once. Anything else surfaces.
  if (res.status === 401 && !retried) {
    token = null;
    return apiCall(method, path, body, true);
  }
  const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (res.status >= 400) {
    throw new Error(`${method} ${path}: ${res.status} ${data.error_description || data.error || ''}`);
  }
  return data;
}

// --- §5.2: the pieces login.js uses to mint revocable site warrants ---

async function allocateStatus(audience, scopes) {
  const { uri, idx } = await apiCall('POST', '/api/v1/warrants/allocate_status', {
    agent_email: store.state().identity,
    audience,
    scopes,
  });
  return { uri, idx };
}

async function registerWarrant(warrantJws) {
  await apiCall('POST', '/api/v1/warrants/register', {
    warrant: warrantJws,
    config_cert: store.state().configCert,
  });
}

// --- §5.1: the approvals inbox ---

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
  const { shell } = require('electron');
  const poll = async () => {
    try {
      const data = await listRequests();
      for (const req of data.requests || []) {
        if (seenCodes.has(req.code)) continue;
        seenCodes.add(req.code);
        const who = req.label || req.agent_email || 'An agent';
        const what = (req.grants || []).map((g) => `${(g.scopes || []).join(',')} @ ${g.audience}`).join('; ');
        notify(`Approval requested: ${who}`, what || 'wants access', () =>
          shell.openExternal(`${broker.BROKER}/consent/${encodeURIComponent(req.code)}`)
        );
      }
    } catch (e) {
      // Offline or broker down — stay quiet, keep polling.
      console.warn('[wallet] inbox poll failed:', e.message || e);
    }
  };
  inboxTimer = setInterval(poll, 60_000);
  poll();
}

module.exports = { getToken, apiCall, allocateStatus, registerWarrant, listRequests, startInboxWatch };
