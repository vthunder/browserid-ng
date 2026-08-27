// Approval-push path test (no Electron): bootstrap a wallet, then act as a
// separate agent requesting a warrant from the same user, and confirm the
// pending request shows up on /wsapi/warrant_requests — the endpoint the
// app's approval watcher polls.
import { createRequire } from 'node:module';
import fs from 'node:fs';
const require = createRequire(import.meta.url);
const store = require('./store');
const ceremony = require('./ceremony');
const { generateKey } = require('./bidcrypto');

const BROKER = ceremony.BROKER;
const ADMIN = process.env.ADMIN_TOKEN || 'localtest-admin';
const email = `wallet-appr-${Date.now()}@example.com`;
const pass = 'wallet-appr-passw0rd!';
let failed = false;
const must = (n, ok, d = '') => { console.log(`${ok ? '✓' : '✗'} ${n}${d ? ' — ' + d : ''}`); if (!ok) failed = true; };
const post = (path, body, headers = {}) =>
  fetch(BROKER + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

// 1. account + wallet bootstrap (gives us a session cookie in the jar AND a device cert)
await store.init(fs.mkdtempSync('/tmp/wallet-appr-'));
let r = await post('/admin/create_account', { email, pass }, { 'x-admin-token': ADMIN });
must('seed account', r.status === 200);
await ceremony.bootstrapPassword({ email, pass });
const s = store.state();

// 2. a second agent (fresh key) gets its own device cert via the pairing lane?
//    Shortcut for the test: request warrants USING the wallet's device cert but
//    for a different audience — /warrant/request creates a pending consent
//    entry either way, which is all the watcher cares about.
r = await post('/warrant/request', {
  device_cert: s.deviceCert,
  identity: email,
  grants: [{ audience: 'https://some-service.example.com', scopes: ['post'] }],
  label: 'Approval Push Test Agent',
  message: 'testing the menubar wallet notification lane',
});
const req = await r.json();
must('/warrant/request accepted', r.status === 200 && req.success === true, JSON.stringify(req).slice(0, 120));

// 3. the watcher's poll: session-cookie GET /wsapi/warrant_requests
//    (ceremony's session jar still holds the bootstrap session)
const { status, data } = await (async () => {
  // reuse ceremony's session lane via a tiny back door: bareFetch has no jar,
  // so replicate with the cookie captured during bootstrapPassword
  const mod = require('./ceremony');
  return mod.__testSessionFetch
    ? mod.__testSessionFetch('/wsapi/warrant_requests')
    : { status: 0, data: {} };
})();
must('warrant_requests lists the pending request', status === 200 && (data.requests || []).some((q) => q.label === 'Approval Push Test Agent'),
  JSON.stringify((data.requests || []).map((q) => ({ label: q.label, grants: q.grants })), null, 0).slice(0, 200));

console.log(failed ? '\nAPPROVALS TEST FAILED' : '\nAPPROVALS TEST OK');
process.exit(failed ? 1 : 0);
