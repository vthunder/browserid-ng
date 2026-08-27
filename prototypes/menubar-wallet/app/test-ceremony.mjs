// Ceremony unit test against a local broker (no Electron involved).
// Usage: WALLET_BROKER=http://localhost:3000 WALLET_AUTO_APPROVE=1 \
//        node test-ceremony.mjs
import { createRequire } from 'node:module';
import fs from 'node:fs';
const require = createRequire(import.meta.url);
const store = require('./store');
const ceremony = require('./ceremony');

const BROKER = ceremony.BROKER;
const ADMIN = process.env.ADMIN_TOKEN || 'localtest-admin';
const email = `wallet-test-${Date.now()}@example.com`;
const pass = 'wallet-test-passw0rd!';

let failed = false;
const must = (name, ok, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failed = true;
};

const tmp = fs.mkdtempSync('/tmp/wallet-test-');
await store.init(tmp);

// 1. seed account
let r = await fetch(`${BROKER}/admin/create_account`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-admin-token': ADMIN },
  body: JSON.stringify({ email, pass }),
});
must('admin create_account', r.status === 200, `${r.status}`);

// 2. bootstrap (password lane)
const boot = await ceremony.bootstrapPassword({ email, pass });
must('bootstrap', boot.email === email && !!boot.holder, JSON.stringify(boot));
const s = store.state();
must('device+config certs stored', !!s.deviceCert && !!s.configCert && !!s.holderPrefix, s.holder);

// 3. login for an RP origin
const audience = 'https://rp.example.com';
const login = await ceremony.login({ origin: audience, approveLogin: async () => true });
must('login returns presentation', !!login.presentation && login.email === email, login.error || '');
must('presentation has 4 parts', (login.presentation || '').split('~').length === 4);

// 4. the RP-side check: broker /verify accepts it
r = await fetch(`${BROKER}/verify`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ presentation: login.presentation, audience }),
});
const v = await r.json();
must('/verify okay', v.status === 'okay' && v.email === email, JSON.stringify(v).slice(0, 200));

// 5. warrant reuse: second login mints fresh access/assertion, reuses warrant
const login2 = await ceremony.login({ origin: audience, approveLogin: async () => true });
must('second login works', !!login2.presentation);
must('warrant reused', login.presentation.split('~')[2] === login2.presentation.split('~')[2]);

// 6. wrong audience is rejected
r = await fetch(`${BROKER}/verify`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ presentation: login.presentation, audience: 'https://evil.example.com' }),
});
const v2 = await r.json();
must('wrong audience rejected', v2.status === 'failure', JSON.stringify(v2).slice(0, 120));

console.log(failed ? '\nCEREMONY TEST FAILED' : '\nCEREMONY TEST OK');
process.exit(failed ? 1 : 0);
