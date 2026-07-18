// Model A demo — "the browser is the user's first agent".
//
// Runs the whole subject:self login loop in the browser against this broker:
//   1. get a session-authorized U_cert for the browser's key (/wsapi/cert_key)
//   2. self-sign a provisioning credential (U_cert~P_cert, constraint subjects:[self])
//   3. register it (/wsapi/register_provisioning_cert)
//   4. mint a *login* cert via /provision/endorse + /provision/mint (subject:self)
//   5. sign an assertion with the login key and (best-effort) /verify it
//
// The novel part is that human login here IS an agent mint (subject:self) — the
// browser mints its own login cert through the very endpoint agents use. No
// hidden iframe, no postMessage cert relay.
//
// Uses the same client crypto the account page uses: window.jwcrypto (Ed25519
// keygen + JWS sign) — see /common/js/lib/jwcrypto-compat.js.

const enc = new TextEncoder();
const b64urlJson = (obj) =>
  btoa(String.fromCharCode(...enc.encode(JSON.stringify(obj))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const nowS = () => Math.floor(Date.now() / 1000);
const genKeypair = () => new Promise((res, rej) =>
  window.jwcrypto.generateKeypair({ algorithm: 'Ed25519' }, (e, kp) => (e ? rej(e) : res(kp))));
const sign = (key, msg) => new Promise((res, rej) =>
  key.sign(msg, (e, s) => (e ? rej(e) : res(s))));
const randomHex = () => {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
};

async function postJSON(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, body: j };
}
async function getJSON(path) {
  const r = await fetch(path, { credentials: 'same-origin' });
  return r.json();
}

// --- step UI ------------------------------------------------------------
const steps = document.getElementById('steps');
function step(label) {
  const li = document.createElement('li');
  li.className = 'pending';
  li.innerHTML = `<span class="mark">…</span> <span class="label"></span><div class="detail"></div>`;
  li.querySelector('.label').textContent = label;
  steps.appendChild(li);
  return {
    ok(detail) { li.className = 'ok'; li.querySelector('.mark').textContent = '✓'; if (detail) li.querySelector('.detail').textContent = detail; },
    fail(detail) { li.className = 'err'; li.querySelector('.mark').textContent = '✗'; if (detail) li.querySelector('.detail').textContent = detail; },
    detail(d) { li.querySelector('.detail').textContent = d; },
  };
}
function decodeJwtPayload(jws) {
  const p = jws.split('.')[1];
  return JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
}

// --- the loop -----------------------------------------------------------
async function run() {
  document.getElementById('run').disabled = true;
  steps.innerHTML = '';
  const result = document.getElementById('result');
  result.hidden = true;
  const email = document.getElementById('email').value.trim().toLowerCase();
  if (!email) { alert('Enter the email you are signed in with.'); document.getElementById('run').disabled = false; return; }

  try {
    // 0. session + csrf
    let s = step('Check broker session');
    const ctx = await getJSON('/wsapi/session_context');
    if (!ctx.authenticated) {
      s.fail('Not signed in. Open /account in another tab, sign in, then retry.');
      document.getElementById('run').disabled = false;
      return;
    }
    const csrf = ctx.csrf_token;
    const idpDomain = ctx.domain; // this broker's issuer domain
    s.ok(`signed in · IdP domain ${idpDomain}`);

    // 1. U_cert — a session-authorized identity cert for a fresh browser key.
    s = step('Bootstrap: get an identity cert for the browser key (U_cert)');
    const U = await genKeypair();
    const certRes = await postJSON('/wsapi/cert_key', {
      csrf, email, ephemeral: false,
      pubkey: { algorithm: 'Ed25519', publicKey: U.publicKey._jwk.x },
    });
    if (!certRes.ok || certRes.body.success === false || !certRes.body.cert) {
      s.fail(`cert_key failed: ${certRes.body.reason || certRes.status} (is "${email}" a verified email on your account?)`);
      document.getElementById('run').disabled = false;
      return;
    }
    const uCert = certRes.body.cert;
    s.ok('U_cert issued for the browser key');

    // 2. Provisioning credential: self-sign P_cert (subjects:[self]) with U.
    s = step('Self-sign the provisioning credential (U_cert~P_cert, subjects:[self])');
    const P = await genKeypair();
    const hdr = b64urlJson({ alg: 'EdDSA', typ: 'JWT' });
    const pCertClaims = {
      typ: 'browserid-provisioning-cert-v1', iss: email, iat: nowS(), exp: nowS() + 90 * 24 * 3600,
      'public-key': { algorithm: 'Ed25519', publicKey: P.publicKey._jwk.x },
      constraint: { subjects: ['self'] },
    };
    const pCertPayload = b64urlJson(pCertClaims);
    const pCertSig = await sign(U.secretKey, `${hdr}.${pCertPayload}`);
    const delegation = `${uCert}~${hdr}.${pCertPayload}.${pCertSig}`;
    s.ok('credential holds subjects:[self] — it can mint your login, never a named agent');

    // 3. Register the credential.
    s = step('Register the provisioning credential');
    const reg = await postJSON('/wsapi/register_provisioning_cert', {
      csrf, label: 'browser (demo self-login)', bundle: delegation,
    });
    if (!reg.ok || reg.body.success === false) {
      s.fail(`register failed: ${reg.body.reason || reg.status}`);
      document.getElementById('run').disabled = false;
      return;
    }
    s.ok('registered');

    // 4. Mint a subject:self LOGIN cert via the agent endpoint.
    s = step('Mint a login cert via /provision/mint (subject:self)');
    const L = await genKeypair(); // the key the login cert certifies + signs assertions
    const rClaims = {
      typ: 'browserid-provisioning-request-v1', iat: nowS(), exp: nowS() + 600,
      action: 'mint', subject: 'self', domain: idpDomain,
      'agent-key': { algorithm: 'Ed25519', publicKey: L.publicKey._jwk.x },
      jti: randomHex(),
    };
    const rPayload = b64urlJson(rClaims);
    const provSk = window.jwcrypto.loadSecretKeyFromObject({ algorithm: 'Ed25519', d: P.secretKey._jwk.d, x: P.publicKey._jwk.x });
    const rSig = await sign(provSk, `${hdr}.${rPayload}`);
    const bundle = `${delegation}~${hdr}.${rPayload}.${rSig}`;

    const end = await postJSON('/provision/endorse', { request_bundle: bundle });
    if (!end.ok || end.body.success === false) { s.fail(`endorse failed: ${end.body.reason || end.status}`); document.getElementById('run').disabled = false; return; }
    const mint = await postJSON('/provision/mint', { request_bundle: bundle, endorsement: end.body.endorsement });
    if (!mint.ok || mint.body.success === false || !mint.body.cert) { s.fail(`mint failed: ${mint.body.reason || mint.status}`); document.getElementById('run').disabled = false; return; }
    const loginCert = mint.body.cert;
    const claims = decodeJwtPayload(loginCert);
    s.ok(`minted a login cert · principal=${claims.principal && claims.principal.email} · typ=${claims.typ || '(none — plain user cert)'} · agent=${claims.agent ? 'YES' : 'no'}`);

    // 5. Sign an assertion with the login key, and (best-effort) verify it.
    s = step('Sign an assertion with the login key and verify it');
    const aud = location.origin;
    const aPayload = b64urlJson({ exp: nowS() + 300, aud });
    const aSig = await sign(L.secretKey, `${hdr}.${aPayload}`);
    const backed = `${loginCert}~${hdr}.${aPayload}.${aSig}`;
    const ver = await postJSON('/verify', { assertion: backed, audience: aud });
    if (ver.ok && (ver.body.status === 'okay' || ver.body.email)) {
      s.ok(`/verify OK → ${ver.body.email || claims.principal.email} (agent: ${ver.body.agent ? 'yes' : 'no'})`);
    } else {
      // Expected for emails whose domain runs its own primary IdP (browserid.me
      // can't fallback-issue for them): the MINT still proves Model A.
      s.detail(`/verify (best-effort): ${ver.body.reason || ver.status} — expected if ${email}'s domain has its own primary IdP. The minted login cert above is the proof.`);
      s.ok('assertion built (verify best-effort — see note)');
    }

    // Success panel.
    document.getElementById('r-email').textContent = claims.principal && claims.principal.email;
    document.getElementById('r-iss').textContent = claims.iss;
    document.getElementById('r-typ').textContent = claims.typ || '(none — a plain user/login cert, byte-identical to a classic login)';
    document.getElementById('r-agent').textContent = claims.agent ? JSON.stringify(claims.agent) : 'none — this is YOU, not a delegated agent';
    document.getElementById('r-cert').textContent = loginCert;
    result.hidden = false;
  } catch (e) {
    step('Unexpected error').fail(String(e && e.message ? e.message : e));
  }
  document.getElementById('run').disabled = false;
}

document.getElementById('run').addEventListener('click', run);
// Prefill nothing — the user types the email they signed in with.
getJSON('/wsapi/session_context').then((ctx) => {
  const b = document.getElementById('signin-note');
  if (ctx && ctx.authenticated) { b.textContent = `Signed in to ${ctx.domain}. Enter the email you signed in with and run the demo.`; }
  else { b.innerHTML = 'You are not signed in. <a href="/account">Sign in at /account</a> first, then reload this page.'; }
}).catch(() => {});
