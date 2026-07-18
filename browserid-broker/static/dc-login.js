// Device-cert model login (DC Phase 5) — a relying party running the real flow.
//
// For a FALLBACK (no-primary) identity, browserid.me is the legitimate IdP:
//   1. /device/issue  → a user device cert (authentication) + a config cert
//      (authorization), both client-key, IdP-signed
//   2. sign an access request with the device key → /access/mint → fresh-key access cert
//   3. sign the login warrant with the CONFIG key (over identity+subject→audience)
//   4. sign an assertion with the access key; present
//      access_cert ~ assertion ~ warrant ~ config_cert
//   5. /verify-access → real primary/fallback conformance
//
// A PRIMARY-domain email (e.g. @sandmill.org) will CORRECTLY fail verify until
// that primary implements the device-cert endpoints (DC Phase 10).

const enc = new TextEncoder();
const b64urlJson = (o) =>
  btoa(String.fromCharCode(...enc.encode(JSON.stringify(o))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const nowS = () => Math.floor(Date.now() / 1000);
const HDR = b64urlJson({ alg: 'EdDSA', typ: 'JWT' });
const genKeypair = () => new Promise((res, rej) =>
  window.jwcrypto.generateKeypair({ algorithm: 'Ed25519' }, (e, kp) => (e ? rej(e) : res(kp))));
const rawSign = (key, msg) => new Promise((res, rej) => key.sign(msg, (e, s) => (e ? rej(e) : res(s))));
async function signJws(kp, payloadB64) {
  const sk = window.jwcrypto.loadSecretKeyFromObject({ algorithm: 'Ed25519', d: kp.secretKey._jwk.d, x: kp.publicKey._jwk.x });
  return `${HDR}.${payloadB64}.${await rawSign(sk, `${HDR}.${payloadB64}`)}`;
}
const rnd = () => { const a = new Uint8Array(16); crypto.getRandomValues(a); return [...a].map((b) => b.toString(16).padStart(2, '0')).join(''); };
async function postJSON(p, b) {
  const r = await fetch(p, { method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(b) });
  return { ok: r.ok, status: r.status, body: await r.json().catch(() => ({})) };
}
const getJSON = (p) => fetch(p, { credentials: 'same-origin' }).then((r) => r.json());
const decode = (jws) => JSON.parse(atob(jws.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));

const steps = document.getElementById('steps');
function step(label) {
  const li = document.createElement('li');
  li.className = 'pending';
  li.innerHTML = '<span class="mark">…</span> <span class="label"></span><div class="detail"></div>';
  li.querySelector('.label').textContent = label;
  steps.appendChild(li);
  return {
    ok: (d) => { li.className = 'ok'; li.querySelector('.mark').textContent = '✓'; if (d) li.querySelector('.detail').textContent = d; },
    fail: (d) => { li.className = 'err'; li.querySelector('.mark').textContent = '✗'; if (d) li.querySelector('.detail').textContent = d; },
  };
}

async function run() {
  document.getElementById('run').disabled = true;
  steps.innerHTML = '';
  document.getElementById('result').hidden = true;
  const email = document.getElementById('email').value.trim().toLowerCase();
  if (!email) { alert('Enter the email you are signed in with.'); document.getElementById('run').disabled = false; return; }
  try {
    let s = step('Check broker session');
    const ctx = await getJSON('/wsapi/session_context');
    if (!ctx.authenticated) { s.fail('Not signed in. Open /account, sign in, then retry.'); document.getElementById('run').disabled = false; return; }
    const csrf = ctx.csrf_token, idpDomain = ctx.domain, audience = location.origin;
    s.ok(`signed in · IdP ${idpDomain}`);

    // 1. Batch-issue a user device cert + a config cert.
    s = step('Issue device cert (authentication) + config cert (authorization)');
    const device = await genKeypair(), config = await genKeypair();
    let r = await postJSON('/device/issue', { csrf, email, device_pubkey: device.publicKey._jwk.x, config_pubkey: config.publicKey._jwk.x });
    if (!r.ok || !r.body.device_cert) { s.fail(`device/issue: ${r.body.reason || r.status} (is "${email}" a verified email on your account?)`); document.getElementById('run').disabled = false; return; }
    const deviceCert = r.body.device_cert, configCert = r.body.config_cert;
    s.ok('device + config certs issued (client-key, IdP-signed)');

    // 2. Access request (device-signed) → access cert.
    s = step('Mint a fresh-key access cert via /access/mint');
    const access = await genKeypair();
    const areq = await signJws(device, b64urlJson({
      typ: 'browserid-access-request-v1', iat: nowS(), exp: nowS() + 600, jti: rnd(),
      domain: idpDomain, identity: email, subject: 'user',
      'access-key': { algorithm: 'Ed25519', publicKey: access.publicKey._jwk.x },
    }));
    r = await postJSON('/access/mint', { device_cert: deviceCert, access_request: areq });
    if (!r.ok || !r.body.access_cert) { s.fail(`access/mint: ${r.body.reason || r.status}`); document.getElementById('run').disabled = false; return; }
    const accessCert = r.body.access_cert;
    s.ok('access cert minted (fresh key; device cert stays private)');

    // 3. Sign the login warrant with the CONFIG key (over identity+subject→audience).
    s = step('Sign the login warrant with the config cert');
    const warrant = await signJws(config, b64urlJson({
      typ: 'browserid-warrant-v1', iat: nowS(), exp: nowS() + 90 * 86400,
      identifier: email, subject: 'user', audience, scopes: ['login'],
    }));
    s.ok('warrant signed (device-agnostic, reusable)');

    // 4. Assertion + present the 4-object bundle.
    s = step('Sign an assertion and present the bundle to /verify-access');
    const assertion = await signJws(access, b64urlJson({ exp: nowS() + 300, aud: audience }));
    const presentation = `${accessCert}~${assertion}~${warrant}~${configCert}`;
    r = await postJSON('/verify-access', { presentation, audience });
    if (r.body.status !== 'okay') {
      s.fail(`/verify-access: ${r.body.reason || r.status}`);
      if ((r.body.reason || '').includes('primary')) {
        step('Note').ok(`This is CORRECT: ${email.split('@')[1]} runs its own primary IdP, so browserid.me cannot issue for it. Use a no-primary email (e.g. @example.com) — or wait for DC Phase 10 (sandmill.org conformance).`);
      }
      document.getElementById('run').disabled = false; return;
    }
    s.ok(`/verify-access OK → ${r.body.email} · subject=${r.body.subject} · scopes=${(r.body.scopes || []).join(',')}`);

    const ac = decode(accessCert), wc = decode(warrant), cc = decode(configCert);
    document.getElementById('r-email').textContent = r.body.email;
    document.getElementById('r-access').textContent = `identity=${ac.identity} subject=${ac.subject} iss=${ac.iss} (fresh key)`;
    document.getElementById('r-warrant').textContent = `${wc.identifier}, subject ${wc.subject} → ${wc.audience} · scopes ${(wc.scopes || []).join(',')}`;
    document.getElementById('r-config').textContent = `purpose=${cc.purpose} subject=${cc.subject} iss=${cc.iss}`;
    document.getElementById('result').hidden = false;
  } catch (e) {
    step('Unexpected error').fail(String(e && e.message ? e.message : e));
  }
  document.getElementById('run').disabled = false;
}

document.getElementById('run').addEventListener('click', run);
getJSON('/wsapi/session_context').then((ctx) => {
  const b = document.getElementById('signin-note');
  if (ctx && ctx.authenticated) b.textContent = `Signed in to ${ctx.domain}. Use a NO-PRIMARY email (e.g. an @example.com you verified) so browserid.me is the legitimate IdP.`;
  else b.innerHTML = 'You are not signed in. <a href="/account">Sign in at /account</a> first, then reload.';
}).catch(() => {});
