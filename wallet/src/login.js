// The steady-state login ceremony (what dialog.js does, from outside the
// broker origin): self-signed login warrant (config key, per RP audience) +
// /access/mint (device-cert-authed) + 300s assertion (fresh access key) →
// 4-object presentation. No cookies anywhere.
const store = require('./store');
const broker = require('./broker');
const { generateKey, jws, decodeJws, nowS, randHex } = require('./crypto');

// The broker-audience warrant behind the session join and the registry token
// exchange. Carries the `registry` scope (ig9p / registry-api-v1 §3.1) —
// without it the token exchange refuses, and the cookie lane will too once
// the migration window closes. Deliberately REFLESS and unregistered: it is
// what the token lane itself authenticates with, so it cannot depend on the
// token lane (a v1 warrant without a status ref is conformant at the
// exchange); it never appears as a site grant on the account page.
async function ensureBrokerWarrant() {
  const s = store.state();
  const cached = (s.warrants || {})[broker.ORIGIN];
  if (cached && decodeJws(cached).exp > nowS() + 3600) return cached;
  const warrant = await jws(s.configKey, {
    typ: 'browserid-warrant-v1',
    iat: nowS(), exp: nowS() + 90 * 86400,
    grantor: s.identity, grantee: s.identity,
    holder: `${s.holderPrefix}.*`,
    audience: broker.ORIGIN,
    scopes: ['login', 'registry'],
  });
  await store.set({ warrants: { ...(s.warrants || {}), [broker.ORIGIN]: warrant } });
  return warrant;
}

// An RP-audience login warrant, with the per-site revocation bit the
// prototype skipped: allocate the stable status ref over the registry API
// and embed it, then register the signed warrant so it appears (revocably)
// on the account page. Both are best-effort — a broker outage must not
// break signing in.
async function ensureWarrant(audience) {
  const s = store.state();
  const cached = (s.warrants || {})[audience];
  if (cached && decodeJws(cached).exp > nowS() + 3600) return cached;

  const registry = require('./registry');
  let ref = (s.warrantRefs || {})[audience] || null;
  if (!ref) {
    try {
      ref = await registry.allocateStatus(audience, ['login']);
    } catch (e) {
      console.warn('[wallet] status allocation failed (warrant will be refless):', e.message || e);
    }
  }
  const claims = {
    typ: 'browserid-warrant-v1',
    iat: nowS(), exp: nowS() + 90 * 86400,
    grantor: s.identity, grantee: s.identity,
    holder: `${s.holderPrefix}.*`,
    audience, scopes: ['login'],
  };
  if (ref) claims.status = ref;
  const warrant = await jws(s.configKey, claims);
  await store.set({
    warrants: { ...(store.state().warrants || {}), [audience]: warrant },
    warrantRefs: { ...(store.state().warrantRefs || {}), ...(ref ? { [audience]: ref } : {}) },
  });
  try {
    await registry.registerWarrant(warrant);
  } catch (e) {
    console.warn('[wallet] warrant registration failed (login proceeds):', e.message || e);
  }
  return warrant;
}

async function mintAccess(audience) {
  const s = store.state();
  const access = await generateKey();
  const claims = {
    typ: 'browserid-access-request-v1',
    iat: nowS(), exp: nowS() + 600, jti: randHex(16),
    domain: s.domain, identity: s.identity, holder: s.holder,
    'access-key': { algorithm: 'Ed25519', publicKey: access.x },
  };
  // Managed identities mint per-audience access certs (spec §4.2/§4.7) —
  // name the audience ONLY when the device cert is marked managed.
  if (decodeJws(s.deviceCert).managed === true) claims.audience = audience;
  const areq = await jws(s.deviceKey, claims);
  const mintUrl = s.mintUrl || `${broker.BROKER}/access/mint`;
  const res = await fetch(mintUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': broker.UA },
    body: JSON.stringify({ device_cert: s.deviceCert, access_request: areq }),
  });
  const mint = { status: res.status, data: await res.json().catch(() => ({})) };
  if (mint.status !== 200 || !mint.data.access_cert) {
    throw new Error(`access/mint failed: ${mint.status} ${mint.data.reason || JSON.stringify(mint.data).slice(0, 200)}`);
  }
  return { cert: mint.data.access_cert, privJwk: access.privJwk };
}

// The registry token exchange's input (registry-api-v1 §3.1): a fresh
// presentation for the BROKER's own audience. A fresh assertion every time —
// the exchange is single-use per assertion.
async function buildBrokerPresentation() {
  const s = store.state();
  if (!s.deviceCert) throw new Error('wallet not bootstrapped');
  const warrant = await ensureBrokerWarrant();
  const access = await mintAccess(broker.ORIGIN);
  const assertion = await jws(access.privJwk, { exp: nowS() + 300, aud: broker.ORIGIN });
  return `${access.cert}~${assertion}~${warrant}~${s.configCert}`;
}

async function login({ origin, caller, approveLogin, acceptedFallbacks }) {
  const s = store.state();
  if (!s.deviceCert) return { error: 'wallet not bootstrapped' };
  // Core §8.1 (bean u6jq): the RP names the fallback IdPs its verifier
  // accepts. Our identity is fallback-issued when its issuer differs from
  // the email's domain; if that issuer is not in the RP's set, the login
  // will be rejected at verification — warn the human before they approve.
  let warning = null;
  const emailDomain = (s.identity || '').split('@')[1] || '';
  const fallbackIssued =
    s.domain && emailDomain && s.domain.toLowerCase() !== emailDomain.toLowerCase();
  if (
    fallbackIssued &&
    Array.isArray(acceptedFallbacks) &&
    !acceptedFallbacks.some((f) => String(f).toLowerCase() === s.domain.toLowerCase())
  ) {
    warning = `This site does not accept ${s.domain} (the service that vouches for `
      + `${s.identity}), so the sign-in will likely be rejected.`;
  }
  const ok = process.env.WALLET_AUTO_APPROVE === '1'
    || (await approveLogin({ origin, email: s.identity, caller, warning }));
  if (!ok) return { error: 'user cancelled' };

  const warrant = await ensureWarrant(origin);
  const access = await mintAccess(origin);
  const assertion = await jws(access.privJwk, { exp: nowS() + 300, aud: origin });
  const presentation = `${access.cert}~${assertion}~${warrant}~${s.configCert}`;
  return { presentation, email: s.identity };
}

module.exports = { login, ensureWarrant, ensureBrokerWarrant, mintAccess, buildBrokerPresentation };
