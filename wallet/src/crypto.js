// Ed25519 + JWS helpers matching the protocol exactly (dialog.js and
// scripts/e2e/smoke-prod-dc.mjs): fixed header {alg:"EdDSA", typ:"JWT"},
// base64url raw signatures over utf8(header.payload) — plus the registry
// API's request proof (registry-api-v1 §3.2), which pins its own typ.
const { webcrypto: crypto } = require('node:crypto');
const { createHash } = require('node:crypto');

const b64uj = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const HDR = b64uj({ alg: 'EdDSA', typ: 'JWT' });
const PROOF_TYP = 'browserid-registry-proof-v1';
const nowS = () => Math.floor(Date.now() / 1000);
const randHex = (n = 16) =>
  [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');

// Extractable keys — the app persists them (encrypted at rest via the OS
// keychain, see store.js). Ed25519 stays in software: Secure Enclave signs
// P-256 only, so enclave custody would mean a protocol suite change (bean
// hd63 territory), not a wallet change.
async function generateKey() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { privJwk, x: (await crypto.subtle.exportKey('jwk', kp.publicKey)).x };
}

async function importPriv(privJwk) {
  return crypto.subtle.importKey('jwk', privJwk, { name: 'Ed25519' }, false, ['sign']);
}

async function signJws(privJwk, header, claims) {
  const key = await importPriv(privJwk);
  const payload = b64uj(claims);
  const sig = Buffer.from(
    await crypto.subtle.sign({ name: 'Ed25519' }, key, new TextEncoder().encode(`${header}.${payload}`))
  ).toString('base64url');
  return `${header}.${payload}.${sig}`;
}

const jws = (privJwk, claims) => signJws(privJwk, HDR, claims);

const decodeJws = (j) => JSON.parse(Buffer.from(j.split('.')[1], 'base64url').toString());

const sha256b64u = (s) => createHash('sha256').update(s).digest('base64url');

// A registry API request proof (registry-api-v1 §3.2), signed with the
// CONFIG key the token is bound to: htm/htu/iat/jti/ath under the
// domain-separating proof typ.
function proof(configPrivJwk, method, htu, accessToken) {
  return signJws(configPrivJwk, b64uj({ alg: 'EdDSA', typ: PROOF_TYP }), {
    htm: method,
    htu,
    iat: nowS(),
    jti: randHex(12),
    ath: sha256b64u(accessToken),
  });
}

module.exports = { generateKey, jws, proof, decodeJws, nowS, randHex, sha256b64u };
