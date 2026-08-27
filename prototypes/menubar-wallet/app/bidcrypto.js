// Ed25519 + JWS helpers matching the protocol exactly (see dialog.js:224 and
// scripts/e2e/smoke-prod-dc.mjs): fixed header {alg:"EdDSA", typ:"JWT"},
// base64url raw signatures over utf8(header.payload).
const { webcrypto: crypto } = require('node:crypto');

const b64uj = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const HDR = b64uj({ alg: 'EdDSA', typ: 'JWT' });
const nowS = () => Math.floor(Date.now() / 1000);
const randHex = (n = 16) =>
  [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');

// Extractable keys — the app persists them (browser keystore custody rules
// don't apply outside an origin; Keychain custody is a follow-up).
async function generateKey() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { privJwk, x: (await crypto.subtle.exportKey('jwk', kp.publicKey)).x };
}

async function importPriv(privJwk) {
  return crypto.subtle.importKey('jwk', privJwk, { name: 'Ed25519' }, false, ['sign']);
}

async function jws(privJwk, claims) {
  const key = await importPriv(privJwk);
  const payload = b64uj(claims);
  const sig = Buffer.from(
    await crypto.subtle.sign({ name: 'Ed25519' }, key, new TextEncoder().encode(`${HDR}.${payload}`))
  ).toString('base64url');
  return `${HDR}.${payload}.${sig}`;
}

const decodeJws = (j) => JSON.parse(Buffer.from(j.split('.')[1], 'base64url').toString());

module.exports = { generateKey, jws, decodeJws, nowS, randHex };
