// Unit test for the wallet's crypto lane (no Electron, no network):
// protocol JWS shape + the registry-API request proof (§3.2). Run with
// `npm test`.
import { createRequire } from 'node:module';
import { webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
const { generateKey, jws, proof, decodeJws, sha256b64u } = require('./crypto.js');

const b64ud = (s) => Buffer.from(s, 'base64url');

async function importPub(x) {
  return webcrypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x }, { name: 'Ed25519' }, false, ['verify']);
}

async function verifyJws(token, x) {
  const [h, p, sig] = token.split('.');
  return webcrypto.subtle.verify(
    { name: 'Ed25519' },
    await importPub(x),
    b64ud(sig),
    new TextEncoder().encode(`${h}.${p}`)
  );
}

// Protocol JWS: fixed {alg:EdDSA, typ:JWT} header, verifiable signature.
{
  const kp = await generateKey();
  const token = await jws(kp.privJwk, { hello: 'world', exp: 123 });
  const header = JSON.parse(b64ud(token.split('.')[0]).toString());
  assert.deepEqual(header, { alg: 'EdDSA', typ: 'JWT' });
  assert.equal(decodeJws(token).hello, 'world');
  assert.equal(await verifyJws(token, kp.x), true);
  const other = await generateKey();
  assert.equal(await verifyJws(token, other.x), false);
  console.log('✓ protocol jws: header pinned, sign/verify round-trips');
}

// Registry request proof: its OWN typ (domain separation), htm/htu/iat/jti,
// ath = base64url(sha256(token)).
{
  const kp = await generateKey();
  const p = await proof(kp.privJwk, 'GET', 'https://registry.example/api/v1/requests', 'tok-123');
  const header = JSON.parse(b64ud(p.split('.')[0]).toString());
  assert.deepEqual(header, { alg: 'EdDSA', typ: 'browserid-registry-proof-v1' });
  const claims = decodeJws(p);
  assert.equal(claims.htm, 'GET');
  assert.equal(claims.htu, 'https://registry.example/api/v1/requests');
  assert.equal(claims.ath, sha256b64u('tok-123'));
  assert.ok(claims.jti.length >= 16 && Math.abs(claims.iat - Date.now() / 1000) < 5);
  assert.equal(await verifyJws(p, kp.x), true);
  // Distinct jti per proof (replay cache food).
  const p2 = await proof(kp.privJwk, 'GET', 'https://registry.example/api/v1/requests', 'tok-123');
  assert.notEqual(decodeJws(p2).jti, claims.jti);
  console.log('✓ registry proof: typ pinned, ath binds the token, fresh jti');
}

console.log('ceremony unit tests OK');
