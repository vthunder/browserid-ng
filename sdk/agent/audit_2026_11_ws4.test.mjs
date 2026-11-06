// Security audit 2026-11, WS4 (bean browserid-ng-n6nn): the agent SDK's key
// custody and what it signs. Tests that FAIL today are skipped with an
// `AUDIT-2026-11 W4-n: fails today` reason and are the acceptance test for
// the fix; the rest pin what the audit re-verified. No production code changed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";

import { requestProvision, DeviceAgent } from "./src/device.mjs";
import { KeyPair, publicKeyField, decodeJwtClaims, b64u } from "./src/crypto.mjs";
import { nowS, ASSERTION_VALIDITY_S } from "./src/protocol.mjs";

const HDR = { alg: "EdDSA", typ: "JWT" };
const BROKER = "https://broker.test";
const IDP = "https://idp.test";
const IDP_DOMAIN = "idp.test";
const EVIL = "https://evil.test";
const AUD = "https://rp.test";
const EMAIL = "alice@idp.test";
const HOLDER = "cfej8yyd.ysspc6qz53";

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** Minimal broker + IdP. `pollCredential` lets a test choose what the poll
 *  hands back (the `idp` / `access_mint` the agent will trust). */
function mockServer({ pollCredential = (dc) => ({ device_cert: dc, idp: IDP, identity: EMAIL }) } = {}) {
  const idpKey = KeyPair.generate();
  const state = { deviceCert: null, mintUrls: [] };
  const issueDeviceCert = (pubB64) =>
    idpKey.jws(HDR, {
      typ: "browserid-device-cert-v1", iss: IDP_DOMAIN, iat: nowS(), exp: nowS() + 99999,
      purpose: "authentication", holder: HOLDER, identities: [EMAIL], "public-key": publicKeyField(pubB64),
    });
  const issueWarrant = () =>
    idpKey.jws(HDR, {
      typ: "browserid-warrant-v2", iss: IDP_DOMAIN, iat: nowS(), exp: nowS() + 99999,
      grantor: EMAIL, grantee: EMAIL, audience: AUD, scopes: ["login"], binding: { holder: HOLDER },
    });
  const http = async (url, init) => {
    const body = JSON.parse(init.body);
    if (url === `${BROKER}/agent-provision/request`) {
      state.deviceCert = issueDeviceCert(body.provisioning_pubkey.publicKey);
      return json({ success: true, code: "c", user_code: "U", verification_uri: `${BROKER}/a`,
        verification_uri_complete: `${BROKER}/a?code=c`, fingerprint: "00-00-00", interval: 0 });
    }
    if (url === `${BROKER}/agent-provision/poll`) {
      return json({ status: "completed", credential: pollCredential(state.deviceCert),
        grants: [{ audience: AUD, warrant: `${issueWarrant()}~${state.deviceCert}` }] });
    }
    if (url.endsWith("/access/mint")) {
      state.mintUrls.push(url);
      const req = decodeJwtClaims(body.access_request);
      return json({ access_cert: idpKey.jws(HDR, {
        typ: "browserid-access-cert-v1", iss: IDP_DOMAIN, iat: nowS(), exp: nowS() + 300,
        identity: req.identity, holder: req.holder, "public-key": req["access-key"] }) });
    }
    throw new Error(`unexpected request to ${url}`);
  };
  return { http, state, idpKey, issueDeviceCert };
}

async function provisioned(opts) {
  const srv = mockServer(opts);
  const pending = await requestProvision(BROKER, { grants: [{ audience: AUD, scopes: ["login"] }], http: srv.http });
  const { credential, grants } = await pending.wait();
  return { ...srv, credential, grants };
}

// ---------------------------------------------------------------------------
// W4-42 — private key material is reachable through ordinary object dumps.
// `DeviceAgent.credential` is a plain public property holding `device_key`
// (the raw seed), and `KeyPair.seed` is public too, so `console.log(agent)`,
// util.inspect, or JSON.stringify of the agent prints the device key.
// ---------------------------------------------------------------------------
test("W4-42: inspecting a DeviceAgent does not print the device key seed", async () => {
  const { credential, http } = await provisioned();
  const agent = new DeviceAgent(credential, { http });
  const dump = inspect(agent, { depth: 5 }) + JSON.stringify(agent);
  assert.ok(!dump.includes(credential.device_key), "device key seed leaked through inspect/JSON");
});

test("W4-42: inspecting a KeyPair does not print its seed", () => {
  const kp = KeyPair.generate();
  // The seed is a public Uint8Array property: inspect prints its bytes.
  assert.ok(!/seed/.test(inspect(kp)), "seed leaked through inspect");
});

// ---------------------------------------------------------------------------
// W4-41 — the mint endpoint is whatever the poll response said. `idp` and
// `access_mint` are taken verbatim from the broker's poll body and never
// cross-checked against the signed device cert's `iss` (nor required to be
// https). A broker that lies sends the agent's device-key-signed access
// requests, pinned to the liar's domain, to the liar. No key leaves the
// process and the request is unusable at the real IdP (it is pinned to the
// wrong `domain`), so this is defence in depth, not an escalation.
// ---------------------------------------------------------------------------
test("W4-41: the agent mints only at the IdP that signed its device cert", async () => {
  const { credential, http, state } = await provisioned({
    pollCredential: (dc) => ({ device_cert: dc, idp: EVIL, identity: EMAIL }),
  });
  await assert.rejects(async () => {
    const agent = new DeviceAgent(credential, { http });
    await agent.mint();
  }, /iss|idp/i);
  assert.deepEqual(state.mintUrls, [], "no mint request may reach a host other than the cert's iss");
});

test("W4-41: a poll-supplied access_mint on another host or a cleartext scheme is refused", async () => {
  for (const access_mint of [`${EVIL}/access/mint`, "http://idp.test/access/mint"]) {
    const { credential, http, state } = await provisioned({
      pollCredential: (dc) => ({ device_cert: dc, idp: IDP, identity: EMAIL, access_mint }),
    });
    await assert.rejects(async () => new DeviceAgent(credential, { http }).mint(), /access_mint|iss|https/i);
    assert.deepEqual(state.mintUrls, []);
  }
});

// Pinned: what IS checked at construction (re-verified).
test("the device cert must certify the held key and name the identity", async () => {
  const { credential, http } = await provisioned();
  const other = KeyPair.generate();
  assert.throws(() => new DeviceAgent({ ...credential, device_key: b64u(other.seed) }, { http }), /does not certify/);
  assert.throws(() => new DeviceAgent({ ...credential, identity: "mallory@idp.test" }, { http }), /does not authorize/);
});

// ---------------------------------------------------------------------------
// D1, client mirror — `authorizesIdentity` in device.mjs repeats the core's
// purpose-blind subaddress rule: an AUTHENTICATION cert for alice@d is taken
// to authorize alice+tag@d. Spec §4.6: exact only for auth certs. Once the
// IdP side moves (decision Q1), the SDK must refuse the same request locally
// instead of minting into a server error.
// ---------------------------------------------------------------------------
test("D1 (client mirror): an auth cert for the base identity does not authorize a subaddress", async () => {
  const { credential, http } = await provisioned();
  assert.throws(() => new DeviceAgent({ ...credential, identity: "alice+bot@idp.test" }, { http }), /does not authorize/);
});

// ---------------------------------------------------------------------------
// Pinned: the access request and assertion carry what the spec requires.
// W4-40 (Q19 (a), bean b18d): the assertion carries `iat` like every other
// signed object, so the amended §6.1 time bounds (`iat ≤ exp`,
// `iat ≤ now + skew`) apply to it; §5's claim table lists it.
// ---------------------------------------------------------------------------
test("access request: 10-min window, jti, holder from the cert, domain = cert iss", async () => {
  const { credential, http } = await provisioned();
  const agent = new DeviceAgent(credential, { http });
  let seen;
  const spy = async (url, init) => { if (url.endsWith("/access/mint")) seen = JSON.parse(init.body); return http(url, init); };
  await new DeviceAgent(credential, { http: spy }).mint();
  const req = decodeJwtClaims(seen.access_request);
  assert.equal(req.typ, "browserid-access-request-v1");
  assert.equal(req.exp - req.iat, 600);
  assert.ok(typeof req.jti === "string" && req.jti.length >= 8);
  assert.equal(req.holder, decodeJwtClaims(credential.agent_device_cert).holder);
  assert.equal(req.domain, decodeJwtClaims(credential.agent_device_cert).iss);
  assert.equal(req.audience, undefined, "unmanaged: RP-blind");
  void agent;
});

test("W4-40 (fixed): the assertion names the audience exactly, expires in <=5 min, and carries iat", async () => {
  const { credential, http } = await provisioned();
  const agent = new DeviceAgent(credential, { http });
  for (const g of (await provisioned()).grants) agent.addGrant(g.grant);
  const [, assertion] = (await agent.assertionFor(AUD)).split("~");
  const c = decodeJwtClaims(assertion);
  assert.equal(c.aud, AUD);
  assert.ok(c.exp <= nowS() + ASSERTION_VALIDITY_S && c.exp > nowS());
  assert.ok(Number.isInteger(c.iat) && c.iat <= nowS(), "iat is set at signing (W4-40)");
  assert.equal(c.exp - c.iat, ASSERTION_VALIDITY_S);
  assert.equal(c.typ, undefined, "assertion has no claim-level typ (spec §4)");
});

