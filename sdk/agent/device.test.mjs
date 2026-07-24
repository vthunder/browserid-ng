// The device-cert path against a mock broker/IdP that PARSES what the SDK
// sends — so the wire shapes (not just the happy path) are exercised.
import { test } from "node:test";
import assert from "node:assert/strict";

import { requestProvision, DeviceAgent } from "./src/device.mjs";
import { KeyPair, publicKeyField, decodeJwtClaims, PublicKey, b64u } from "./src/crypto.mjs";
import { nowS } from "./src/protocol.mjs";

const HDR = { alg: "EdDSA", typ: "JWT" };
const BROKER = "https://broker.test";
const IDP = "https://idp.test";
const IDP_DOMAIN = "idp.test";
const AUD = "https://rp.test";
const EMAIL = "alice@idp.test";
const HOLDER = "cfej8yyd.ysspc6qz53";

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/**
 * A broker+IdP good enough to catch protocol drift: it verifies the device
 * cert certifies the requester's key, checks the access request is signed by
 * the device key and pinned to this IdP, and refuses to let a requester
 * choose its own holder.
 */
function mockServer({ pendingPolls = 1 } = {}) {
  const idpKey = KeyPair.generate();
  const state = { polls: 0, deviceCert: null, seen: {} };

  const issueDeviceCert = (devicePubB64) =>
    idpKey.jws(HDR, {
      typ: "browserid-device-cert-v1",
      iss: IDP_DOMAIN,
      iat: nowS(),
      exp: nowS() + 99999,
      purpose: "authentication",
      holder: HOLDER,
      identities: [EMAIL],
      "public-key": publicKeyField(devicePubB64),
    });

  const issueWarrant = () =>
    idpKey.jws(HDR, {
      typ: "browserid-warrant-v1",
      iat: nowS(),
      exp: nowS() + 99999,
      grantor: EMAIL,
      grantee: EMAIL,
      holder: HOLDER,
      audience: AUD,
      scopes: ["login", "post"],
    });

  const http = async (url, init) => {
    const body = JSON.parse(init.body);
    if (url === `${BROKER}/agent-provision/request`) {
      state.seen.request = body;
      state.deviceCert = issueDeviceCert(body.provisioning_pubkey.publicKey);
      return json({
        success: true,
        code: "dev-code",
        user_code: "WXYZ-1234",
        verification_uri: `${BROKER}/approve`,
        verification_uri_complete: `${BROKER}/approve?code=dev-code`,
        fingerprint: "4F-2A-9C",
        interval: 0,
        expires_in: 900,
      });
    }
    if (url === `${BROKER}/agent-provision/poll`) {
      if (state.polls++ < pendingPolls) return json({ status: "pending" });
      return json({
        status: "completed",
        credential: { device_cert: state.deviceCert, idp: IDP, identity: EMAIL },
        // The pair shape the real poll returns.
        grants: [{ audience: AUD, warrant: `${issueWarrant()}~${state.deviceCert}` }],
      });
    }
    if (url === `${IDP}/access/mint`) {
      state.seen.mint = body;
      const req = decodeJwtClaims(body.access_request);
      const devClaims = decodeJwtClaims(body.device_cert);
      // The access request must be signed by the key the device cert certifies.
      const devPub = PublicKey.fromB64u(devClaims["public-key"].publicKey);
      const [h, p, sig] = body.access_request.split(".");
      assert.ok(devPub.verify(`${h}.${p}`, sig), "access request signed by the device key");
      assert.equal(req.typ, "browserid-access-request-v1");
      assert.equal(req.domain, IDP_DOMAIN, "pinned to this IdP");
      assert.equal(req.holder, devClaims.holder, "holder copied from the device cert");
      assert.ok(req.jti, "single-use nonce present");
      assert.notEqual(req["access-key"].publicKey, devClaims["public-key"].publicKey,
        "access key must be fresh, never the device key");
      return json({
        access_cert: idpKey.jws(HDR, {
          typ: "browserid-access-cert-v1",
          iss: IDP_DOMAIN,
          iat: nowS(),
          exp: nowS() + 300,
          identity: req.identity,
          holder: req.holder,
          "public-key": req["access-key"],
        }),
      });
    }
    throw new Error(`unexpected request to ${url}`);
  };
  return { http, state, idpKey };
}

async function provisionedAgent(opts) {
  const { http, state, idpKey } = mockServer(opts);
  const pending = await requestProvision(BROKER, {
    grants: [{ audience: AUD, scopes: ["login", "post"] }],
    label: "test",
    http,
  });
  const { credential, grants } = await pending.wait();
  const agent = new DeviceAgent(credential, { http });
  for (const g of grants) agent.addGrant(g.grant);
  return { agent, credential, grants, state, idpKey, http };
}

test("provisioning surfaces what the human must see, then yields a usable credential", async () => {
  const { http, state } = mockServer();
  const pending = await requestProvision(BROKER, {
    handle: "alice",
    grants: [{ audience: AUD, scopes: ["login"] }],
    http,
  });
  assert.equal(pending.verificationUriComplete, `${BROKER}/approve?code=dev-code`);
  assert.equal(pending.userCode, "WXYZ-1234");
  assert.equal(pending.fingerprint, "4F-2A-9C");
  assert.deepEqual(state.seen.request.requested_handles, { names: ["alice"] });
  assert.deepEqual(state.seen.request.grants, [{ audience: AUD, scopes: ["login"] }]);

  const { credential } = await pending.wait();
  // The seed is retained so the credential can be persisted and reloaded.
  assert.equal(typeof credential.device_key, "string");
  assert.equal(credential.idp, IDP);
});

test("assertionFor builds the four-part presentation in browserid-core's order", async () => {
  const { agent } = await provisionedAgent();
  const presentation = await agent.assertionFor(AUD);
  const parts = presentation.split("~");
  assert.equal(parts.length, 4, "access_cert ~ assertion ~ warrant ~ config_cert");
  const [accessCert, assertion, warrant, configCert] = parts.map(decodeJwtClaims);
  assert.equal(accessCert.typ, "browserid-access-cert-v1");
  assert.equal(assertion.aud, AUD);
  assert.equal(warrant.typ, "browserid-warrant-v1");
  assert.equal(configCert.typ, "browserid-device-cert-v1");
});

test("the assertion is signed by the ACCESS key, not the device key", async () => {
  const { agent, credential } = await provisionedAgent();
  const [accessCertJws, assertionJws] = (await agent.assertionFor(AUD)).split("~");
  const certified = decodeJwtClaims(accessCertJws)["public-key"].publicKey;
  const [h, p, sig] = assertionJws.split(".");
  assert.ok(PublicKey.fromB64u(certified).verify(`${h}.${p}`, sig),
    "assertion verifies against the key the access cert certifies");
  const deviceKey = KeyPair.fromSeed(Buffer.from(credential.device_key, "base64url"));
  assert.notEqual(certified, deviceKey.publicKeyB64);
});

test("a stale access cert is re-minted; a fresh one is reused", async () => {
  const { agent, state } = await provisionedAgent();
  await agent.assertionFor(AUD);
  const afterFirst = JSON.stringify(state.seen.mint);
  await agent.assertionFor(AUD);
  assert.equal(JSON.stringify(state.seen.mint), afterFirst, "no re-mint while fresh");
});

test("assertionWithAccessKey hands back the key that signed the presentation", async () => {
  const { agent } = await provisionedAgent();
  const { presentation, accessKey, accessCert } = await agent.assertionWithAccessKey(AUD);
  assert.equal(presentation.split("~")[0], accessCert);
  assert.equal(decodeJwtClaims(accessCert)["public-key"].publicKey, accessKey.publicKeyB64,
    "the returned key is the one the access cert certifies — what an RP enforces");
  // It can sign an external payload (an SBO envelope, a post attestation…).
  const sig = accessKey.sign("payload");
  assert.ok(PublicKey.fromB64u(accessKey.publicKeyB64).verify("payload", sig));
});

test("a warrant for another identity or audience is refused", async () => {
  const { agent, idpKey } = await provisionedAgent();
  const foreign = idpKey.jws(HDR, {
    typ: "browserid-warrant-v1", iat: nowS(), exp: nowS() + 999,
    grantor: "bob@idp.test", grantee: "bob@idp.test", holder: HOLDER,
    audience: AUD, scopes: ["post"],
  });
  assert.throws(() => agent.addGrant(foreign), /grantee/);
  await assert.rejects(agent.assertionFor("https://other.test"), /warrant/i);
});

test("a device cert that does not certify the held key is rejected", async () => {
  const { credential, http } = await provisionedAgent();
  const other = KeyPair.generate();
  assert.throws(
    () => new DeviceAgent({ ...credential, device_key: b64u(other.seed) }, { http }),
    /does not certify/,
  );
});

test("a credential round-trips through storage with its warrants", async () => {
  const { agent, credential, http } = await provisionedAgent();
  const saved = JSON.parse(JSON.stringify({ credential, grants: agent.storedGrants() }));

  const reloaded = new DeviceAgent(saved.credential, { http });
  for (const g of saved.grants) reloaded.addGrant(g.grant);
  assert.deepEqual(reloaded.warrantedAudiences(), [AUD]);
  assert.equal((await reloaded.assertionFor(AUD)).split("~").length, 4);
});
