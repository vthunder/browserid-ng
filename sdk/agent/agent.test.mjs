import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFile, rm } from "node:fs/promises";

import { Agent, Credential, AmbiguousNameError, NoWarrantError } from "./index.mjs";
import { KeyPair, publicKeyField, decodeJwtClaims, verifyJws, PublicKey, b64u } from "./src/crypto.mjs";
import { nowS, parseCert, backedPresentation } from "./src/protocol.mjs";

const HDR = { alg: "EdDSA", typ: "JWT" };
const IDP = "https://idp.test";
const BROKER = "https://broker.test";
const IDP_DOMAIN = "idp.test";

// Build a test credential (U_cert~P_cert) with the given constraint. The issuer
// and user keys are ours; the P_cert carries the constraint the SDK reads.
function makeCredential({ names = [], patterns = [] } = {}) {
  const userKey = KeyPair.generate();      // the delegator ("alice") identity key
  const provKey = KeyPair.generate();      // P_priv
  const uCert = userKey.jws(HDR, {
    iss: "mingo.place", exp: nowS() + 99999, iat: nowS(),
    "public-key": publicKeyField(userKey.publicKeyB64), principal: { email: "alice@mingo.place" },
  });
  const pCert = userKey.jws(HDR, {
    typ: "browserid-provisioning-cert-v1", iss: "alice@mingo.place", iat: nowS(), exp: nowS() + 99999,
    "public-key": publicKeyField(provKey.publicKeyB64), constraint: { names, patterns },
  });
  const cred = new Credential({
    secret_key: b64u(provKey.seed), delegation: `${uCert}~${pCert}`, broker: BROKER, idp: IDP,
  });
  return { cred, userKey };
}

// A faithful-enough IdP+broker: it PARSES the bundles the SDK actually builds
// and issues a real chain, so the whole request shape is exercised.
function mockServer(userKey, { denyWarrant = false } = {}) {
  const issuerKey = KeyPair.generate(); // the IdP signing key
  let polls = 0;
  let grants = null;
  let agentEmail = null;
  const calls = [];
  const lastRequest = (bundle) => decodeJwtClaims(bundle.split("~").pop());

  return {
    issuerKey,
    calls,
    fetch: async (url, init) => {
      const path = new URL(url).pathname;
      const body = JSON.parse(init.body);
      calls.push(path);
      const ok = (o) => new Response(JSON.stringify({ success: true, ...o }), { status: 200 });

      if (path === "/provision/endorse") {
        return ok({ endorsement: issuerKey.jws(HDR, { typ: "browserid-provisioning-endorsement-v1", iat: nowS() }) });
      }
      if (path === "/provision/mint") {
        const r = lastRequest(body.request_bundle);
        assert.equal(r.typ, "browserid-provisioning-request-v1");
        assert.equal(r.action, "mint");
        assert.equal(r.domain, IDP_DOMAIN);           // domain pin = IdP domain
        const agentKeyB64 = r["agent-key"].publicKey;  // §2.2 embedding
        const email = `${r.name}@${IDP_DOMAIN}`;
        const cert = issuerKey.jws(HDR, {
          typ: "browserid-agent-cert-v1", iss: IDP_DOMAIN, iat: nowS(), exp: nowS() + 6 * 3600,
          "public-key": publicKeyField(agentKeyB64), principal: { email },
          agent: { parent: "alice@mingo.place" }, registrar: BROKER,
          status: { uri: `${BROKER}/.well-known/browserid-status`, idx: 1 },
        });
        return ok({ email, cert });
      }
      if (path === "/warrant/request") {
        const r = lastRequest(body.request_bundle);
        assert.equal(r.action, "warrant");
        assert.equal(r.domain, "broker.test");         // domain pin = registrar domain
        grants = r["warrant-grants"];
        agentEmail = `${r.name}@${IDP_DOMAIN}`;
        polls = 0;
        return ok({ code: "wrq_1", verification_uri: `${BROKER}/consent/wrq_1`, expires_in: 900, interval: 1 });
      }
      if (path === "/warrant/poll") {
        if (denyWarrant) return ok({ status: "denied" });
        if (polls++ === 0) return ok({ status: "pending" });
        // approve: sign a warrant per grant with the delegator (user) key
        const warrants = grants.map((g) =>
          userKey.jws(HDR, {
            typ: "browserid-agent-warrant-v1", iss: "alice@mingo.place", agent: agentEmail,
            aud: g.aud, ...(g.scopes ? { scopes: g.scopes } : {}), "parent-cert": "u.cert",
            status: { uri: `${BROKER}/.well-known/browserid-status`, idx: 2 }, iat: nowS(), exp: nowS() + 90 * 86400,
          })
        );
        return ok({ status: "approved", warrants, warrant: warrants.length === 1 ? warrants[0] : null });
      }
      if (path === "/provision/revoke") return ok({});
      throw new Error("unexpected path " + path);
    },
  };
}

// ---- crypto parity with browserid-core (Rust) ------------------------------

test("signing is byte-identical to the Rust core (known-answer vector)", () => {
  // Same seed (1..32) + message, cross-checked against ed25519-dalek in
  // browserid-core/src/keys.rs. Both are RFC 8032; this locks in the encoding.
  const kp = KeyPair.fromSeed(new Uint8Array(32).map((_, i) => i + 1));
  assert.equal(kp.publicKeyB64, "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ");
  assert.equal(kp.sign("aGVhZGVy.cGF5bG9hZA"),
    "XXPvOzV0JK3iY3oG_fHIaieC3Kd9sstOtCOl8jmQIW9p8f_tDHPXaHJ-Qab_HvHOAwR706iOUcxzrl0YMDEpAw");
});

// ---- credential + identity resolution --------------------------------------

test("credential: single reserved name resolves; pattern generates; multi is ambiguous", () => {
  assert.deepEqual(makeCredential({ names: ["tester"] }).cred.defaultIdentity(),
    { name: "tester", generated: false, domain: IDP_DOMAIN });
  const pat = makeCredential({ patterns: ["svc+*"] }).cred.defaultIdentity();
  assert.equal(pat.generated, true);
  assert.equal(pat.prefix, "svc");
  assert.equal(makeCredential({ names: ["a", "b"] }).cred.defaultIdentity(), null);
});

test("provision throws AmbiguousNameError for a multi-name credential", async () => {
  const { cred } = makeCredential({ names: ["a", "b"] });
  await assert.rejects(() => Agent.provision(cred, { http: async () => new Response("{}") }), AmbiguousNameError);
});

// ---- full flow against the faithful mock -----------------------------------

test("provision → request warrant → approve → assertion → revoke", async () => {
  const { cred, userKey } = makeCredential({ names: ["researcher"] });
  const srv = mockServer(userKey);
  const audience = "https://api.example.com";

  const agent = await Agent.provision(cred, { http: srv.fetch });
  assert.equal(agent.email, "researcher@idp.test");
  assert.ok(srv.calls.includes("/provision/endorse") && srv.calls.includes("/provision/mint"));

  // assertion before a warrant → NoWarrantError (agent cert needs one)
  await assert.rejects(() => agent.assertionFor(audience), NoWarrantError);

  // request a warrant: approveUrl surfaces immediately, approval resolves via poll
  const { approveUrl, approved } = await agent.requestWarrant(audience, ["post", "read"]);
  assert.equal(approveUrl, `${BROKER}/consent/wrq_1`);
  await approved;
  assert.deepEqual(agent.warrantedAudiences(), [audience]);
  assert.equal(agent.warrantCovers(audience, ["post"]), true);
  assert.equal(agent.warrantCovers(audience, ["delete"]), false);

  // a covering warrant means no new request
  const again = await agent.requestWarrant(audience, ["post"]);
  assert.equal(again.approveUrl, null);

  // assertion is the agent presentation: agent_cert ~ warrant ~ assertion
  const presentation = await agent.assertionFor(audience);
  const parts = presentation.split("~");
  assert.equal(parts.length, 3);
  const cert = parseCert(parts[0]);
  assert.equal(cert.isAgent, true);
  assert.equal(cert.email, "researcher@idp.test");
  assert.equal(decodeJwtClaims(parts[1]).typ, "browserid-agent-warrant-v1"); // warrant in the middle
  const assn = decodeJwtClaims(parts[2]);
  assert.equal(assn.aud, audience);

  // the assertion actually verifies against the cert's embedded agent key
  assert.equal(verifyJws(parts[2], PublicKey.fromB64u(cert.publicKeyB64)), true);

  await agent.revoke();
  assert.ok(srv.calls.includes("/provision/revoke"));
});

test("bootstrap: pair → poll → provisioned Agent (no downloaded credential)", async () => {
  const userKey = KeyPair.generate();   // delegator (human) identity key
  const issuerKey = KeyPair.generate(); // IdP signing key
  let suppliedPubkey = null, polls = 0;
  const uCert = userKey.jws(HDR, { iss: "mingo.place", exp: nowS() + 99999, iat: nowS(),
    "public-key": publicKeyField(userKey.publicKeyB64), principal: { email: "alice@mingo.place" } });

  const http = async (url, init) => {
    const path = new URL(url).pathname;
    const body = JSON.parse(init.body);
    const ok = (o) => new Response(JSON.stringify({ success: true, ...o }), { status: 200 });
    if (path === "/agent-provision/request") {
      suppliedPubkey = body.provisioning_pubkey.publicKey;  // the AGENT's key — never a server secret
      assert.deepEqual(body.requested_handles, { names: ["researcher"] });
      return ok({ code: "aprv_1", verification_uri: BROKER + "/link",
        verification_uri_complete: BROKER + "/agent-provision/aprv_1", user_code: "WXYZ-1234",
        fingerprint: "AA-BB-CC", expires_in: 900, interval: 1 });
    }
    if (path === "/agent-provision/poll") {
      if (polls++ === 0) return ok({ status: "pending" });
      // human approved: broker returns a delegation signed over the AGENT-supplied pubkey
      const pCert = userKey.jws(HDR, { typ: "browserid-provisioning-cert-v1", iss: "alice@mingo.place",
        iat: nowS(), exp: nowS() + 99999, "public-key": publicKeyField(suppliedPubkey),
        constraint: { names: ["researcher"], patterns: [] } });
      return ok({ status: "completed", credential: {
        delegation: `${uCert}~${pCert}`, broker: BROKER, idp: IDP, names: ["researcher"], patterns: [] } });
    }
    if (path === "/provision/endorse") return ok({ endorsement: issuerKey.jws(HDR, { typ: "e", iat: nowS() }) });
    if (path === "/provision/mint") {
      const r = decodeJwtClaims(body.request_bundle.split("~").pop());
      const email = `${r.name}@${IDP_DOMAIN}`;
      return ok({ email, cert: issuerKey.jws(HDR, { typ: "browserid-agent-cert-v1", iss: IDP_DOMAIN,
        iat: nowS(), exp: nowS() + 6 * 3600, "public-key": publicKeyField(r["agent-key"].publicKey),
        principal: { email }, agent: { parent: "alice@mingo.place" }, registrar: BROKER,
        status: { uri: BROKER + "/s", idx: 1 } }) });
    }
    throw new Error("unexpected " + path);
  };

  const pairing = await Agent.bootstrap({ broker: BROKER, requestedHandles: { names: ["researcher"] }, label: "my agent", http });
  assert.equal(pairing.verificationUriComplete, BROKER + "/agent-provision/aprv_1");
  assert.equal(pairing.userCode, "WXYZ-1234");
  assert.ok(pairing.fingerprint);
  const agent = await pairing.ready;   // resolves once the human approves
  assert.equal(agent.email, "researcher@idp.test");
  assert.equal(agent.identity().names[0], "researcher");
});

test("denied consent rejects the approved promise", async () => {
  const { cred, userKey } = makeCredential({ names: ["researcher"] });
  const agent = await Agent.provision(cred, { http: mockServer(userKey).fetch });
  const denied = mockServer(userKey, { denyWarrant: true });
  // swap the agent's http by provisioning a fresh one on the denying server
  const agent2 = await Agent.provision(cred, { http: denied.fetch });
  const { approved } = await agent2.requestWarrant("https://x.example", ["post"]);
  await assert.rejects(() => approved, /denied/);
});

test("save / open round-trips identity + warrants", async () => {
  const { cred, userKey } = makeCredential({ names: ["researcher"] });
  const srv = mockServer(userKey);
  const audience = "https://api.example.com";
  const path = join(tmpdir(), `agent-sdk-test-${process.pid}.identity.json`);
  try {
    const agent = await Agent.provision(cred, { http: srv.fetch });
    await agent.obtainWarrant(audience, ["post", "read"]);
    await agent.save(path);

    const stored = JSON.parse(await readFile(path, "utf8"));
    assert.equal(stored.email, "researcher@idp.test");
    assert.equal(stored.warrants.length, 1);

    // reopen (file exists → loads, no provision)
    const reopened = await Agent.open(cred, path, { http: srv.fetch });
    assert.equal(reopened.email, "researcher@idp.test");
    assert.equal(reopened.warrantCovers(audience, ["post"]), true);
  } finally {
    await rm(path, { force: true });
  }
});
