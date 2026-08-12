// The authorization-code lane end to end against a MOCK BROKER over real
// HTTP (the github-mcp mocking idiom: a local mock server, env-shaped base
// URL, default global fetch). The mock implements the four broker surfaces
// the lane touches — /warrant/request (records the return_url), /consent/<w>
// (auto-approves and 302s to the recorded return_url, exactly like the real
// consent page after the human clicks Allow), /warrant/poll (single
// delivery), /verify-access + /status/check — and the test drives
// discover → register → authorize → [browser bounce] → return → token →
// authenticate, asserting a working attributed bearer and the fail-closed
// revoke on the lane-minted bearer.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import {
  createMcpAuth,
  createAuthCodeLane,
  McpAuthError,
} from "../index.mjs";
import { KeyPair } from "@browserid-ng/agent";

const BROKER_PORT = 43331;
const BROKER = process.env.BROWSERID_BROKER || `http://localhost:${BROKER_PORT}`;
const RESOURCE = "https://notes.gate.example";
const GATEWAY = "gate@example.com";
const HUMAN = "dan@example.com";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (claims) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(claims)}.c2ln`;
const nowS = () => Math.floor(Date.now() / 1000);

// The gateway's credential (a real device keypair; certs are canned claims —
// the MOCK broker doesn't verify signatures, the real one does).
const gatewayKp = KeyPair.generate();
const credential = {
  device_key: Buffer.from(gatewayKp.seed).toString("base64url"),
  agent_device_cert: fakeJws({
    typ: "browserid-device-cert-v1",
    "public-key": { algorithm: "Ed25519", publicKey: gatewayKp.publicKeyB64 },
    holder: "svc.gate1",
    identities: [GATEWAY],
    purpose: "authentication",
    iat: nowS(),
    exp: nowS() + 90 * 24 * 3600,
  }),
  idp: BROKER,
  identity: GATEWAY,
};

const WARRANT = fakeJws({
  typ: "browserid-warrant-v1",
  grantor: HUMAN,
  grantee: GATEWAY,
  holder: "svc.gate1",
  audience: RESOURCE,
  scopes: ["notes:read", "notes:write"],
  iat: nowS(),
  exp: nowS() + 90 * 24 * 3600,
});
const CONFIG_CERT = fakeJws({
  typ: "browserid-device-cert-v1",
  purpose: "authorization",
  iat: nowS(),
  exp: nowS() + 90 * 24 * 3600,
});

// --- the mock broker ----------------------------------------------------------

// wcode -> { returnUrl, state: "pending"|"approved"|"delivered", identity }
const consentRequests = new Map();
let statusMode = "ok"; // "ok" | "revoked"
let nextWcode = 1;

const broker = createServer(async (req, res) => {
  const reply = (code, obj, headers = {}) => {
    res.writeHead(code, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(obj));
  };
  let raw = "";
  for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  const url = new URL(req.url, BROKER);

  if (req.method === "POST" && url.pathname === "/warrant/request") {
    // The real registrar's checks the lane depends on: a device cert, one
    // grant per audience, and an ORIGIN-VALIDATED return_url (must match the
    // requester's identity domain or a grant audience's origin).
    assert.ok(body.device_cert, "warrant request authenticates with the device cert");
    assert.equal(body.identity, GATEWAY);
    assert.equal(body.grants.length, 1);
    if (body.return_url) {
      const ret = new URL(body.return_url);
      const ok = body.grants.some((g) => {
        try {
          return new URL(g.audience).origin === ret.origin;
        } catch {
          return false;
        }
      }) || ret.hostname === GATEWAY.split("@")[1];
      if (!ok) return reply(400, { success: false, reason: "return_url origin does not belong to the requesting service" });
    }
    const wcode = `w${nextWcode++}`;
    consentRequests.set(wcode, { returnUrl: body.return_url || null, state: "pending" });
    return reply(200, {
      success: true,
      code: wcode,
      verification_uri: `${BROKER}/consent`,
      verification_uri_complete: `${BROKER}/consent/${wcode}`,
      expires_in: 900,
      interval: 5,
    });
  }

  // The human's approval: GET the consent link → auto-approve → 302 to the
  // recorded (validated) return_url, like the consent page after Allow.
  if (req.method === "GET" && url.pathname.startsWith("/consent/")) {
    const wcode = url.pathname.slice("/consent/".length);
    const rec = consentRequests.get(wcode);
    if (!rec) return reply(404, { success: false });
    rec.state = "approved";
    if (rec.returnUrl) return reply(302, {}, { location: rec.returnUrl });
    return reply(200, { success: true });
  }

  if (req.method === "POST" && url.pathname === "/warrant/poll") {
    const rec = consentRequests.get(body.code);
    if (!rec) return reply(410, { success: false, reason: "gone" });
    if (rec.state === "pending") return reply(200, { success: true, status: "pending" });
    // Single delivery, like the real registrar.
    consentRequests.delete(body.code);
    return reply(200, {
      success: true,
      status: "approved",
      grants: [{ audience: RESOURCE, warrant: `${WARRANT}~${CONFIG_CERT}` }],
    });
  }

  if (req.method === "POST" && url.pathname === "/access/mint") {
    assert.equal(body.device_cert, credential.agent_device_cert);
    return reply(200, {
      success: true,
      access_cert: fakeJws({ typ: "browserid-access-cert-v1", exp: nowS() + 3600 }),
    });
  }

  if (req.method === "POST" && url.pathname === "/verify-access") {
    // The verifier binds the audience — the same check Lane A rides.
    assert.equal(body.audience, RESOURCE, "verify-access binds the bearer to THIS resource");
    const parts = String(body.presentation).split("~");
    if (parts.length !== 4 || parts[2] !== WARRANT || parts[3] !== CONFIG_CERT) {
      return reply(200, { status: "failure", reason: "not the issued warrant" });
    }
    return reply(200, {
      status: "okay",
      email: HUMAN,
      grantee: GATEWAY,
      holder: "svc.gate1",
      issuer: "example.com",
      scopes: ["notes:read", "notes:write"],
      status_refs: [{ uri: `${BROKER}/.well-known/browserid-status`, idx: 3 }],
    });
  }

  if (req.method === "POST" && url.pathname === "/status/check") {
    return reply(200, { ok: true, revoked: statusMode === "revoked" });
  }

  reply(404, { error: "not_found" });
});

before(() => new Promise((resolve) => broker.listen(BROKER_PORT, resolve)));
after(() => broker.close());

// --- the gateway under test ----------------------------------------------------

const mcpAuth = createMcpAuth({
  resource: RESOURCE,
  broker: BROKER,
  scopesForTool: { read_note: ["notes:read"], write_note: ["notes:write"], admin: ["notes:admin"] },
  statusCacheS: 0, // re-check revocation on every authenticate
});
const authCode = createAuthCodeLane({
  mcpAuth,
  credential,
  label: "notes gateway",
});

const s256 = (v) => createHash("sha256").update(v, "ascii").digest("base64url");

test("discover → register → authorize → approve → return → token → authenticate, end to end", async () => {
  // 1. Discovery: a stock OAuth host finds everything it needs.
  const asm = authCode.authorizationServerMetadata();
  assert.equal(asm.authorization_endpoint, `${RESOURCE}/authorize`);
  assert.equal(asm.registration_endpoint, `${RESOURCE}/register`);
  assert.equal(asm.token_endpoint, `${RESOURCE}/token`);
  assert.ok(asm.grant_types_supported.includes("authorization_code"));
  assert.deepEqual(asm.code_challenge_methods_supported, ["S256"]);

  // 2. DCR: the host self-registers.
  const reg = authCode.handleRegister({
    redirect_uris: [REDIRECT],
    client_name: "claude.ai",
    token_endpoint_auth_method: "none",
  });

  // 3. /authorize: PKCE + state, exactly what a generic host sends.
  const verifier = randomBytes(48).toString("base64url");
  const hostState = randomBytes(12).toString("base64url");
  const authz = await authCode.handleAuthorize({
    response_type: "code",
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_challenge: s256(verifier),
    code_challenge_method: "S256",
    scope: "notes:read notes:write",
    state: hostState,
  });
  assert.match(authz.redirect, new RegExp(`^${BROKER}/consent/w\\d+$`), "browser sent to the consent page");

  // 4. The browser: open the consent page; the (mock) human approves; the
  //    broker 302s the browser to the origin-validated return_url.
  const consentRes = await fetch(authz.redirect, { redirect: "manual" });
  assert.equal(consentRes.status, 302, "consent approval bounces the browser back");
  const returnUrl = consentRes.headers.get("location");
  assert.ok(returnUrl.startsWith(`${RESOURCE}/authorize/return?st=`), `return_url: ${returnUrl}`);

  // 5. The gateway's return leg: poll the approval, mint the single-use code.
  const st = new URL(returnUrl).searchParams.get("st");
  const back = await authCode.handleAuthorizeReturn({ st });
  const cb = new URL(back.redirect);
  assert.equal(cb.origin + cb.pathname, REDIRECT, "redirects to the host's registered redirect_uri");
  assert.equal(cb.searchParams.get("state"), hostState, "host state round-trips");
  const code = cb.searchParams.get("code");
  assert.ok(code);

  // 6. /token: PKCE-bound exchange mints a Lane-A-shaped bearer.
  const tok = await authCode.handleToken({
    grant_type: "authorization_code",
    code,
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  });
  assert.equal(tok.token_type, "Bearer");
  assert.ok(tok.access_token.startsWith("bat_"));
  assert.equal(tok.scope, "notes:read notes:write");

  // 7. The gated call: the SAME authenticate/requireWarrant path as Lane A,
  //    with full attribution from the warrant.
  const ctx = await mcpAuth.requireWarrant(`Bearer ${tok.access_token}`, "write_note");
  assert.equal(ctx.grantor, HUMAN, "attributed to the approving human");
  assert.equal(ctx.grantee, GATEWAY, "acted by the gateway agent");
  assert.deepEqual(ctx.scopes, ["notes:read", "notes:write"]);
  await assert.rejects(
    () => mcpAuth.requireWarrant(`Bearer ${tok.access_token}`, "admin"),
    (e) => e.oauthError === "insufficient_scope"
  );

  // 8. The code was single-use.
  await assert.rejects(
    () =>
      authCode.handleToken({
        grant_type: "authorization_code",
        code,
        client_id: reg.client_id,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }),
    (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant"
  );

  // 9. The flagship property, on a LANE-B bearer: a revoke fails the next
  //    call closed — same per-call status re-check as Lane A.
  statusMode = "revoked";
  try {
    await assert.rejects(
      () => mcpAuth.authenticate(`Bearer ${tok.access_token}`),
      (e) => e.oauthError === "invalid_token" && /revoked/.test(e.message)
    );
  } finally {
    statusMode = "ok";
  }
});

test("the mock broker refuses a foreign return_url (the origin validation the real broker enforces)", async () => {
  const reg = authCode.handleRegister({ redirect_uris: [REDIRECT] });
  // Point the lane at a poisoned resource by driving requestWarrants
  // indirectly is not possible — the lane pins return_url to its own
  // resource. Instead prove the mock's guard itself (parity with the real
  // registrar test in browserid-broker/tests/warrant_return_url_test.rs).
  const res = await fetch(`${BROKER}/warrant/request`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      device_cert: credential.agent_device_cert,
      identity: GATEWAY,
      grants: [{ audience: RESOURCE, scopes: [] }],
      return_url: "https://evil.example/phish",
    }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.match(body.reason, /return_url origin/);
  assert.ok(reg.client_id); // silence unused
});
