// The credential-less CONNECTION mode of the authorization-code lane (spec
// §7.5 + §6.4) against a mock broker over real HTTP: capability detection
// via the support document's `record-grants`, the connection grant request +
// audience proof, the delivered record validated at /validate-record,
// bearers + rotating refresh tokens bound to (binding.id, record), and the
// freshness-backed mint (a revoked/unvalidatable record stops refresh cold).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { createMcpAuth, createAuthCodeLane, McpAuthError } from "../index.mjs";

const BROKER_PORT = 43332;
const BROKER = `http://localhost:${BROKER_PORT}`;
const RESOURCE = "https://notes.gate.example";
const HUMAN = "dan@example.com";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const BINDING_ID = "cn_8f3a";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (claims) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(claims)}.c2ln`;
const nowS = () => Math.floor(Date.now() / 1000);

const RECORD = `${fakeJws({
  typ: "browserid-warrant-v2",
  grantor: HUMAN,
  grantee: HUMAN,
  binding: { kind: "connection", protocol: "oauth", id: BINDING_ID, client_host: "claude.ai", client_name: "Claude" },
  audience: RESOURCE,
  scopes: ["notes:read", "notes:write"],
  status: { uri: `${BROKER}/.well-known/browserid-status`, idx: 168 },
  iat: nowS(),
  exp: nowS() + 90 * 24 * 3600,
})}~${fakeJws({ typ: "browserid-device-cert-v1", purpose: "authorization" })}`;

// --- the mock broker ---------------------------------------------------------

// request_id -> { challenge, state: "pending"|"approved", audience }
const recordRequests = new Map();
let nextId = 1;
let advertiseSupport = true;
let validateMode = "ok"; // "ok" | "revoked" | "down"
let validateClientHost = "claude.ai";
let validateCalls = 0;

const broker = createServer(async (req, res) => {
  const reply = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  let raw = "";
  for await (const chunk of req) raw += chunk;
  const body = raw ? JSON.parse(raw) : {};
  const url = new URL(req.url, BROKER);

  if (url.pathname === "/.well-known/browserid") {
    return reply(200, advertiseSupport ? { "record-grants": "/warrant/record-request" } : {});
  }
  if (url.pathname === "/warrant/record-request") {
    if (body.type === "connection") {
      assert.equal(body.audience, RESOURCE);
      assert.equal(body.client?.client_host, "claude.ai");
    } else {
      assert.equal(body.type, "authoring");
      assert.ok(Array.isArray(body.grants) && body.grants.length > 0);
    }
    const requestId = `req_${nextId++}`;
    const challenge = randomBytes(24).toString("base64url");
    recordRequests.set(requestId, { challenge, state: "pending", returnUrl: body.return_url });
    return reply(200, {
      success: true,
      request_id: requestId,
      challenge,
      consent_uri: `${BROKER}/consent/${requestId}`,
      expires_in: 900,
      interval: 0,
    });
  }
  if (url.pathname === "/warrant/poll") {
    const r = recordRequests.get(body.request_id || body.code);
    if (!r) return reply(404, { success: false, reason: "not found" });
    if (r.state === "pending") return reply(200, { success: true, status: "pending" });
    recordRequests.delete(body.request_id || body.code); // single delivery
    return reply(200, {
      success: true,
      status: "approved",
      grants: r.deliver || [{ audience: RESOURCE, warrant: memberConnection ? MEMBER_RECORD : RECORD }],
    });
  }
  if (url.pathname === "/validate-record") {
    validateCalls++;
    if (validateExtra(body, reply)) return;
    if (validateMode === "down") return reply(503, { status: "failure", reason: "down" });
    if (validateMode === "revoked") return reply(200, { status: "failure", reason: "warrant revoked" });
    assert.equal(body.record, RECORD);
    assert.equal(body.audience, RESOURCE);
    return reply(200, {
      status: "okay",
      grantor: HUMAN,
      grantee: HUMAN,
      binding: {
        kind: "connection", protocol: "oauth", id: BINDING_ID,
        client_host: validateClientHost, client_name: "Claude",
      },
      scopes: ["notes:read", "notes:write"],
      issuer: "example.com",
      status_refs: [{ uri: `${BROKER}/.well-known/browserid-status`, idx: 168 }],
      expires_at: nowS() + 90 * 24 * 3600,
    });
  }
  if (url.pathname === "/status/check") {
    return reply(200, { ok: true, revoked: false });
  }
  reply(404, { error: "not found" });
});

before(() => new Promise((r) => broker.listen(BROKER_PORT, r)));
after(() => new Promise((r) => broker.close(r)));

function makeLane(overrides = {}) {
  const mcpAuth = createMcpAuth({
    resource: RESOURCE,
    broker: BROKER,
    scopesForTool: { read: ["notes:read"], write: ["notes:write"] },
  });
  const lane = createAuthCodeLane({
    mcpAuth,
    broker: BROKER,
    returnPollTries: 2,
    returnPollDelayMs: 10,
    ...overrides,
  });
  return { mcpAuth, lane };
}

const pkce = () => {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  return { verifier, challenge };
};

/** Drive register → authorize → (approve at broker) → return → code. */
async function authorizeToCode(lane, { verifier, challenge }) {
  const reg = lane.handleRegister({ redirect_uris: [REDIRECT], client_name: "Claude" });
  const authz = await lane.handleAuthorize({
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    response_type: "code",
    state: "host-state-1",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: "notes:read notes:write",
  });
  const consent = new URL(authz.redirect);
  assert.equal(consent.origin, BROKER, "redirects to the broker consent page");
  const requestId = consent.pathname.split("/").pop();
  // The audience proof is published, verbatim (the broker would fetch it).
  const r = recordRequests.get(requestId);
  assert.equal(lane.handleAudienceProof(requestId), r.challenge);
  // The human approves; the broker's consent page bounces to return_url.
  r.state = "approved";
  const st = new URL(r.returnUrl).searchParams.get("st");
  const ret = await lane.handleAuthorizeReturn({ st });
  const back = new URL(ret.redirect);
  assert.equal(back.origin + back.pathname, REDIRECT);
  assert.equal(back.searchParams.get("state"), "host-state-1");
  const code = back.searchParams.get("code");
  assert.ok(code, `expected a code, got ${ret.redirect}`);
  return { reg, code };
}

test("connection mode end to end: authorize → proof → record → tokens → ctx", async () => {
  validateMode = "ok";
  validateClientHost = "claude.ai";
  const { mcpAuth, lane } = makeLane();

  const meta = lane.authorizationServerMetadata();
  assert.ok(meta.grant_types_supported.includes("refresh_token"));

  const p = pkce();
  const { reg, code } = await authorizeToCode(lane, p);

  const tokens = await lane.handleToken({
    grant_type: "authorization_code",
    code,
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_verifier: p.verifier,
    scope: "notes:read notes:write",
  });
  assert.ok(tokens.access_token.startsWith("bat_"));
  assert.ok(tokens.refresh_token.startsWith("mrt_"));
  assert.ok(tokens.expires_in <= 3600, "bearer ≤ 1h");

  // The proof came down after resolution.
  assert.equal(lane.handleAudienceProof("req_1"), null);

  const ctx = await mcpAuth.authenticate(`Bearer ${tokens.access_token}`);
  assert.equal(ctx.grantor, HUMAN);
  assert.deepEqual(ctx.client, { name: "Claude", host: "claude.ai" });
  assert.deepEqual(ctx.scopes.sort(), ["notes:read", "notes:write"]);
});

test("refresh rotates, reuse burns the family, and every mint revalidates", async () => {
  validateMode = "ok";
  validateClientHost = "claude.ai";
  const { lane } = makeLane();
  const p = pkce();
  const { reg, code } = await authorizeToCode(lane, p);
  const t1 = await lane.handleToken({
    grant_type: "authorization_code", code,
    client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: p.verifier,
  });

  const callsBefore = validateCalls;
  const t2 = await lane.handleToken({ grant_type: "refresh_token", refresh_token: t1.refresh_token });
  assert.ok(t2.access_token && t2.access_token !== t1.access_token);
  assert.ok(t2.refresh_token && t2.refresh_token !== t1.refresh_token);
  assert.ok(validateCalls > callsBefore, "refresh minted with fresh /validate-record evidence");

  // Reusing the rotated token is theft evidence: family burned.
  await assert.rejects(
    lane.handleToken({ grant_type: "refresh_token", refresh_token: t1.refresh_token }),
    (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant"
  );
  await assert.rejects(
    lane.handleToken({ grant_type: "refresh_token", refresh_token: t2.refresh_token }),
    (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant",
    "the successor dies with the family"
  );
});

test("freshness-backed mint: no fresh evidence ⇒ no tokens", async () => {
  validateMode = "ok";
  validateClientHost = "claude.ai";
  const { lane } = makeLane();
  const p = pkce();
  const { reg, code } = await authorizeToCode(lane, p);
  const t1 = await lane.handleToken({
    grant_type: "authorization_code", code,
    client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: p.verifier,
  });

  // Revoked record → refresh fails (the connection goes dark within one
  // bearer TTL).
  validateMode = "revoked";
  await assert.rejects(
    lane.handleToken({ grant_type: "refresh_token", refresh_token: t1.refresh_token }),
    (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant"
  );
  // Unreachable validator is not evidence either (fail-closed, 503).
  validateMode = "down";
  await assert.rejects(
    lane.handleToken({ grant_type: "refresh_token", refresh_token: t1.refresh_token }),
    (e) => e instanceof McpAuthError && e.httpStatus === 400 || e.httpStatus === 503
  );
  validateMode = "ok";
});

test("client binding: a record for a different client_host never redeems", async () => {
  validateMode = "ok";
  validateClientHost = "evil.ai"; // the validator reveals a foreign custody host
  const { lane } = makeLane();
  const p = pkce();
  const reg = lane.handleRegister({ redirect_uris: [REDIRECT], client_name: "Claude" });
  const authz = await lane.handleAuthorize({
    client_id: reg.client_id, redirect_uri: REDIRECT, response_type: "code",
    code_challenge: p.challenge, code_challenge_method: "S256",
  });
  const requestId = new URL(authz.redirect).pathname.split("/").pop();
  const r = recordRequests.get(requestId);
  r.state = "approved";
  const st = new URL(r.returnUrl).searchParams.get("st");
  const ret = await lane.handleAuthorizeReturn({ st });
  const back = new URL(ret.redirect);
  assert.equal(back.searchParams.get("error"), "access_denied");
  validateClientHost = "claude.ai";
});

test("no support advertised and no credential: authorize fails cleanly", async () => {
  advertiseSupport = false;
  const { lane } = makeLane({ capabilityCacheS: 0 });
  const p = pkce();
  const reg = lane.handleRegister({ redirect_uris: [REDIRECT] });
  const authz = await lane.handleAuthorize({
    client_id: reg.client_id, redirect_uri: REDIRECT, response_type: "code",
    code_challenge: p.challenge, code_challenge_method: "S256",
  });
  const back = new URL(authz.redirect);
  assert.equal(back.searchParams.get("error"), "temporarily_unavailable");
  advertiseSupport = true;
});

// ---------------------------------------------------------------------------
// §6.5 composition: policy records × connection records
// ---------------------------------------------------------------------------

const OWNER = "gwen@example.com";
const MEMBER = "erin@example.com";

// A connection record self-granted by MEMBER (not the owner).
const MEMBER_RECORD = `${fakeJws({
  typ: "browserid-warrant-v2",
  grantor: MEMBER,
  grantee: MEMBER,
  binding: { kind: "connection", protocol: "oauth", id: "cn_member1", client_host: "claude.ai", client_name: "Claude" },
  audience: RESOURCE,
  scopes: ["notes:read", "notes:write"],
  status: { uri: `${BROKER}/.well-known/browserid-status`, idx: 200 },
  iat: nowS(),
  exp: nowS() + 90 * 24 * 3600,
})}~${fakeJws({ typ: "browserid-device-cert-v1", purpose: "authorization" })}`;

// The OWNER's policy record granting MEMBER notes:read only.
const POLICY_RECORD = `${fakeJws({
  typ: "browserid-warrant-v2",
  grantor: OWNER,
  grantee: MEMBER,
  binding: { kind: "holder", matcher: "*" },
  audience: RESOURCE,
  scopes: ["notes:read"],
  status: { uri: `${BROKER}/.well-known/browserid-status`, idx: 300 },
  iat: nowS(),
  exp: nowS() + 90 * 24 * 3600,
})}~${fakeJws({ typ: "browserid-device-cert-v1", purpose: "authorization" })}`;

// Teach the mock validator about the extra records (it keys off the body).
// Modes: policyMode "ok" | "revoked" gates POLICY_RECORD only.
let policyMode = "ok";
let memberConnection = false; // poll delivers MEMBER_RECORD instead of RECORD
const validateExtra = (body, reply) => {
  if (body.record === MEMBER_RECORD) {
    reply(200, {
      status: "okay", grantor: MEMBER, grantee: MEMBER,
      binding: { kind: "connection", protocol: "oauth", id: "cn_member1", client_host: "claude.ai", client_name: "Claude" },
      scopes: ["notes:read", "notes:write"], issuer: "example.com",
      status_refs: [{ uri: `${BROKER}/.well-known/browserid-status`, idx: 200 }],
      expires_at: nowS() + 90 * 24 * 3600,
    });
    return true;
  }
  if (body.record === POLICY_RECORD) {
    if (policyMode === "revoked") {
      reply(200, { status: "failure", reason: "warrant revoked" });
      return true;
    }
    reply(200, {
      status: "okay", grantor: OWNER, grantee: MEMBER,
      binding: { kind: "holder", matcher: "*" },
      scopes: ["notes:read"], issuer: "example.com",
      status_refs: [{ uri: `${BROKER}/.well-known/browserid-status`, idx: 300 }],
      expires_at: nowS() + 90 * 24 * 3600,
    });
    return true;
  }
  return false;
};

test("authoring ceremony: raise → proof → owner signs → validated rows land in the store", async () => {
  validateMode = "ok";
  const { lane } = makeLane({ policy: { owners: [OWNER] } });
  const ceremony = await lane.requestAuthoring({
    grants: [{ grantee: MEMBER, scopes: ["notes:read"] }],
    pollDelayMs: 10,
  });
  assert.ok(ceremony.consentUri.startsWith(`${BROKER}/consent/`));
  // The proof is published while pending.
  const r = recordRequests.get(ceremony.requestId);
  assert.equal(lane.handleAudienceProof(ceremony.requestId), r.challenge);
  // The owner approves at the broker; delivery carries the policy record.
  r.state = "approved";
  r.deliver = [{ audience: RESOURCE, warrant: POLICY_RECORD }];
  const rows = await ceremony.wait();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].grantor, OWNER);
  assert.equal(rows[0].grantee, MEMBER);
  assert.deepEqual(rows[0].scopes, ["notes:read"]);
  // Proof came down after resolution.
  assert.equal(lane.handleAudienceProof(ceremony.requestId), null);
});

test("composition: a member admits under the owner's grant with S ∩ S′", async () => {
  validateMode = "ok";
  policyMode = "ok";
  memberConnection = true;
  const { mcpAuth, lane } = makeLane({ policy: { owners: [OWNER] } });
  await lane.policyStore.put({
    record: POLICY_RECORD, grantor: OWNER, grantee: MEMBER,
    audience: RESOURCE, scopes: ["notes:read"], exp: nowS() + 1000,
  });
  const p = pkce();
  const { reg, code } = await authorizeToCode(lane, p);
  const tokens = await lane.handleToken({
    grant_type: "authorization_code", code,
    client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: p.verifier,
  });
  // S′ = read+write (the member's connection), S = read (the owner's policy
  // row) → effective read only.
  assert.equal(tokens.scope, "notes:read");
  const ctx = await mcpAuth.authenticate(`Bearer ${tokens.access_token}`);
  assert.equal(ctx.grantor, MEMBER, "attributed to the member — the connection signer");
  assert.equal(ctx.permittedBy, OWNER, "permitted by the owner — never the author");
  assert.deepEqual(ctx.scopes, ["notes:read"]);
  memberConnection = false;
});

test("composition: no covering policy row refuses the member", async () => {
  validateMode = "ok";
  memberConnection = true;
  const { lane } = makeLane({ policy: { owners: [OWNER] } });
  // Empty policy store: the member's own valid connection record is not enough.
  const p = pkce();
  const { reg, code } = await authorizeToCode(lane, p);
  await assert.rejects(
    lane.handleToken({
      grant_type: "authorization_code", code,
      client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: p.verifier,
    }),
    (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant"
  );
  memberConnection = false;
});

test("composition: revoking the policy record kills the member's refresh (two-sided revocation)", async () => {
  validateMode = "ok";
  policyMode = "ok";
  memberConnection = true;
  const { lane } = makeLane({ policy: { owners: [OWNER] } });
  await lane.policyStore.put({
    record: POLICY_RECORD, grantor: OWNER, grantee: MEMBER,
    audience: RESOURCE, scopes: ["notes:read"], exp: nowS() + 1000,
  });
  const p = pkce();
  const { reg, code } = await authorizeToCode(lane, p);
  const t1 = await lane.handleToken({
    grant_type: "authorization_code", code,
    client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: p.verifier,
  });
  // G revokes the policy record → the member's next refresh finds no valid
  // covering row, even though the member's own connection record is fine.
  policyMode = "revoked";
  await assert.rejects(
    lane.handleToken({ grant_type: "refresh_token", refresh_token: t1.refresh_token }),
    (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant"
  );
  policyMode = "ok";
  memberConnection = false;
});

test("composition: the owner needs no policy row (degenerate G = E)", async () => {
  validateMode = "ok";
  const { lane } = makeLane({ policy: { owners: [HUMAN] } }); // RECORD's grantor
  const p = pkce();
  const { reg, code } = await authorizeToCode(lane, p);
  const tokens = await lane.handleToken({
    grant_type: "authorization_code", code,
    client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: p.verifier,
  });
  assert.deepEqual(tokens.scope.split(" ").sort(), ["notes:read", "notes:write"]);
});

test("authoring: a record from a non-owner grantor is refused", async () => {
  validateMode = "ok";
  const { lane } = makeLane({ policy: { owners: ["someone-else@example.com"] } });
  const ceremony = await lane.requestAuthoring({
    grants: [{ grantee: MEMBER, scopes: ["notes:read"] }],
    pollDelayMs: 10,
  });
  const r = recordRequests.get(ceremony.requestId);
  r.state = "approved";
  r.deliver = [{ audience: RESOURCE, warrant: POLICY_RECORD }]; // grantor = OWNER, not configured
  await assert.rejects(ceremony.wait(), (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant");
});
