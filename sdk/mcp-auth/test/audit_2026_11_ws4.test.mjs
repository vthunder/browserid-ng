// Security audit 2026-11, WS4 (bean browserid-ng-n6nn): the mcp-auth layer.
//
// Reviewer-then-skeptic tests for the WS1 candidates routed here (D5, D17,
// D20) plus the new W4-1x findings. Tests that FAIL today are skipped with
// `AUDIT-2026-11 <id>: fails today` — un-skipping is the acceptance test for
// the fix. Everything else passes today and pins what the audit re-verified.
// No production code changed. Fetch is injected; no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import {
  createMcpAuth,
  createAuthCodeLane,
  createMemoryStore,
  createPolicyStore,
  identityEq,
  granteeCovers,
  McpAuthError,
  JWT_BEARER_GRANT,
} from "../index.mjs";

const RESOURCE = "https://notes.example";
const BROKER = "https://broker.example";
const OWNER = "gwen@example.com";
const MEMBER = "erin@example.com";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const nowS = () => Math.floor(Date.now() / 1000);
const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (c) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(c)}.sig`;
const record = (claims) =>
  `${fakeJws({ typ: "browserid-warrant-v2", iat: nowS(), exp: nowS() + 86400, ...claims })}~${fakeJws({
    typ: "browserid-device-cert-v1",
    purpose: "authorization",
  })}`;

// ---------------------------------------------------------------------------
// An in-process fake broker: /verify, /status/check, /validate-record,
// record-request, poll, support doc. `validate` maps record → result | fn.
// ---------------------------------------------------------------------------
function fakeBroker({ verify, status = { ok: true, revoked: false }, validate = {}, deliver } = {}) {
  const calls = { verify: 0, status: 0, validate: 0 };
  const reqs = new Map();
  let n = 0;
  const res = (httpStatus, obj) => ({ ok: httpStatus < 300, status: httpStatus, json: async () => obj ?? {} });
  const fetch = async (url, init) => {
    const body = init?.body ? JSON.parse(init.body) : {};
    const path = new URL(url).pathname;
    if (path === "/.well-known/browserid") return res(200, { "record-grants": "/warrant/record-request" });
    if (path === "/verify") {
      calls.verify++;
      const v = typeof verify === "function" ? verify(body) : verify;
      return res(v?.__status ?? 200, v);
    }
    if (path === "/status/check") {
      calls.status++;
      const s = typeof status === "function" ? status(body) : status;
      return res(s?.__status ?? 200, s);
    }
    if (path === "/validate-record") {
      calls.validate++;
      const v = validate[body.record];
      const out = typeof v === "function" ? v(body) : v;
      if (!out) return res(200, { status: "failure", reason: "unknown record" });
      return res(out.__status ?? 200, out);
    }
    if (path === "/warrant/record-request") {
      const id = `req_${++n}`;
      reqs.set(id, { body });
      return res(200, { success: true, request_id: id, challenge: "chal", consent_uri: `${BROKER}/consent/${id}`, expires_in: 900, interval: 0 });
    }
    if (path === "/warrant/poll") {
      const r = reqs.get(body.request_id);
      if (!r) return res(404, { success: false });
      reqs.delete(body.request_id);
      return res(200, { success: true, status: "approved", grants: deliver(r.body) });
    }
    throw new Error("unexpected url " + url);
  };
  return { fetch, calls, reqs };
}

const okVerify = {
  status: "okay",
  email: MEMBER,
  grantee: MEMBER,
  holder: "br.abc",
  issuer: "example.com",
  scopes: ["notes:read", "notes:write"],
  status_refs: [{ uri: `${BROKER}/status`, idx: 7 }],
};

const pkce = () => {
  const verifier = randomBytes(48).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier, "ascii").digest("base64url") };
};

/** Drive register → authorize → approve → return → code → tokens through a lane. */
async function connect(lane, { scope = "notes:read notes:write" } = {}) {
  const p = pkce();
  const reg = lane.handleRegister({ redirect_uris: [REDIRECT], client_name: "Claude" });
  const authz = await lane.handleAuthorize({
    client_id: reg.client_id, redirect_uri: REDIRECT, response_type: "code",
    code_challenge: p.challenge, code_challenge_method: "S256", scope,
  });
  const st = new URL(authz.present.return_url).searchParams.get("st");
  const ret = await lane.handleAuthorizeReturn({ st });
  const code = new URL(ret.redirect).searchParams.get("code");
  if (!code) throw new Error(`no code: ${ret.redirect}`);
  return lane.handleToken({
    grant_type: "authorization_code", code, client_id: reg.client_id,
    redirect_uri: REDIRECT, code_verifier: p.verifier, scope,
  });
}

const connectionResult = (who, id = `cn_${who}`, extra = {}) => ({
  status: "okay", grantor: who, grantee: who,
  binding: { kind: "connection", protocol: "oauth", id, client_host: "claude.ai", client_name: "Claude" },
  scopes: ["notes:read", "notes:write"], issuer: "example.com",
  status_refs: [{ uri: `${BROKER}/status`, idx: 200 }], expires_at: nowS() + 86400, ...extra,
});
const policyResult = (grantee, binding, extra = {}) => ({
  status: "okay", grantor: OWNER, grantee, binding,
  scopes: ["notes:read"], issuer: "example.com",
  status_refs: [{ uri: `${BROKER}/status`, idx: 300 }], expires_at: nowS() + 86400, ...extra,
});

function policyLane({ validate, deliver, policyRows }) {
  const broker = fakeBroker({ verify: okVerify, validate, deliver });
  const store = createPolicyStore();
  for (const r of policyRows) store.put(r);
  const mcpAuth = createMcpAuth({ resource: RESOURCE, broker: BROKER, statusCacheS: 0, fetch: broker.fetch, store: createMemoryStore() });
  const lane = createAuthCodeLane({ mcpAuth, broker: BROKER, fetch: broker.fetch, returnPollTries: 1, returnPollDelayMs: 1, policy: { owners: [OWNER], store } });
  return { broker, mcpAuth, lane, store };
}

// ===========================================================================
// D17 — identity comparison (spec §5, threat model I5)
// ===========================================================================

test("D17 pin: identityEq is local-part byte-exact and domain case-insensitive", () => {
  assert.equal(identityEq("Dan@Example.com", "Dan@example.com"), true);
  assert.equal(identityEq("Dan@example.com", "dan@example.com"), false, "local part must not fold");
  assert.equal(granteeCovers("*@example.com", "x@EXAMPLE.com"), true);
  assert.equal(granteeCovers("*@example.com", "x@sub.example.com"), false, "no subdomain widening");
  assert.equal(granteeCovers("*", "not-an-email"), false);
});

test("D17: a string with two '@' is not an identity (core rejects; splitEmail splits on the last '@')", { skip: "AUDIT-2026-11 D17: fails today" }, () => {
  assert.equal(identityEq("a@b@example.com", "a@b@example.com"), false);
  assert.equal(granteeCovers("*@example.com", "a@b@example.com"), false);
});

test("D17: granteeCovers('*') must not admit a malformed subject", { skip: "AUDIT-2026-11 D17: fails today" }, () => {
  assert.equal(granteeCovers("*", "@"), false);
  assert.equal(granteeCovers("*", "@example.com"), false);
  assert.equal(granteeCovers("*", "nobody@"), false);
});

// ===========================================================================
// D5 — admission ignores binding entries (spec §6.4 step 3, inv. 6/7)
// ===========================================================================

const MEMBER_CONN = record({ grantor: MEMBER, grantee: MEMBER, audience: RESOURCE, scopes: ["notes:read", "notes:write"], binding: { kind: "connection", protocol: "oauth", id: "cn_m", client_host: "claude.ai" }, status: { uri: `${BROKER}/status`, idx: 200 } });
const POLICY_NARROW = record({ grantor: OWNER, grantee: MEMBER, audience: RESOURCE, scopes: ["notes:read"], binding: { kind: "holder", matcher: "agents.one-specific-holder" }, status: { uri: `${BROKER}/status`, idx: 300 } });
const POLICY_REQUESTER = record({ grantor: OWNER, grantee: MEMBER, audience: RESOURCE, scopes: ["notes:read"], binding: [{ kind: "holder", matcher: "*" }, { kind: "requester", origin: "https://app.example" }], status: { uri: `${BROKER}/status`, idx: 301 } });
const POLICY_OPEN = record({ grantor: OWNER, grantee: MEMBER, audience: RESOURCE, scopes: ["notes:read"], binding: { kind: "holder", matcher: "*" }, status: { uri: `${BROKER}/status`, idx: 302 } });

const row = (rec, grantee = MEMBER) => ({ record: rec, grantor: OWNER, grantee, audience: RESOURCE, scopes: ["notes:read"], exp: nowS() + 86400 });

test("D5 pin: a holder:'*' policy row admits a connection subject with S ∩ S′", async () => {
  const { lane, mcpAuth } = policyLane({
    validate: { [MEMBER_CONN]: connectionResult(MEMBER, "cn_m"), [POLICY_OPEN]: policyResult(MEMBER, { kind: "holder", matcher: "*" }) },
    deliver: () => [{ audience: RESOURCE, warrant: MEMBER_CONN }],
    policyRows: [row(POLICY_OPEN)],
  });
  const tokens = await connect(lane, { scope: "notes:read" });
  const ctx = await mcpAuth.authenticate(`Bearer ${tokens.access_token}`);
  assert.equal(ctx.permittedBy, OWNER);
  assert.deepEqual(ctx.scopes, ["notes:read"]);
});

test("D5: a policy row narrowed to one holder must not admit a holder-less connection subject (§6.4 step 3 fail-closed)", { skip: "AUDIT-2026-11 D5: fails today" }, async () => {
  const { lane } = policyLane({
    validate: { [MEMBER_CONN]: connectionResult(MEMBER, "cn_m"), [POLICY_NARROW]: policyResult(MEMBER, { kind: "holder", matcher: "agents.one-specific-holder" }) },
    deliver: () => [{ audience: RESOURCE, warrant: MEMBER_CONN }],
    policyRows: [row(POLICY_NARROW)],
  });
  await assert.rejects(connect(lane, { scope: "notes:read" }), (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant");
});

test("D5: a policy row carrying a requester entry is unsatisfiable in operation A and must refuse", { skip: "AUDIT-2026-11 D5: fails today" }, async () => {
  const { lane } = policyLane({
    validate: {
      [MEMBER_CONN]: connectionResult(MEMBER, "cn_m"),
      [POLICY_REQUESTER]: policyResult(MEMBER, [{ kind: "holder", matcher: "*" }, { kind: "requester", origin: "https://app.example" }]),
    },
    deliver: () => [{ audience: RESOURCE, warrant: MEMBER_CONN }],
    policyRows: [row(POLICY_REQUESTER)],
  });
  await assert.rejects(connect(lane, { scope: "notes:read" }), (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant");
});

// ===========================================================================
// W4-10 — the policy layer does not reach Lane A (jwt-bearer) bearers
// ===========================================================================

test("W4-10: with policy configured, a jwt-bearer presentation from a non-owner with no covering row must not mint", { skip: "AUDIT-2026-11 W4-10: fails today" }, async () => {
  const { lane } = policyLane({ validate: {}, deliver: () => [], policyRows: [] });
  // okVerify is MEMBER (not an owner) and the policy store holds no row.
  await assert.rejects(
    lane.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: "AC~AS~WR~CC" }),
    (e) => e instanceof McpAuthError && e.oauthError === "invalid_grant"
  );
});

test("W4-10 pin: today the Lane A mint ignores the policy layer entirely (the gate re-checks at /mcp)", async () => {
  const { lane, mcpAuth } = policyLane({ validate: {}, deliver: () => [], policyRows: [] });
  const t = await lane.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: "AC~AS~WR~CC" });
  const ctx = await mcpAuth.authenticate(`Bearer ${t.access_token}`);
  assert.equal(ctx.grantor, MEMBER);
  assert.equal(ctx.permittedBy, null);
});

// ===========================================================================
// D20 — binding.id is not held 1:1 with its record (spec §6.6 invariant 5)
// ===========================================================================

test("D20: a second record naming an already-bound binding.id must be refused", { skip: "AUDIT-2026-11 D20: fails today" }, async () => {
  const CONN_A = record({ grantor: OWNER, grantee: OWNER, audience: RESOURCE, scopes: ["notes:read"], binding: { kind: "connection", protocol: "oauth", id: "cn_dup", client_host: "claude.ai" }, status: { uri: `${BROKER}/status`, idx: 1 } });
  const CONN_B = record({ grantor: OWNER, grantee: OWNER, audience: RESOURCE, scopes: ["notes:read"], binding: { kind: "connection", protocol: "oauth", id: "cn_dup", client_host: "claude.ai" }, status: { uri: `${BROKER}/status`, idx: 2 } });
  let which = CONN_A;
  const { lane } = policyLane({
    validate: { [CONN_A]: connectionResult(OWNER, "cn_dup"), [CONN_B]: connectionResult(OWNER, "cn_dup") },
    deliver: () => [{ audience: RESOURCE, warrant: which }],
    policyRows: [],
  });
  const first = await connect(lane, { scope: "notes:read" });
  assert.ok(first.access_token);
  which = CONN_B;
  await assert.rejects(connect(lane, { scope: "notes:read" }), (e) => e instanceof McpAuthError);
});

// ===========================================================================
// D6 (mcp-auth side) — the lane's own re-checks ARE fail-closed; pins
// ===========================================================================

test("D6 pin: conjoinPolicy fails closed when the validator answers HTTP 503", async () => {
  const { lane } = policyLane({
    validate: { [MEMBER_CONN]: connectionResult(MEMBER, "cn_m"), [POLICY_OPEN]: { __status: 503, status: "failure", reason: "down" } },
    deliver: () => [{ audience: RESOURCE, warrant: MEMBER_CONN }],
    policyRows: [row(POLICY_OPEN)],
  });
  await assert.rejects(connect(lane, { scope: "notes:read" }), (e) => e instanceof McpAuthError);
});

// W4-12: validateRecord maps an HTTP 5xx from the validator to
// `invalid_grant` (400) — a definitive-looking verdict — instead of
// `temporarily_unavailable` (503); only a THROWN fetch is classed 503. The
// gate's isRowLive keys on httpStatus === 503, so an HTTP 503 deletes the
// signed policy row (grantsDiff custodial delete) while a connection failure
// keeps it live (D6's fail-open branch).
test("W4-12: an HTTP 5xx from /validate-record is 'temporarily_unavailable', not a definitive invalid_grant", { skip: "AUDIT-2026-11 W4-12: fails today" }, async () => {
  const broker = fakeBroker({ validate: { [POLICY_OPEN]: { __status: 503, status: "failure", reason: "down" } } });
  const mcp = createMcpAuth({ resource: RESOURCE, broker: BROKER, fetch: broker.fetch });
  await assert.rejects(mcp.validateRecord(POLICY_OPEN), (e) => e instanceof McpAuthError && e.httpStatus === 503 && e.oauthError === "temporarily_unavailable");
});

test("W4-12 pin: today an HTTP 503 from the validator reads as invalid_grant (400)", async () => {
  const broker = fakeBroker({ validate: { [POLICY_OPEN]: { __status: 503, status: "failure", reason: "down" } } });
  const mcp = createMcpAuth({ resource: RESOURCE, broker: BROKER, fetch: broker.fetch });
  await assert.rejects(mcp.validateRecord(POLICY_OPEN), (e) => e instanceof McpAuthError && e.httpStatus === 400 && e.oauthError === "invalid_grant");
  // …while a thrown fetch is correctly classed 503.
  const down = createMcpAuth({ resource: RESOURCE, broker: BROKER, fetch: async () => { throw new Error("ECONNREFUSED"); } });
  await assert.rejects(down.validateRecord(POLICY_OPEN), (e) => e.httpStatus === 503);
});

test("D6 pin: the per-call status re-check fails closed on an HTTP 503 (not only on a thrown fetch)", async () => {
  const broker = fakeBroker({ verify: okVerify, status: { __status: 503, ok: false } });
  const mcp = createMcpAuth({ resource: RESOURCE, broker: BROKER, statusCacheS: 0, fetch: broker.fetch });
  const t = await mcp.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: "AC~AS~WR~CC" });
  // First authenticate is inside the mint's own freshness window only when statusCacheS > 0; here it re-checks.
  await assert.rejects(mcp.authenticate(`Bearer ${t.access_token}`), (e) => e.httpStatus === 401);
});

test("D6 pin: a bearer minted from a record never outlives the record", async () => {
  const soon = nowS() + 30;
  const { lane } = policyLane({
    validate: { [MEMBER_CONN]: connectionResult(MEMBER, "cn_m", { expires_at: soon }) },
    deliver: () => [{ audience: RESOURCE, warrant: MEMBER_CONN }],
    policyRows: [row(POLICY_OPEN)],
  });
  // MEMBER has no live policy row → refused (pins the fail-closed conjunction too)
  await assert.rejects(connect(lane, { scope: "notes:read" }), (e) => e instanceof McpAuthError);
});

// ===========================================================================
// W4-11 — refresh_token exchange does not require client_id (public client)
// ===========================================================================

test("W4-11: a refresh without client_id must be refused for a public client (RFC 6749 §4.1.3 / OAuth 2.1 §4.3.1)", { skip: "AUDIT-2026-11 W4-11: fails today" }, async () => {
  const { lane } = policyLane({
    validate: { [MEMBER_CONN]: connectionResult(OWNER, "cn_o") },
    deliver: () => [{ audience: RESOURCE, warrant: MEMBER_CONN }],
    policyRows: [],
  });
  const t = await connect(lane, { scope: "notes:read" });
  await assert.rejects(lane.handleToken({ grant_type: "refresh_token", refresh_token: t.refresh_token }), (e) => e instanceof McpAuthError);
});

// ===========================================================================
// Pins: OAuth 2.1 / RFC 7521 behaviour the skeptic re-verified
// ===========================================================================

test("pin: a replayed jwt-bearer assertion mints again (no AS-side jti cache; the verifier is stateless) — observation, not a finding", async () => {
  const broker = fakeBroker({ verify: okVerify });
  const mcp = createMcpAuth({ resource: RESOURCE, broker: BROKER, fetch: broker.fetch });
  const a = await mcp.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: "AC~AS~WR~CC" });
  const b = await mcp.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: "AC~AS~WR~CC" });
  assert.notEqual(a.access_token, b.access_token);
  assert.equal(broker.calls.verify, 2, "each redemption re-verifies at the broker, audience-pinned");
});

test("pin: /verify is always called with audience == this resource and the accepted fallbacks", async () => {
  let seen;
  const broker = fakeBroker({ verify: (b) => { seen = b; return okVerify; } });
  const mcp = createMcpAuth({ resource: RESOURCE + "/", broker: BROKER, fetch: broker.fetch });
  await mcp.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: "AC~AS~WR~CC" });
  assert.equal(seen.audience, RESOURCE);
  assert.deepEqual(seen.accepted_fallbacks, ["broker.example"]);
});

test("pin: scope entries with parameters (object entries) fail closed against a string tool scope", async () => {
  const broker = fakeBroker({ verify: { ...okVerify, scopes: [{ "notes:read": { mode: "prompt" } }, "notes:write"] } });
  const mcp = createMcpAuth({ resource: RESOURCE, broker: BROKER, fetch: broker.fetch, scopesForTool: { read: ["notes:read"], write: ["notes:write"] } });
  await assert.rejects(mcp.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: "x" , scope: "notes:read" }), (e) => e.oauthError === "invalid_scope");
  const t = await mcp.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: "x" });
  await assert.rejects(mcp.requireWarrant(`Bearer ${t.access_token}`, "read"), (e) => e.oauthError === "insufficient_scope");
  const ctx = await mcp.requireWarrant(`Bearer ${t.access_token}`, "write");
  assert.deepEqual(ctx.scopes[0], { "notes:read": { mode: "prompt" } }, "the entry rides verbatim (S7 relay rule)");
});

test("pin: the authorization code is bound to client_id, redirect_uri and PKCE; replay finds nothing", async () => {
  const { lane } = policyLane({ validate: { [MEMBER_CONN]: connectionResult(OWNER, "cn_o") }, deliver: () => [{ audience: RESOURCE, warrant: MEMBER_CONN }], policyRows: [] });
  const p = pkce();
  const reg = lane.handleRegister({ redirect_uris: [REDIRECT] });
  const authz = await lane.handleAuthorize({ client_id: reg.client_id, redirect_uri: REDIRECT, response_type: "code", code_challenge: p.challenge, code_challenge_method: "S256" });
  const st = new URL(authz.present.return_url).searchParams.get("st");
  const code = new URL((await lane.handleAuthorizeReturn({ st })).redirect).searchParams.get("code");
  const bad = (over) => lane.handleToken({ grant_type: "authorization_code", code, client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: p.verifier, ...over });
  await assert.rejects(bad({ client_id: "mcp_other" }), (e) => e.oauthError === "invalid_grant");
  // the failed exchange consumed the code (single use) — a correct retry also fails
  await assert.rejects(bad({}), (e) => e.oauthError === "invalid_grant");
});

test("pin: the connection record's client_host must equal the registered redirect host at release AND exchange", async () => {
  const { lane } = policyLane({ validate: { [MEMBER_CONN]: connectionResult(OWNER, "cn_o", { binding: { kind: "connection", protocol: "oauth", id: "cn_o", client_host: "evil.example" } }) }, deliver: () => [{ audience: RESOURCE, warrant: MEMBER_CONN }], policyRows: [] });
  const p = pkce();
  const reg = lane.handleRegister({ redirect_uris: [REDIRECT] });
  const authz = await lane.handleAuthorize({ client_id: reg.client_id, redirect_uri: REDIRECT, response_type: "code", code_challenge: p.challenge, code_challenge_method: "S256" });
  const st = new URL(authz.present.return_url).searchParams.get("st");
  const back = new URL((await lane.handleAuthorizeReturn({ st })).redirect);
  assert.equal(back.searchParams.get("error"), "access_denied");
});
