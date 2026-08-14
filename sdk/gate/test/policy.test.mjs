// Credential-less sharing through the gate (spec §6.5 × §7.5), over real
// HTTP: a mount with OWNERS and no credential; the owner shares to a
// member's email via the authoring ceremony (lane.requestAuthoring against
// the mock broker); the member connects through the connection mode
// (authorize → consent → record) and calls a real tool on the fs-child —
// scoped to S ∩ S′, attributed to the member under the owner's grant. Then
// both revocation axes: the owner's policy revoke kills the member's
// refresh; an unshared stranger never mints at all.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createGateService } from "../src/gate.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BROKER_PORT = 43400;
const PORT = 43401;
const BROKER = `http://localhost:${BROKER_PORT}`;
const RESOURCE = `http://localhost:${PORT}`;

const OWNER = "gwen@example.com";
const MEMBER = "erin@example.com";
const STRANGER = "sam@example.com";
const REDIRECT = "http://127.0.0.1:9/cb";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (claims) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(claims)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);

const connectionRecord = (who, idx) => `${fakeJws({
  typ: "browserid-warrant-v2",
  grantor: who, grantee: who,
  binding: { kind: "connection", protocol: "oauth", id: `cn_${who}`, client_host: "127.0.0.1", client_name: "Claude" },
  audience: RESOURCE,
  scopes: ["tool:read_text_file", "tool:list_directory"],
  status: { uri: `${BROKER}/status`, idx },
  iat: nowS(), exp: nowS() + 90 * 24 * 3600,
})}~${fakeJws({ typ: "browserid-device-cert-v1", purpose: "authorization" })}`;

const MEMBER_CONNECTION = connectionRecord(MEMBER, 10);
const STRANGER_CONNECTION = connectionRecord(STRANGER, 11);
// The owner's policy record: MEMBER may read, not list (S ∩ S′ bites).
const POLICY_RECORD = `${fakeJws({
  typ: "browserid-warrant-v2",
  grantor: OWNER, grantee: MEMBER,
  binding: { kind: "holder", matcher: "*" },
  audience: RESOURCE,
  scopes: ["tool:read_text_file"],
  status: { uri: `${BROKER}/status`, idx: 20 },
  iat: nowS(), exp: nowS() + 90 * 24 * 3600,
})}~${fakeJws({ typ: "browserid-device-cert-v1", purpose: "authorization" })}`;

// --- mock broker -------------------------------------------------------------
const pending = new Map(); // request_id -> { challenge, type, returnUrl, deliver }
let nextId = 1;
let policyRevoked = false;

const broker = createServer(async (req, res) => {
  const reply = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
  let raw = ""; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  const path = new URL(req.url, BROKER).pathname;

  if (path === "/.well-known/browserid") return reply(200, { "record-grants": "/warrant/record-request" });
  if (path === "/warrant/record-request") {
    const id = `req_${nextId++}`;
    const challenge = randomBytes(24).toString("base64url");
    pending.set(id, { challenge, type: body.type, grantor: body.grantor || null, scopes: body.scopes, returnUrl: body.return_url, grants: body.grants, deliver: null });
    return reply(200, { success: true, request_id: id, challenge, consent_uri: `${BROKER}/consent/${id}`, expires_in: 900, interval: 0 });
  }
  if (path === "/warrant/poll") {
    const r = pending.get(body.request_id || body.code);
    if (!r) return reply(404, { success: false, reason: "not found" });
    if (!r.deliver) return reply(200, { success: true, status: "pending" });
    pending.delete(body.request_id || body.code);
    return reply(200, { success: true, status: "approved", grants: r.deliver });
  }
  if (path === "/validate-record") {
    const known = {
      [MEMBER_CONNECTION]: {
        grantor: MEMBER, grantee: MEMBER,
        binding: { kind: "connection", protocol: "oauth", id: `cn_${MEMBER}`, client_host: "127.0.0.1", client_name: "Claude" },
        scopes: ["tool:read_text_file", "tool:list_directory"], refs: [{ uri: `${BROKER}/status`, idx: 10 }],
      },
      [STRANGER_CONNECTION]: {
        grantor: STRANGER, grantee: STRANGER,
        binding: { kind: "connection", protocol: "oauth", id: `cn_${STRANGER}`, client_host: "127.0.0.1", client_name: "Claude" },
        scopes: ["tool:read_text_file"], refs: [{ uri: `${BROKER}/status`, idx: 11 }],
      },
      [POLICY_RECORD]: policyRevoked
        ? null
        : {
            grantor: OWNER, grantee: MEMBER,
            binding: { kind: "holder", matcher: "*" },
            scopes: ["tool:read_text_file"], refs: [{ uri: `${BROKER}/status`, idx: 20 }],
          },
    }[body.record];
    if (known === null) return reply(200, { status: "failure", reason: "warrant revoked" });
    if (!known) return reply(200, { status: "failure", reason: "unknown record" });
    return reply(200, {
      status: "okay", grantor: known.grantor, grantee: known.grantee, binding: known.binding,
      scopes: known.scopes, issuer: "example.com", status_refs: known.refs,
      expires_at: nowS() + 90 * 24 * 3600,
    });
  }
  if (path === "/status/check") return reply(200, { ok: true, revoked: false });
  if (path === "/verify-access") {
    const email = { "pres-member": MEMBER, "pres-stranger": STRANGER }[body.presentation];
    if (!email) return reply(200, { status: "failure", reason: "verification failed" });
    return reply(200, {
      status: "okay", email, grantee: email, holder: "br.x", issuer: "example.com",
      scopes: [], status_refs: [],
    });
  }
  reply(404, {});
});

const dataDir = mkdtempSync(join(tmpdir(), "gate-policy-"));
writeFileSync(join(dataDir, "hello.txt"), "shared notes\n");

const logLines = [];
let svc;

before(async () => {
  await new Promise((r) => broker.listen(BROKER_PORT, r));
  // NO credential, NO allowlist: owners + policy records are the gate.
  svc = await createGateService({
    owners: [OWNER],
    sessionSecret: randomBytes(32),
    name: "Shared Notes",
    child: { command: process.execPath, args: [join(HERE, "fixtures", "fs-child.mjs"), dataDir] },
    resource: RESOURCE,
    broker: BROKER,
    statusCacheS: 0,
    log: (l) => logLines.push(l),
  });
  await new Promise((r) => svc.server.listen(PORT, r));
});

after(async () => {
  await svc.close();
  await new Promise((r) => broker.close(r));
});

const pkce = () => {
  const verifier = randomBytes(48).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier, "ascii").digest("base64url") };
};

/** Establish the gate member session (the identity-first login). */
async function login(who) {
  const r = await fetch(`${RESOURCE}/connect/login`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ presentation: `pres-${who}`, next: "/" }),
  });
  const j = await r.json();
  assert.ok(j.ok, `login: ${JSON.stringify(j)}`);
  return r.headers.getSetCookie().map((c) => c.split(";")[0]).find((c) => c.startsWith("gate_user="));
}

/** Drive the identity-first connection dance for `who` and return the token
 *  response (or {denied} when refused before consent). */
async function connect(who, record) {
  const reg = await (await fetch(`${RESOURCE}/register`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: "Claude" }),
  })).json();
  const p = pkce();
  const authorizeUrl =
    `${RESOURCE}/authorize?client_id=${reg.client_id}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
    `&response_type=code&code_challenge=${p.challenge}&code_challenge_method=S256`;

  // Signed out → the gate demands ITS login first (never a broker request).
  const anon = await fetch(authorizeUrl, { redirect: "manual" });
  assert.equal(anon.status, 302);
  assert.ok(anon.headers.get("location").startsWith("/connect/login?next="), anon.headers.get("location"));

  const cookie = await login(who);
  const authz = await fetch(authorizeUrl, { redirect: "manual", headers: { cookie } });
  if (authz.status === 403) return { denied: true, body: await authz.text() };
  const consent = new URL(authz.headers.get("location"));
  assert.equal(consent.origin, BROKER, `authorize should 302 to the broker consent page (got ${consent})`);
  const requestId = consent.pathname.split("/").pop();
  const r = pending.get(requestId);
  // Identity-first: the request is PINNED to the signed-in user, and its
  // scopes are the user's actual entitlement (not the host's ceiling).
  assert.equal(r.grantor, who === "member" ? MEMBER : STRANGER);
  // The audience proof is live at the GATE origin while pending.
  const proof = await fetch(`${RESOURCE}/.well-known/browserid-audience-proof/${requestId}`);
  assert.equal(await proof.text(), r.challenge);
  // The human approves at the broker → record delivered on poll.
  r.deliver = [{ audience: RESOURCE, warrant: record }];
  const st = new URL(r.returnUrl).searchParams.get("st");
  const ret = await fetch(`${RESOURCE}/authorize/return?st=${st}`, { redirect: "manual" });
  const back = new URL(ret.headers.get("location"));
  if (back.searchParams.get("error")) return { error: back.searchParams.get("error"), description: back.searchParams.get("error_description") };
  const code = back.searchParams.get("code");
  const tok = await fetch(`${RESOURCE}/token`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code", code,
      client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: p.verifier,
    }),
  });
  return tok.json();
}

const callTool = (token, name, args) =>
  fetch(`${RESOURCE}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });

test("an unshared stranger is refused BEFORE any consent ceremony", async () => {
  const out = await connect("stranger", STRANGER_CONNECTION);
  assert.ok(out.denied, JSON.stringify(out));
  assert.match(out.body, /don't have access/);
});

test("owner shares to the member's email; the member connects and works under S ∩ S′", async () => {
  // 1. The owner shares: the gate raises the authoring ceremony; the owner
  //    approves at the (mock) broker's consent page.
  const ceremony = await svc.lane.requestAuthoring({
    grants: [{ grantee: MEMBER, scopes: ["tool:read_text_file"] }],
    pollDelayMs: 10,
  });
  assert.ok(ceremony.consentUri.startsWith(`${BROKER}/consent/`));
  // The authoring proof is ALSO live at the gate origin.
  const proof = await fetch(`${RESOURCE}/.well-known/browserid-audience-proof/${ceremony.requestId}`);
  assert.equal(proof.status, 200);
  pending.get(ceremony.requestId).deliver = [{ audience: RESOURCE, warrant: POLICY_RECORD }];
  const rows = await ceremony.wait();
  assert.equal(rows[0].grantee, MEMBER);

  // 2. The member connects (their own consent) and gets S ∩ S′.
  const tokens = await connect("member", MEMBER_CONNECTION);
  assert.ok(tokens.access_token, JSON.stringify(tokens));
  assert.equal(tokens.scope, "tool:read_text_file", "S′(read+list) ∩ S(read) = read");
  assert.ok(tokens.refresh_token);

  // 3. A real tool call on the child, attributed to the member under the
  //    owner's grant.
  const ok = await callTool(tokens.access_token, "read_text_file", { path: "hello.txt" });
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /shared notes/);
  assert.ok(
    logLines.some((l) => l.includes(`grantor=${MEMBER}`) && l.includes(`under=${OWNER}`) && l.includes("read_text_file")),
    `attribution line missing: ${logLines.slice(-5).join("\n")}`
  );

  // 4. The intersection bites: list_directory is in the member's connection
  //    scopes but NOT the owner's grant — the bearer simply lacks it.
  const denied = await callTool(tokens.access_token, "list_directory", { path: "." });
  assert.match(await denied.text(), /ACCESS_DENIED/);

  // 5. Two-sided revocation: the owner revokes the policy record → the
  //    member's refresh (freshness-backed, fail-closed) mints nothing.
  policyRevoked = true;
  const refreshed = await (await fetch(`${RESOURCE}/token`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }),
  })).json();
  assert.equal(refreshed.error, "invalid_grant", JSON.stringify(refreshed));
  policyRevoked = false;
});
