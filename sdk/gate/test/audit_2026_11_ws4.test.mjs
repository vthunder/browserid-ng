// Security audit 2026-11, WS4 (bean browserid-ng-n6nn): the gate layer.
//
// Candidates D5 (admission ignores binding entries), D6 (policy-row liveness
// fails open / is never re-checked), D17 (local-part case folding at the
// admin and grantor gates), over real HTTP against a mock broker. Tests that
// FAIL today are skipped with `AUDIT-2026-11 <id>: fails today`; the rest
// pass today and pin what the skeptic re-verified. No production code changed.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createGateService } from "../src/gate.mjs";
import { createGateway } from "../src/gateway.mjs";
import { createSessionManager } from "../src/session.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BROKER_PORT = 43510;
const SINGLE_PORT = 43511;
const GW_PORT = 43512;
const BROKER = `http://localhost:${BROKER_PORT}`;
const SINGLE = `http://localhost:${SINGLE_PORT}`;
const GW = `http://127.0.0.1:${GW_PORT}`;
const NOTES = `${GW}/notes`;

const ADMIN = "admin@example.com";
const OWNER = "gwen@example.com";
const MEMBER = "erin@example.com";
const MEMBER_CASED = "Erin@example.com"; // a DISTINCT identity under spec §5
const ADMIN_CASED = "Admin@example.com";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (c) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(c)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);
const record = (claims) =>
  `${fakeJws({ typ: "browserid-warrant-v2", iat: nowS(), exp: nowS() + 86400, ...claims })}~${fakeJws({ typ: "browserid-device-cert-v1", purpose: "authorization" })}`;

// Policy records the "owner"/"admin" signed. Validation echoes the payload.
const SINGLE_POLICY = record({ grantor: OWNER, grantee: MEMBER, audience: SINGLE, scopes: ["tool:read_text_file"], binding: { kind: "holder", matcher: "*" }, status: { uri: `${BROKER}/status`, idx: 1 } });
const SINGLE_NARROW = record({ grantor: OWNER, grantee: MEMBER, audience: SINGLE, scopes: ["tool:read_text_file"], binding: { kind: "holder", matcher: "agents.someone-else" }, status: { uri: `${BROKER}/status`, idx: 2 } });
const GW_POLICY = record({ grantor: ADMIN, grantee: MEMBER, audience: NOTES, scopes: ["tool:read_text_file"], binding: { kind: "holder", matcher: "*" }, status: { uri: `${BROKER}/status`, idx: 3 } });

// Per-record validator mode: "ok" | "revoked" | "http503" | "reset" (socket destroyed → fetch throws)
const validateMode = new Map();
// presentation → verify result (holder is what D5 keys on)
const PRES = {
  "pres-member": { email: MEMBER, holder: "agents.erin" },
  "pres-member-cased": { email: MEMBER_CASED, holder: "agents.erin" },
  "pres-admin": { email: ADMIN, holder: "br.admin" },
  "pres-admin-cased": { email: ADMIN_CASED, holder: "br.admin" },
  "pres-owner": { email: OWNER, holder: "br.gwen" },
};

const broker = createServer(async (req, res) => {
  const reply = (c, o) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  let raw = ""; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  const path = new URL(req.url, BROKER).pathname;
  if (path === "/.well-known/browserid") return reply(200, { "record-grants": "/warrant/record-request" });
  if (path === "/verify") {
    const p = PRES[body.presentation];
    if (!p) return reply(200, { status: "failure", reason: "verification failed" });
    return reply(200, { status: "okay", email: p.email, grantee: p.email, holder: p.holder, issuer: "example.com", scopes: ["tool:read_text_file", "tool:list_directory"], status_refs: [] });
  }
  if (path === "/status/check") return reply(200, { ok: true, revoked: false });
  if (path === "/validate-record") {
    const mode = validateMode.get(body.record) || "ok";
    if (mode === "reset") return req.socket.destroy();
    if (mode === "http503") return reply(503, { status: "failure", reason: "down" });
    if (mode === "revoked") return reply(200, { status: "failure", reason: "warrant revoked" });
    const claims = JSON.parse(Buffer.from(body.record.split("~")[0].split(".")[1], "base64url").toString());
    if (claims.audience !== body.audience) return reply(200, { status: "failure", reason: "audience mismatch" });
    return reply(200, { status: "okay", grantor: claims.grantor, grantee: claims.grantee, binding: claims.binding, scopes: claims.scopes, issuer: "example.com", status_refs: [claims.status], expires_at: claims.exp });
  }
  reply(404, {});
});

function memoryPolicyStore(rows = []) {
  const key = (r) => `${r.grantor}|${r.grantee}|${r.audience}`;
  const m = new Map(rows.map((r) => [key(r), r]));
  return {
    async put(r) { m.set(key(r), r); },
    async list(aud = null) { return [...m.values()].filter((r) => aud == null || r.audience === aud); },
    async del(g, e, a) { m.delete(`${g}|${e}|${a}`); },
    raw: m,
  };
}
const rowFor = (rec, over = {}) => {
  const c = JSON.parse(Buffer.from(rec.split("~")[0].split(".")[1], "base64url").toString());
  return { record: rec, grantor: c.grantor, grantee: c.grantee, audience: c.audience, scopes: c.scopes, exp: c.exp, ...over };
};

const dir = mkdtempSync(join(tmpdir(), "gate-audit-"));
writeFileSync(join(dir, "hello.txt"), "hi\n");
const child = { command: process.execPath, args: [join(HERE, "fixtures", "fs-child.mjs"), dir] };
const secret = randomBytes(32);

let single, singleStore, gw, gwStore;
before(async () => {
  await new Promise((r) => broker.listen(BROKER_PORT, r));
  singleStore = memoryPolicyStore([rowFor(SINGLE_POLICY)]);
  single = await createGateService({
    owners: [OWNER], policyStore: singleStore, sessionSecret: secret, name: "Single", child,
    resource: SINGLE, broker: BROKER, statusCacheS: 0, log: () => {},
  });
  await new Promise((r) => single.server.listen(SINGLE_PORT, r));

  gwStore = memoryPolicyStore([rowFor(GW_POLICY)]);
  gw = createGateway({
    adminEmail: ADMIN, broker: BROKER, origin: GW, statusCacheS: 0, persist: false,
    signedGrants: true, grantsLivenessS: 0, policyStore: gwStore, sessionSecret: secret, log: () => {},
    config: { mounts: [{ id: "n1", name: "Notes", mount: "notes", command: [child.command, ...child.args], enabled: true }], people: [], roles: [] },
  });
  await gw.start({ port: GW_PORT });
});
after(async () => {
  await gw.close();
  await single.close();
  broker.close();
});

async function bearer(base, presentation) {
  const res = await fetch(`${base}/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: presentation }),
  });
  assert.equal(res.status, 200, `token HTTP ${res.status}`);
  return (await res.json()).access_token;
}
let id = 1;
const mcp = (base, tok) => fetch(`${base}/mcp`, {
  method: "POST",
  headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tok}` },
  body: JSON.stringify({ jsonrpc: "2.0", id: id++, method: "tools/list", params: {} }),
});

// ===========================================================================
// D6 — single-server policy mode never re-checks a policy row
// ===========================================================================

test("D6 pin: the member is admitted under the owner's live policy row (single-server)", async () => {
  const res = await mcp(SINGLE, await bearer(SINGLE, "pres-member"));
  assert.equal(res.status, 200);
});

test("D6: single-server — a policy row the broker reports REVOKED must stop admitting a jwt-bearer subject", { skip: "AUDIT-2026-11 D6: fails today" }, async () => {
  validateMode.set(SINGLE_POLICY, "revoked");
  try {
    const res = await mcp(SINGLE, await bearer(SINGLE, "pres-member"));
    assert.equal(res.status, 403);
  } finally { validateMode.delete(SINGLE_POLICY); }
});

test("D6: single-server — an EXPIRED policy row must not admit", { skip: "AUDIT-2026-11 D6: fails today" }, async () => {
  const live = singleStore.raw.get(`${OWNER}|${MEMBER}|${SINGLE}`);
  singleStore.raw.set(`${OWNER}|${MEMBER}|${SINGLE}`, { ...live, exp: nowS() - 10 });
  try {
    const res = await mcp(SINGLE, await bearer(SINGLE, "pres-member"));
    assert.equal(res.status, 403);
  } finally { singleStore.raw.set(`${OWNER}|${MEMBER}|${SINGLE}`, live); }
});

// ===========================================================================
// D6 — gateway signed mode: isRowLive fails OPEN when the validator is unreachable
// ===========================================================================

test("D6 pin: gateway signed mode — the member is admitted under the admin's live policy row (validated fresh)", async () => {
  const res = await mcp(NOTES, await bearer(NOTES, "pres-member"));
  assert.equal(res.status, 200);
});

test("D6: gateway signed mode — an UNREACHABLE validator must fail closed (last-known-good is not fresh evidence)", { skip: "AUDIT-2026-11 D6: fails today" }, async () => {
  validateMode.set(GW_POLICY, "reset");
  try {
    const res = await mcp(NOTES, await bearer(NOTES, "pres-member"));
    assert.equal(res.status, 403);
  } finally { validateMode.delete(GW_POLICY); }
});

test("D6 pin: gateway signed mode — today an unreachable validator ADMITS on last-known-good (isRowLive → cached?.ok ?? true)", async () => {
  validateMode.set(GW_POLICY, "reset");
  try {
    const res = await mcp(NOTES, await bearer(NOTES, "pres-member"));
    assert.equal(res.status, 200);
  } finally { validateMode.delete(GW_POLICY); }
});

test("D6 pin: gateway signed mode — a REVOKED policy row refuses the member (definitive answers are honored)", async () => {
  validateMode.set(GW_POLICY, "revoked");
  try {
    const res = await mcp(NOTES, await bearer(NOTES, "pres-member"));
    assert.equal(res.status, 403);
  } finally { validateMode.delete(GW_POLICY); }
});

test("D6 pin: gateway signed mode — an HTTP 503 from the validator is read as DEFINITIVE (fails closed here; see W4-12)", async () => {
  validateMode.set(GW_POLICY, "http503");
  try {
    const res = await mcp(NOTES, await bearer(NOTES, "pres-member"));
    assert.equal(res.status, 403);
  } finally { validateMode.delete(GW_POLICY); }
});

// ===========================================================================
// D5 — the policy row's holder matcher is never evaluated at the gate
// ===========================================================================

test("D5: a policy row narrowed to another holder must not admit a jwt-bearer login with a different holder (§6.4 step 3)", async () => {
  const k = `${OWNER}|${MEMBER}|${SINGLE}`;
  const live = singleStore.raw.get(k);
  singleStore.raw.set(k, rowFor(SINGLE_NARROW));
  try {
    const res = await mcp(SINGLE, await bearer(SINGLE, "pres-member")); // holder agents.erin ≠ agents.someone-else
    assert.equal(res.status, 403);
  } finally { singleStore.raw.set(k, live); }
});

// ===========================================================================
// D17 — local-part case folding at the admin and grantor gates
// ===========================================================================

test("D17 pin: the admin gate refuses a different exact identity", async () => {
  const res = await fetch(`${GW}/admin/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ presentation: "pres-owner" }) });
  assert.equal(res.status, 403);
});

test("D17: the admin gate must not fold the local part — Admin@ is not admin@ (spec §5, I5)", { skip: "AUDIT-2026-11 D17: fails today" }, async () => {
  const res = await fetch(`${GW}/admin/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ presentation: "pres-admin-cased" }) });
  assert.equal(res.status, 403);
});

test("D17 pin: today Admin@example.com signs in as the admin (local part folded)", async () => {
  const res = await fetch(`${GW}/admin/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ presentation: "pres-admin-cased" }) });
  assert.equal(res.status, 200);
});

test("D17: the grantor gate must not fold the local part — a row for erin@ must not admit Erin@", { skip: "AUDIT-2026-11 D17: fails today" }, async () => {
  const res = await mcp(NOTES, await bearer(NOTES, "pres-member-cased"));
  assert.equal(res.status, 403);
});

test("D17 pin: today the gateway's /mcp lowercases the grantor before the entitlement lookup", async () => {
  const res = await mcp(NOTES, await bearer(NOTES, "pres-member-cased"));
  assert.equal(res.status, 200);
});

// ===========================================================================
// Pins the skeptic re-verified
// ===========================================================================

test("pin: a member session cookie signed with the right secret but for a NON-admin cannot reach the console API", async () => {
  const s = createSessionManager({ secret, cookieName: "gate_session" }).issue(MEMBER);
  const res = await fetch(`${GW}/admin/state`, { headers: { cookie: s.setCookies.map((c) => c.split(";")[0]).join("; ") } });
  assert.equal(res.status, 401);
});

test("pin: /connect/login keeps `next` on this origin (open-redirect guard)", async () => {
  const res = await fetch(`${GW}/connect/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ presentation: "pres-member", next: "https://evil.example/x" }) });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).next, "/");
});

test("pin: a bearer minted at the gateway mount is not valid at the single-server gate (separate audiences and stores)", async () => {
  const tok = await bearer(NOTES, "pres-member");
  const res = await mcp(SINGLE, tok);
  assert.equal(res.status, 401);
});
