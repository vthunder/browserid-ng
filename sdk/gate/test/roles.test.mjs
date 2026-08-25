// Roles are the single source of truth for access (gate v0.4 — the redesigned
// admin console's model). Proves, against a REAL fs child:
//  • per-tool enforcement: a role granting a subset lets exactly that subset
//    through — the rest is ACCESS_DENIED before reaching the child, and
//    tools/list is filtered to the granted set;
//  • the built-in Full access role grants every tool;
//  • the admin identity has implicit full access (never in a role);
//  • a grantor no role reaches is refused (403) before any tool runs;
//  • role edits are STAGED: enforcement uses the startup snapshot;
//  • the admin API: /admin/state shape, people/roles CRUD, built-in role
//    protections, and the staged-diff entries;
//  • v1 legacy `allow` configs migrate to roles (unit-level; multimount.test
//    covers the migrated end-to-end path).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { KeyPair } from "@browserid-ng/agent";
import { createGateway } from "../src/gateway.mjs";
import { createRecordBroker } from "./fixtures/record-broker.mjs";
import { normalizeConfig } from "../src/config.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BROKER_PORT = 43390;
const PORT = 43391;
const BROKER = `http://localhost:${BROKER_PORT}`;
const ORIGIN = `http://127.0.0.1:${PORT}`;

const ADMIN = "admin@example.com";
const ALICE = "alice@example.com"; // Readers role: list_directory only
const SAM = "sam@example.com"; // built-in Full access member
const BOB = "bob@example.com"; // in the address book, in NO role
const GATEWAY = "gate@example.com";
const GRANTEE = "claude@agents.example.com";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (c) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(c)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);
const gatewayKp = KeyPair.generate();
const credential = {
  device_key: Buffer.from(gatewayKp.seed).toString("base64url"),
  agent_device_cert: fakeJws({ typ: "browserid-device-cert-v1", "public-key": { algorithm: "Ed25519", publicKey: gatewayKp.publicKeyB64 }, holder: "svc.gate1", identities: [GATEWAY], iat: nowS(), exp: nowS() + 8.64e6 }),
  idp: BROKER, identity: GATEWAY,
};

// Mock verifier: presentation → email; every grantor's warrant carries BOTH
// tool scopes, so what differentiates access below is the ROLE, not the scope.
const EMAILS = { "pres-admin": ADMIN, "pres-alice": ALICE, "pres-sam": SAM, "pres-bob": BOB };
const records = createRecordBroker({ brokerOrigin: BROKER, adminEmail: ADMIN });
const broker = createServer(async (req, res) => {
  const reply = (c, o) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  let raw = ""; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  if (records.handle(new URL(req.url, BROKER).pathname, body, reply)) return;
  if (req.url === "/verify") {
    const email = EMAILS[body.presentation];
    if (!email) return reply(200, { status: "failure", reason: "verification failed" });
    return reply(200, {
      status: "okay", email, grantee: GRANTEE, holder: "agents.test", issuer: "example.com",
      scopes: ["tool:read_text_file", "tool:list_directory"], status_refs: [],
    });
  }
  reply(404, {});
});

const notesDir = mkdtempSync(join(tmpdir(), "gate-notes-"));
writeFileSync(join(notesDir, "note.txt"), "a private note\n");

let gw;
before(async () => {
  await new Promise((r) => broker.listen(BROKER_PORT, r));
  gw = createGateway({
    credential, adminEmail: ADMIN, broker: BROKER, origin: ORIGIN, statusCacheS: 0, persist: false,
    signedGrants: true,
    grantsLivenessS: 0, // deterministic revocation tests
    policyStore: memoryPolicyStore(),
    log: () => {},
    config: {
      mounts: [{ id: "n1", name: "Notes", mount: "notes", command: [process.execPath, join(HERE, "fixtures", "fs-child.mjs"), notesDir], enabled: true }],
      people: [{ email: ALICE, name: "Alice" }, { email: SAM, name: "Sam" }, { email: BOB, name: "Bob" }],
      roles: [
        { id: "full", name: "Full access", builtin: true, members: [SAM], grants: [] },
        { id: "readers", name: "Readers", builtin: false, members: [ALICE], grants: [{ mountId: "n1", on: ["list_directory"] }] },
      ],
    },
  });
  await gw.start({ port: PORT });
  // Records are the enforcement source (§6.5): compile the configured roles
  // and sign them (the record broker auto-approves the authoring card).
  const s = await adminLogin();
  const sign = await fetch(`${ORIGIN}/admin/grants/sign`, { method: "POST", headers: H(s) });
  assert.equal(sign.status, 200, `sign HTTP ${sign.status}`);
  for (let i = 0; i < 50; i++) {
    const st = await (await fetch(`${ORIGIN}/admin/grants/status`, { headers: { cookie: s.cookie } })).json();
    if (st.signState?.status === "done") break;
    if (st.signState?.status === "error") assert.fail(`signing failed: ${st.signState.error}`);
    await new Promise((r) => setTimeout(r, 100));
  }
});
after(async () => { await gw.close(); broker.close(); });

// --- MCP-side helpers -------------------------------------------------------

async function getBearer(presentation) {
  const res = await fetch(`${ORIGIN}/notes/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: presentation }),
  });
  assert.equal(res.status, 200, `token HTTP ${res.status}`);
  return (await res.json()).access_token;
}
let nextId = 1;
async function mcp(bearer, method, params) {
  return fetch(`${ORIGIN}/notes/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${bearer}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  });
}
async function callTool(bearer, name, args = {}) {
  const res = await mcp(bearer, "tools/call", { name, arguments: args });
  assert.equal(res.status, 200, `call HTTP ${res.status}`);
  const body = await res.json();
  assert.ok(!body.error, JSON.stringify(body.error));
  return body.result;
}

// --- per-tool enforcement ---------------------------------------------------

test("a role granting a SUBSET lets that subset through and refuses the rest", async () => {
  const bearer = await getBearer("pres-alice");
  const ok = await callTool(bearer, "list_directory", {});
  assert.match(ok.content[0].text, /note\.txt/, "the granted tool reaches the child");

  const denied = await callTool(bearer, "read_text_file", { path: "note.txt" });
  assert.equal(denied.isError, true, "the ungranted tool is refused");
  assert.match(denied.content[0].text, /ACCESS_DENIED/);
  assert.ok(!denied.content[0].text.includes("a private note"), "no child output leaks");
});

test("tools/list is filtered to the grantor's granted set", async () => {
  const bearer = await getBearer("pres-alice");
  const res = await mcp(bearer, "tools/list", {});
  const body = await res.json();
  assert.deepEqual(body.result.tools.map((t) => t.name), ["list_directory"]);
});

test("a built-in Full access member gets every tool", async () => {
  const bearer = await getBearer("pres-sam");
  const read = await callTool(bearer, "read_text_file", { path: "note.txt" });
  assert.match(read.content[0].text, /a private note/);
  const res = await mcp(bearer, "tools/list", {});
  assert.equal((await res.json()).result.tools.length, 2);
});

test("the admin identity has implicit full access (never in a role)", async () => {
  const bearer = await getBearer("pres-admin");
  const read = await callTool(bearer, "read_text_file", { path: "note.txt" });
  assert.match(read.content[0].text, /a private note/);
});

test("a grantor NO role reaches is refused (403) before any tool runs", async () => {
  const bearer = await getBearer("pres-bob");
  const res = await mcp(bearer, "tools/call", { name: "list_directory", arguments: {} });
  assert.equal(res.status, 403);
  assert.equal((await res.json()).error, "access_denied");
});

// --- admin API --------------------------------------------------------------

async function adminLogin() {
  const res = await fetch(`${ORIGIN}/admin/login`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ presentation: "pres-admin" }),
  });
  assert.equal(res.status, 200);
  const cookie = res.headers.getSetCookie().map((c) => c.split(";")[0]).find((c) => c.startsWith("gate_session="));
  const { csrf } = await res.json();
  return { cookie, csrf };
}
function H(s, extra = {}) { return { cookie: s.cookie, "content-type": "application/json", "x-csrf-token": s.csrf, ...extra }; }
function memoryPolicyStore() {
  let rows = [];
  const key = (r) => `${r.grantor}|${r.grantee}|${r.audience}`;
  return {
    async put(row) { rows = rows.filter((r) => key(r) !== key(row)); rows.push(row); },
    async list(aud = null) { return aud == null ? [...rows] : rows.filter((r) => r.audience === aud); },
    async del(g, e, a) { rows = rows.filter((r) => key(r) !== `${g}|${e}|${a}`); },
  };
}

test("the signing ceremony pins the admin and returns to the console", () => {
  assert.equal(records.lastRequest?.type, "authoring");
  assert.equal(records.lastRequest?.grantor, ADMIN, "the signer is pinned");
  assert.equal(records.lastRequest?.return_url, `${ORIGIN}/admin/`, "the signer lands back in the console");
});

test("a broker-revoked grant resurfaces as PENDING (never a false 'in sync')", async () => {
  const s = await adminLogin();
  // Alice's grant was signed in before(). Revoke it at the "broker".
  records.revokedGrantees.add(ALICE);
  try {
    const g = await (await fetch(`${ORIGIN}/admin/grants`, { headers: { cookie: s.cookie } })).json();
    assert.ok(
      g.pending.some((r) => r.grantee === ALICE),
      `alice's dead grant must be pending again: ${JSON.stringify(g.pending)}`
    );
    assert.ok(!g.signed.some((r) => r.grantee === ALICE), "the dead row is dropped from the store");
    // …and enforcement agrees while unsigned: alice is refused.
    const bearer = await getBearer("pres-alice");
    const res = await mcp(bearer, "tools/call", { name: "list_directory", arguments: {} });
    assert.equal(res.status, 403);
  } finally {
    records.revokedGrantees.delete(ALICE);
    // Re-sign so later tests see the original state.
    const sign = await fetch(`${ORIGIN}/admin/grants/sign`, { method: "POST", headers: H(s) });
    assert.equal(sign.status, 200);
    for (let i = 0; i < 50; i++) {
      const st = await (await fetch(`${ORIGIN}/admin/grants/status`, { headers: { cookie: s.cookie } })).json();
      if (st.signState?.status !== "pending") break;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
});

test("adding a member surfaces a PENDING grant to sign (the People-tab flow)", async () => {
  const s = await adminLogin();
  // Add carol to the Readers role — the exact flow of toggling a role chip
  // on the People tab.
  await fetch(`${ORIGIN}/admin/roles/readers`, {
    method: "PATCH", headers: H(s),
    body: JSON.stringify({ members: [ALICE, "carol@example.com"] }),
  });
  const g = await (await fetch(`${ORIGIN}/admin/grants`, { headers: { cookie: s.cookie } })).json();
  assert.ok(
    g.pending.some((r) => r.grantee === "carol@example.com"),
    `carol's grant must be pending: ${JSON.stringify(g.pending)}`
  );
  // Restore (membership AND the address-book row the safety net auto-added).
  await fetch(`${ORIGIN}/admin/roles/readers`, {
    method: "PATCH", headers: H(s), body: JSON.stringify({ members: [ALICE] }),
  });
  await fetch(`${ORIGIN}/admin/people/${encodeURIComponent("carol@example.com")}`, {
    method: "DELETE", headers: H(s),
  });
});

test("a refused login reports the ATTEMPTED identity (never the admin's)", async () => {
  const res = await fetch(`${ORIGIN}/admin/login`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ presentation: "pres-alice" }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.attempted, ALICE);
  assert.ok(!JSON.stringify(body).includes(ADMIN), "the admin email is not revealed");
});

test("/admin/state carries the whole console model", async () => {
  const s = await adminLogin();
  const res = await fetch(`${ORIGIN}/admin/state`, { headers: { cookie: s.cookie } });
  assert.equal(res.status, 200);
  const state = await res.json();
  assert.equal(state.admin, ADMIN);
  assert.ok(state.csrf, "a csrf token rides along");
  assert.equal(state.mounts.length, 1);
  assert.deepEqual(state.mounts[0].tools, ["read_text_file", "list_directory"], "live tool list");
  // People: the implicit admin row first, then the address book.
  assert.equal(state.people[0].email, ADMIN);
  assert.equal(state.people[0].admin, true);
  assert.equal(state.people.length, 4);
  // Roles: built-in present and flagged.
  assert.ok(state.roles.some((r) => r.builtin && r.name === "Full access"));
  assert.equal(state.needsRestart, false, "clean startup is in sync");
});

test("role + people edits are STAGED with diff entries; enforcement stays on the startup snapshot", async () => {
  const s = await adminLogin();

  // Grant bob a tool via a new role — saved, surfaced, NOT yet enforced.
  const created = await fetch(`${ORIGIN}/admin/roles`, { method: "POST", headers: H(s), body: JSON.stringify({ name: "Bots" }) });
  assert.equal(created.status, 201);
  const role = await created.json();
  const patched = await fetch(`${ORIGIN}/admin/roles/${role.id}`, {
    method: "PATCH", headers: H(s),
    body: JSON.stringify({ members: [BOB], grants: [{ mountId: "n1", on: ["list_directory"] }] }),
  });
  assert.equal(patched.status, 200);

  const state = await (await fetch(`${ORIGIN}/admin/state`, { headers: { cookie: s.cookie } })).json();
  assert.ok(state.pending.some((c) => c.sign === "+" && c.label === "role bots" && c.desc === "new role"), "new role staged");
  assert.equal(state.needsRestart, true);

  // Still refused live: the running gateway enforces the STARTUP roles.
  const bearer = await getBearer("pres-bob");
  const res = await mcp(bearer, "tools/call", { name: "list_directory", arguments: {} });
  assert.equal(res.status, 403, "staged role edits don't change the running gateway");

  // Cleanup: delete the staged role again (net-zero diff).
  const del = await fetch(`${ORIGIN}/admin/roles/${role.id}`, { method: "DELETE", headers: H(s) });
  assert.equal(del.status, 200);
  const after = await (await fetch(`${ORIGIN}/admin/state`, { headers: { cookie: s.cookie } })).json();
  assert.equal(after.needsRestart, false, "creating then deleting a role nets out");
});

test("member edits stage a 'members edited' entry; removing a person cascades", async () => {
  const s = await adminLogin();
  // Add carol, toggle her into Readers, then remove her from the address book.
  const add = await fetch(`${ORIGIN}/admin/people`, { method: "POST", headers: H(s), body: JSON.stringify({ email: "carol@example.com", name: "Carol" }) });
  assert.equal(add.status, 201);
  await fetch(`${ORIGIN}/admin/roles/readers`, { method: "PATCH", headers: H(s), body: JSON.stringify({ members: [ALICE, "carol@example.com"] }) });
  let state = await (await fetch(`${ORIGIN}/admin/state`, { headers: { cookie: s.cookie } })).json();
  assert.ok(state.pending.some((c) => c.sign === "~" && c.label === "role readers" && c.desc === "members edited"));

  const rm = await fetch(`${ORIGIN}/admin/people/${encodeURIComponent("carol@example.com")}`, { method: "DELETE", headers: H(s) });
  assert.equal(rm.status, 200);
  state = await (await fetch(`${ORIGIN}/admin/state`, { headers: { cookie: s.cookie } })).json();
  assert.ok(!state.people.some((p) => p.email === "carol@example.com"), "gone from the address book");
  assert.ok(!state.roles.find((r) => r.id === "readers").members.includes("carol@example.com"), "gone from every role");
  assert.equal(state.needsRestart, false, "add+remove nets out to the startup members");
});

test("the built-in role is protected: no delete, no grant edits, no admin membership", async () => {
  const s = await adminLogin();
  assert.equal((await fetch(`${ORIGIN}/admin/roles/full`, { method: "DELETE", headers: H(s) })).status, 400);
  assert.equal((await fetch(`${ORIGIN}/admin/roles/full`, {
    method: "PATCH", headers: H(s), body: JSON.stringify({ grants: [{ mountId: "n1", on: ["list_directory"] }] }),
  })).status, 400);
  assert.equal((await fetch(`${ORIGIN}/admin/roles/full`, {
    method: "PATCH", headers: H(s), body: JSON.stringify({ members: [SAM, ADMIN] }),
  })).status, 400, "the admin identity can't join a role");
  assert.equal((await fetch(`${ORIGIN}/admin/people`, {
    method: "POST", headers: H(s), body: JSON.stringify({ email: ADMIN }),
  })).status, 400, "the admin identity can't be added to the address book");
});

test("undo remove restores the startup def (staged removal → back in config)", async () => {
  const s = await adminLogin();
  assert.equal((await fetch(`${ORIGIN}/admin/mounts/n1`, { method: "DELETE", headers: H(s) })).status, 200);
  let state = await (await fetch(`${ORIGIN}/admin/state`, { headers: { cookie: s.cookie } })).json();
  assert.equal(state.mounts.find((m) => m.id === "n1").pending, "removed");

  const restored = await fetch(`${ORIGIN}/admin/mounts/n1/restore`, { method: "POST", headers: H(s) });
  assert.equal(restored.status, 200);
  state = await (await fetch(`${ORIGIN}/admin/state`, { headers: { cookie: s.cookie } })).json();
  assert.equal(state.mounts.find((m) => m.id === "n1").pending, null);
  assert.equal(state.needsRestart, false);
});

// --- v1 migration (unit) ----------------------------------------------------

test("a legacy per-mount allow list migrates to a role granting every tool", () => {
  const cfg = normalizeConfig({
    mounts: [{ id: "m1", name: "Notes", mount: "notes", command: ["echo"], allow: ["Friend@Example.com "] }],
  });
  assert.ok(cfg.people.some((p) => p.email === "friend@example.com"), "allowlisted email lands in people");
  const migrated = cfg.roles.find((r) => !r.builtin);
  assert.equal(migrated.name, "Notes");
  assert.deepEqual(migrated.members, ["friend@example.com"]);
  assert.deepEqual(migrated.grants, [{ mountId: "m1", on: ["*"] }], "granted every tool ('*' until discovery)");
  assert.ok(cfg.roles.some((r) => r.builtin), "the built-in role is ensured");
  // Idempotent: a v2 doc (roles present) is NOT re-migrated.
  const again = normalizeConfig(cfg);
  assert.equal(again.roles.filter((r) => !r.builtin).length, 1);
});
