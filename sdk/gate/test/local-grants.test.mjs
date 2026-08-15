// LOCAL grants mode (the self-hosted default, Dan's 2026-08-15 call):
// unsigned roles enforce directly — no signing ceremony — using the STARTUP
// snapshot (the staged model). The identity-first connect flow is identical
// to signed mode; only the entitlement source differs. Signed mode is the
// --signed-grants opt-in, covered by roles.test/policy.test.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { KeyPair } from "@browserid-ng/agent";
import { createGateway } from "../src/gateway.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BROKER_PORT = 43420;
const PORT = 43421;
const BROKER = `http://localhost:${BROKER_PORT}`;
const ORIGIN = `http://localhost:${PORT}`;

const ADMIN = "admin@example.com";
const ALICE = "alice@example.com"; // Readers: list_directory only
const BOB = "bob@example.com"; // no role

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (claims) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(claims)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);
const gatewayKp = KeyPair.generate();
const credential = {
  device_key: Buffer.from(gatewayKp.seed).toString("base64url"),
  agent_device_cert: fakeJws({ typ: "browserid-device-cert-v1", "public-key": { algorithm: "Ed25519", publicKey: gatewayKp.publicKeyB64 }, holder: "svc.g", identities: ["gate@example.com"], iat: nowS(), exp: nowS() + 8.64e6 }),
  idp: BROKER, identity: "gate@example.com",
};

const EMAILS = { "pres-admin": ADMIN, "pres-alice": ALICE, "pres-bob": BOB };
const broker = createServer(async (req, res) => {
  const reply = (c, o) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  let raw = ""; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  if (req.url === "/verify-access") {
    const email = EMAILS[body.presentation];
    if (!email) return reply(200, { status: "failure", reason: "no" });
    return reply(200, {
      status: "okay", email, grantee: email, holder: "a.1", issuer: "example.com",
      scopes: ["tool:read_text_file", "tool:list_directory"], status_refs: [],
    });
  }
  reply(404, {});
});

const dir = mkdtempSync(join(tmpdir(), "gate-local-"));
writeFileSync(join(dir, "note.txt"), "a private note\n");

let gw;
before(async () => {
  await new Promise((r) => broker.listen(BROKER_PORT, r));
  gw = createGateway({
    credential, adminEmail: ADMIN, broker: BROKER, origin: ORIGIN, statusCacheS: 0, persist: false,
    log: () => {},
    // No signedGrants: LOCAL mode is the default.
    config: {
      mounts: [{ id: "n1", name: "Notes", mount: "notes", command: [process.execPath, join(HERE, "fixtures", "fs-child.mjs"), dir], enabled: true }],
      people: [{ email: ALICE, name: "Alice" }],
      roles: [
        { id: "full", name: "Full access", builtin: true, members: [], grants: [] },
        { id: "readers", name: "Readers", builtin: false, members: [ALICE], grants: [{ mountId: "n1", on: ["list_directory"] }] },
      ],
    },
  });
  await gw.start({ port: PORT });
});
after(async () => { await gw.close(); broker.close(); });

async function bearer(pres) {
  const res = await fetch(`${ORIGIN}/notes/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: pres }),
  });
  assert.equal(res.status, 200);
  return (await res.json()).access_token;
}
const mcp = (b, method, params) =>
  fetch(`${ORIGIN}/notes/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${b}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });

test("local mode: unsigned roles enforce directly — no ceremony anywhere", async () => {
  assert.equal(gw.signedGrants, false);
  // Alice: the granted subset works, the rest is refused.
  const b = await bearer("pres-alice");
  const list = await (await mcp(b, "tools/list", {})).json();
  assert.deepEqual(list.result.tools.map((t) => t.name), ["list_directory"]);
  const denied = await (await mcp(b, "tools/call", { name: "read_text_file", arguments: { path: "note.txt" } })).json();
  assert.match(denied.result.content[0].text, /ACCESS_DENIED/);
  // Bob (no role): refused before any tool runs.
  const rb = await bearer("pres-bob");
  assert.equal((await mcp(rb, "tools/call", { name: "list_directory", arguments: {} })).status, 403);
  // Admin: implicit full access.
  const ab = await bearer("pres-admin");
  const read = await (await mcp(ab, "tools/call", { name: "read_text_file", arguments: { path: "note.txt" } })).json();
  assert.match(read.result.content[0].text, /a private note/);
});

test("the /shared landing lists exactly what the signed-in member may use", async () => {
  // Unauthenticated: the page bounces to the member login; the API 401s.
  const page = await fetch(`${ORIGIN}/shared`, { redirect: "manual" });
  assert.equal(page.status, 302);
  assert.ok(page.headers.get("location").startsWith("/connect/login"));
  assert.equal((await fetch(`${ORIGIN}/shared/servers`)).status, 401);

  const login = async (pres) => {
    const r = await fetch(`${ORIGIN}/connect/login`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ presentation: pres, next: "/shared" }),
    });
    assert.equal(r.status, 200);
    return r.headers.getSetCookie().map((c) => c.split(";")[0]).find((c) => c.startsWith("gate_user="));
  };

  // Alice sees notes with exactly her granted tool.
  const aliceCookie = await login("pres-alice");
  const a = await (await fetch(`${ORIGIN}/shared/servers`, { headers: { cookie: aliceCookie } })).json();
  assert.equal(a.email, ALICE);
  assert.equal(a.servers.length, 1);
  assert.equal(a.servers[0].url, `${ORIGIN}/notes/mcp`);
  assert.deepEqual(a.servers[0].tools, ["list_directory"]);

  // Bob (no role) sees an empty landing, not an error.
  const bobCookie = await login("pres-bob");
  const b = await (await fetch(`${ORIGIN}/shared/servers`, { headers: { cookie: bobCookie } })).json();
  assert.deepEqual(b.servers, []);

  // The signed-in page itself serves.
  const html = await fetch(`${ORIGIN}/shared`, { headers: { cookie: aliceCookie } });
  assert.equal(html.status, 200);
  assert.match(await html.text(), /Servers shared with you/);
});

test("the gallery serves curated servers with name, description and repo", async () => {
  const g = await (await fetch(`${ORIGIN}/admin/gallery`)).json();
  assert.ok(Array.isArray(g.servers) && g.servers.length >= 6);
  for (const it of g.servers) {
    assert.ok(it.name && it.description && it.repo && it.command, JSON.stringify(it));
  }
});

test("local mode: the grants API reports disabled (console shows the staged model)", async () => {
  const login = await fetch(`${ORIGIN}/admin/login`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ presentation: "pres-admin" }),
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.getSetCookie().map((c) => c.split(";")[0]).find((c) => c.startsWith("gate_session="));
  const g = await (await fetch(`${ORIGIN}/admin/grants`, { headers: { cookie } })).json();
  assert.equal(g.disabled, true);
  assert.deepEqual(g.pending, []);
});
