// Config lifecycle under the STAGED model: the console EDITS config.json; the
// running set of children changes only on a RESTART.
//  • add → persisted + pending "new", NOT live (no /<mount>/mcp yet);
//  • restart → the persisted enabled mount spawns and is reachable + gated;
//  • remove → persisted, but the child keeps running until restart (pending
//    "removed"); a further restart drops it.
// Proves persistence across a simulated restart via a temp GATE_HOME.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { KeyPair } from "@browserid-ng/agent";
import { createGateway } from "../src/gateway.mjs";
import { configPath } from "../src/config.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BROKER_PORT = 43380;
const PORT = 43381;
const BROKER = `http://localhost:${BROKER_PORT}`;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const ALLOWED = "dan@example.com";
const GATEWAY = "gate@example.com";
const GRANTEE = "claude@agents.example.com";
const ADMIN = "admin@example.com";

const GATE_HOME = mkdtempSync(join(tmpdir(), "gate-home-"));
process.env.GATE_HOME = GATE_HOME;

const notesDir = mkdtempSync(join(tmpdir(), "gate-notes-"));
writeFileSync(join(notesDir, "hello.txt"), "staged and gated\n");

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (c) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(c)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);
const gatewayKp = KeyPair.generate();
const credential = {
  device_key: Buffer.from(gatewayKp.seed).toString("base64url"),
  agent_device_cert: fakeJws({ typ: "browserid-device-cert-v1", "public-key": { algorithm: "Ed25519", publicKey: gatewayKp.publicKeyB64 }, holder: "svc.gate1", identities: [GATEWAY], iat: nowS(), exp: nowS() + 8.64e6 }),
  idp: BROKER, identity: GATEWAY,
};

const broker = createServer(async (req, res) => {
  const reply = (c, o) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  let raw = ""; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  if (req.url === "/verify-access") {
    if (body.presentation !== "pres-allowed") return reply(200, { status: "failure", reason: "no" });
    return reply(200, { status: "okay", email: ALLOWED, grantee: GRANTEE, holder: "a.1", issuer: "example.com", scopes: ["tool:read_text_file", "tool:list_directory"], status_refs: [] });
  }
  if (req.url === "/status/check") return reply(200, { ok: true, revoked: false });
  reply(404, {});
});

before(() => new Promise((r) => broker.listen(BROKER_PORT, r)));
after(() => broker.close());

const child = [process.execPath, join(HERE, "fixtures", "fs-child.mjs"), notesDir];
const newGateway = () => createGateway({ credential, adminEmail: ADMIN, broker: BROKER, origin: ORIGIN, statusCacheS: 0, log: () => {} });

async function reachable(slug) {
  // `connection: close` avoids undici reusing a keep-alive socket to a prior
  // gateway instance bound to the same port across our simulated restarts.
  const H = { connection: "close" };
  try {
    const tok = await fetch(`${ORIGIN}/${slug}/token`, {
      method: "POST", headers: { ...H, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: "pres-allowed" }),
    });
    if (tok.status !== 200) return false;
    const bearer = (await tok.json()).access_token;
    const res = await fetch(`${ORIGIN}/${slug}/mcp`, {
      method: "POST", headers: { ...H, "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_directory", arguments: {} } }),
    });
    if (res.status !== 200) return false;
    const body = await res.json();
    return /hello\.txt/.test(body?.result?.content?.[0]?.text || "");
  } catch {
    return false; // connection refused / reset ⇒ not reachable
  }
}

test("add is STAGED: persisted + pending, but NOT live until restart", async () => {
  const gw = newGateway();
  await gw.start({ port: PORT });
  try {
    const row = gw.addMount({ name: "Notes", mount: "notes", command: child, allow: [ALLOWED] });
    assert.equal(row.running, false);
    assert.equal(row.pending, "new");
    // Persisted to disk…
    assert.ok(existsSync(configPath()), "config.json written");
    assert.match(readFileSync(configPath(), "utf8"), /"mount": "notes"/);
    // …but the endpoint is NOT mounted live.
    assert.equal(await reachable("notes"), false, "not reachable before restart");
    const list = gw.listMounts();
    assert.equal(list.needsRestart, true);
  } finally {
    await gw.close();
  }
});

test("restart applies the persisted config: the mount spawns and is gated+reachable", async () => {
  const gw = newGateway(); // fresh instance, same GATE_HOME → loads config.json
  await gw.start({ port: PORT });
  try {
    assert.ok(gw.mounts.has("notes"), "mount spawned at startup from persisted config");
    assert.equal(await reachable("notes"), true, "reachable after restart");
    const list = gw.listMounts();
    assert.equal(list.needsRestart, false, "no pending changes right after a clean restart");
    assert.equal(list.mounts.find((m) => m.mount === "notes").running, true);
  } finally {
    await gw.close();
  }
});

test("remove is STAGED: dropped from config + pending 'removed', child keeps running until restart", async () => {
  const gw = newGateway();
  await gw.start({ port: PORT });
  try {
    const id = gw.listMounts().mounts.find((m) => m.mount === "notes").id;
    gw.removeMount(id);
    // Persisted removal…
    assert.ok(!/"mount": "notes"/.test(readFileSync(configPath(), "utf8")), "removed from config.json");
    // …but still live this run (staged): reachable + surfaced as pending removal.
    assert.equal(await reachable("notes"), true, "child keeps running until restart");
    const removed = gw.listMounts().mounts.find((m) => m.id === id);
    assert.equal(removed.pending, "removed");
    assert.equal(removed.running, true);
  } finally {
    await gw.close();
  }
});

test("a further restart drops the removed mount entirely", async () => {
  const gw = newGateway();
  await gw.start({ port: PORT });
  try {
    assert.ok(!gw.mounts.has("notes"), "removed mount not spawned");
    assert.equal(await reachable("notes"), false, "404 after the applying restart");
  } finally {
    await gw.close();
  }
});
