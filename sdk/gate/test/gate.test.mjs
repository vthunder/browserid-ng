// The gate end to end over real HTTP: a real stdio child (the fs-child
// fixture, reading a real temp dir) wrapped by the gate; a MOCK broker
// (github-mcp idiom) for /verify-access + /status/check; a Lane-A bearer
// minted at /token reaching tools/call on the child and getting a genuine
// filesystem result; the grantor allowlist refusing a non-allowlisted human
// BEFORE the tool runs; the attribution line; and proof BOTH auth lanes are
// mounted (Lane B discovery + DCR).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { KeyPair } from "@browserid-ng/agent";
import { createGateService } from "../src/gate.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BROKER_PORT = 43350;
const PORT = 43351;
const BROKER = `http://localhost:${BROKER_PORT}`;
const RESOURCE = `http://localhost:${PORT}`;

const ALLOWED = "dan@example.com";
const BLOCKED = "mallory@evil.example";
const GATEWAY = "gate@example.com";
const GRANTEE = "claude@agents.example.com";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (claims) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(claims)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);

// A real device keypair; the certs are canned (the MOCK broker doesn't verify).
const gatewayKp = KeyPair.generate();
const credential = {
  device_key: Buffer.from(gatewayKp.seed).toString("base64url"),
  agent_device_cert: fakeJws({
    typ: "browserid-device-cert-v1",
    "public-key": { algorithm: "Ed25519", publicKey: gatewayKp.publicKeyB64 },
    holder: "svc.gate1",
    identities: [GATEWAY],
    iat: nowS(),
    exp: nowS() + 90 * 24 * 3600,
  }),
  idp: BROKER,
  identity: GATEWAY,
};

// --- mock broker: presentation string → verified grantor --------------------
let statusMode = "ok"; // "ok" | "revoked" | "down"
const broker = createServer(async (req, res) => {
  const reply = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
  let raw = ""; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  if (req.url === "/verify-access") {
    const grantor = { "pres-allowed": ALLOWED, "pres-blocked": BLOCKED }[body.presentation];
    if (!grantor) return reply(200, { status: "failure", reason: "verification failed" });
    assert.equal(body.audience, RESOURCE, "verify-access binds this resource as audience");
    return reply(200, {
      status: "okay",
      email: grantor,
      grantee: GRANTEE,
      holder: "agents.test",
      issuer: "example.com",
      scopes: ["tool:read_text_file", "tool:list_directory"],
      status_refs: [{ uri: `${BROKER}/status`, idx: 1 }],
    });
  }
  if (req.url === "/status/check") {
    if (statusMode === "down") return reply(500, {});
    return reply(200, { ok: true, revoked: statusMode === "revoked" });
  }
  reply(404, {});
});

// --- a real temp dir the fs-child serves ------------------------------------
const dataDir = mkdtempSync(join(tmpdir(), "gate-notes-"));
writeFileSync(join(dataDir, "hello.txt"), "notes from a gated vault\n");

const logLines = [];
let svc;

before(async () => {
  await new Promise((r) => broker.listen(BROKER_PORT, r));
  svc = await createGateService({
    allow: [ALLOWED],
    name: "Test Notes",
    child: { command: process.execPath, args: [join(HERE, "fixtures", "fs-child.mjs"), dataDir] },
    credential,
    resource: RESOURCE,
    broker: BROKER,
    statusCacheS: 0, // re-check revocation every call
    log: (l) => logLines.push(l),
  });
  await new Promise((r) => svc.server.listen(PORT, r));
});
after(async () => { await svc.close(); broker.close(); });

// --- helpers ----------------------------------------------------------------
async function getBearer(presentation) {
  const res = await fetch(`${RESOURCE}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: presentation,
    }),
  });
  assert.equal(res.status, 200, `token HTTP ${res.status}`);
  return (await res.json()).access_token;
}
let nextId = 1;
async function rpcRaw(bearer, method, params = {}) {
  return fetch(`${RESOURCE}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  });
}
async function rpc(bearer, method, params = {}) {
  const res = await rpcRaw(bearer, method, params);
  assert.equal(res.status, 200, `${method} HTTP ${res.status}`);
  const body = await res.json();
  assert.ok(!body.error, `${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}
const callTool = (bearer, name, args = {}) => rpc(bearer, "tools/call", { name, arguments: args });

// --- discovery serves BOTH lanes --------------------------------------------
test("discovery advertises the resource and BOTH auth lanes", async () => {
  const prm = await (await fetch(`${RESOURCE}/.well-known/oauth-protected-resource`)).json();
  assert.equal(prm.resource, RESOURCE);
  assert.ok(prm.scopes_supported.includes("tool:read_text_file"), "tool→scope auto-map surfaced");

  const asm = await (await fetch(`${RESOURCE}/.well-known/oauth-authorization-server`)).json();
  assert.equal(asm.token_endpoint, `${RESOURCE}/token`);
  // Lane A grant + Lane B additions both present.
  assert.ok(asm.grant_types_supported.includes("urn:ietf:params:oauth:grant-type:jwt-bearer"), "Lane A grant");
  assert.ok(asm.grant_types_supported.includes("authorization_code"), "Lane B grant");
  assert.equal(asm.authorization_endpoint, `${RESOURCE}/authorize`);
  assert.equal(asm.registration_endpoint, `${RESOURCE}/register`);
  assert.deepEqual(asm.code_challenge_methods_supported, ["S256"]);
});

test("Lane B dynamic client registration is mounted (POST /register)", async () => {
  const res = await fetch(`${RESOURCE}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], client_name: "claude.ai" }),
  });
  assert.equal(res.status, 201);
  const reg = await res.json();
  assert.match(reg.client_id, /^mcp_/);
  assert.ok(reg.grant_types.includes("authorization_code"));
});

// --- tools surface + real filesystem result ---------------------------------
test("the wrapped child's tools are proxied with their real schemas", async () => {
  const bearer = await getBearer("pres-allowed");
  const { tools } = await rpc(bearer, "tools/list");
  assert.deepEqual(tools.map((t) => t.name).sort(), ["list_directory", "read_text_file"]);
  const readTool = tools.find((t) => t.name === "read_text_file");
  assert.equal(readTool.inputSchema.type, "object", "child's JSON schema preserved");
});

test("a mcp-auth bearer reaches tools/call on the child and gets a REAL filesystem result", async () => {
  const bearer = await getBearer("pres-allowed");
  const list = await callTool(bearer, "list_directory", {});
  assert.match(list.content[0].text, /hello\.txt/, "listed the real temp dir");
  const read = await callTool(bearer, "read_text_file", { path: "hello.txt" });
  assert.match(read.content[0].text, /notes from a gated vault/, "read the real file's contents");
});

// --- attribution ------------------------------------------------------------
test("each tool call emits one attribution line (grantor, grantee, tool, args digest)", async () => {
  const bearer = await getBearer("pres-allowed");
  logLines.length = 0;
  await callTool(bearer, "read_text_file", { path: "hello.txt" });
  const line = logLines.find((l) => l.includes("tool=read_text_file"));
  assert.ok(line, `no attribution line in ${JSON.stringify(logLines)}`);
  assert.ok(line.includes(`grantor=${ALLOWED}`), line);
  assert.ok(line.includes(`grantee=${GRANTEE}`), line);
  assert.ok(line.includes("args="), line);
  assert.ok(line.includes("hello.txt"), "args digest carries the argument");
});

// --- allowlist --------------------------------------------------------------
test("a non-allowlisted grantor is refused (403) BEFORE any tool runs", async () => {
  const bearer = await getBearer("pres-blocked"); // verifies, but grantor not on --allow
  logLines.length = 0;
  const res = await rpcRaw(bearer, "tools/call", { name: "read_text_file", arguments: { path: "hello.txt" } });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, "access_denied");
  assert.match(body.error_description, new RegExp(BLOCKED));
  // The tool never ran: no attribution line, only the refusal line.
  assert.ok(!logLines.some((l) => l.includes("tool=read_text_file")), "the wrapped tool must not run");
  assert.ok(logLines.some((l) => l.includes("REFUSED")), "the refusal is logged");
});

// --- fail-closed revocation (the flagship property, on a proxied call) -------
test("a revoke fails the agent closed on its next proxied call", async () => {
  const bearer = await getBearer("pres-allowed");
  assert.match((await callTool(bearer, "list_directory", {})).content[0].text, /hello\.txt/);
  statusMode = "revoked";
  try {
    const res = await rpcRaw(bearer, "tools/call", { name: "list_directory", arguments: {} });
    assert.equal(res.status, 401);
    assert.match((await res.json()).error_description, /revoked/);
  } finally {
    statusMode = "ok";
  }
});

test("the MCP endpoint requires a bearer (401 + resource-metadata challenge)", async () => {
  const res = await rpcRaw(null, "tools/list");
  assert.equal(res.status, 401);
  assert.match(res.headers.get("www-authenticate"), /resource_metadata=/);
});
