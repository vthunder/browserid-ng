// The multi-mount gateway: two mounts wrapping two DIFFERENT real fs-children,
// each a self-contained OAuth resource at its own /<slug> prefix. Proves:
//  • path-prefixed discovery (resource + advertised OAuth URLs carry /<slug>),
//  • independent gated tools/call reaching the right child,
//  • the two mounts don't leak into each other,
//  • an unknown mount 404s.
// Mock broker via the github-mcp idiom (real local HTTP, keyed on presentation).
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
const BROKER_PORT = 43360;
const PORT = 43361;
const BROKER = `http://localhost:${BROKER_PORT}`;
const ORIGIN = `http://127.0.0.1:${PORT}`;

const ALLOWED = "dan@example.com";
const GATEWAY = "gate@example.com";
const GRANTEE = "claude@agents.example.com";
const ADMIN = "admin@example.com";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (c) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(c)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);
const gatewayKp = KeyPair.generate();
const credential = {
  device_key: Buffer.from(gatewayKp.seed).toString("base64url"),
  agent_device_cert: fakeJws({ typ: "browserid-device-cert-v1", "public-key": { algorithm: "Ed25519", publicKey: gatewayKp.publicKeyB64 }, holder: "svc.gate1", identities: [GATEWAY], iat: nowS(), exp: nowS() + 8.64e6 }),
  idp: BROKER,
  identity: GATEWAY,
};

let statusMode = "ok";
const broker = createServer(async (req, res) => {
  const reply = (c, o) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  let raw = ""; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  if (req.url === "/verify-access") {
    const grantor = { "pres-allowed": ADMIN }[body.presentation];
    if (!grantor) return reply(200, { status: "failure", reason: "verification failed" });
    // Two mounts ⇒ two audiences; assert it's one of ours (path-prefixed).
    assert.ok([`${ORIGIN}/notes`, `${ORIGIN}/docs`].includes(body.audience), `audience ${body.audience}`);
    return reply(200, {
      status: "okay", email: grantor, grantee: GRANTEE, holder: "agents.test", issuer: "example.com",
      scopes: ["tool:read_text_file", "tool:list_directory"],
      status_refs: [{ uri: `${BROKER}/status`, idx: 1 }],
    });
  }
  if (req.url === "/status/check") return statusMode === "down" ? reply(500, {}) : reply(200, { ok: true, revoked: statusMode === "revoked" });
  reply(404, {});
});

const notesDir = mkdtempSync(join(tmpdir(), "gate-notes-"));
const docsDir = mkdtempSync(join(tmpdir(), "gate-docs-"));
writeFileSync(join(notesDir, "note.txt"), "a private note\n");
writeFileSync(join(docsDir, "readme.txt"), "the docs\n");

const child = (dir) => [process.execPath, join(HERE, "fixtures", "fs-child.mjs"), dir];

let gw;
before(async () => {
  await new Promise((r) => broker.listen(BROKER_PORT, r));
  gw = createGateway({
    credential, adminEmail: ADMIN, broker: BROKER, origin: ORIGIN, statusCacheS: 0, persist: false,
    log: () => {},
    config: { mounts: [
      { id: "n1", name: "Notes", mount: "notes", command: child(notesDir), allow: [ALLOWED], enabled: true },
      { id: "d1", name: "Docs", mount: "docs", command: child(docsDir), allow: [ALLOWED], enabled: true },
    ] },
  });
  await gw.start({ port: PORT });
});
after(async () => { await gw.close(); broker.close(); });

async function getBearer(slug, presentation) {
  const res = await fetch(`${ORIGIN}/${slug}/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: presentation }),
  });
  assert.equal(res.status, 200, `token HTTP ${res.status}`);
  return (await res.json()).access_token;
}
let nextId = 1;
async function callTool(slug, bearer, name, args = {}) {
  const res = await fetch(`${ORIGIN}/${slug}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${bearer}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method: "tools/call", params: { name, arguments: args } }),
  });
  assert.equal(res.status, 200, `call HTTP ${res.status}`);
  const body = await res.json();
  assert.ok(!body.error, JSON.stringify(body.error));
  return body.result;
}

test("each mount's discovery is path-prefixed to its own /<slug>", async () => {
  for (const slug of ["notes", "docs"]) {
    const prm = await (await fetch(`${ORIGIN}/${slug}/.well-known/oauth-protected-resource`)).json();
    assert.equal(prm.resource, `${ORIGIN}/${slug}`, `${slug} resource carries the prefix`);
    const asm = await (await fetch(`${ORIGIN}/${slug}/.well-known/oauth-authorization-server`)).json();
    assert.equal(asm.token_endpoint, `${ORIGIN}/${slug}/token`);
    assert.equal(asm.authorization_endpoint, `${ORIGIN}/${slug}/authorize`);
    assert.equal(asm.registration_endpoint, `${ORIGIN}/${slug}/register`);
    assert.ok(asm.grant_types_supported.includes("authorization_code"));
  }
});

test("PATH-INSERTED discovery works (RFC 8414/9728 — what claude.ai actually fetches)", async () => {
  for (const slug of ["notes", "docs"]) {
    // A spec client derives the AS metadata URL from the issuer <origin>/<slug>
    // by INSERTING the well-known between host and path — not suffixing it.
    const asRes = await fetch(`${ORIGIN}/.well-known/oauth-authorization-server/${slug}`);
    assert.equal(asRes.status, 200, `${slug} AS metadata must be at the path-inserted location`);
    const asm = await asRes.json();
    assert.equal(asm.registration_endpoint, `${ORIGIN}/${slug}/register`);
    assert.equal(asm.token_endpoint, `${ORIGIN}/${slug}/token`);
    const prRes = await fetch(`${ORIGIN}/.well-known/oauth-protected-resource/${slug}`);
    assert.equal(prRes.status, 200, `${slug} PR metadata must be at the path-inserted location too`);
    assert.equal((await prRes.json()).resource, `${ORIGIN}/${slug}`);
  }
  // A bogus mount slug in the inserted form is a 404, not a crash.
  assert.equal((await fetch(`${ORIGIN}/.well-known/oauth-authorization-server/nope`)).status, 404);
});

test("the /<slug>/mcp 401 challenge points at the prefixed metadata", async () => {
  const res = await fetch(`${ORIGIN}/notes/mcp`, {
    method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(res.status, 401);
  assert.match(res.headers.get("www-authenticate"), new RegExp(`${ORIGIN}/notes/\\.well-known/oauth-protected-resource`));
});

test("each mount serves its OWN child's files, independently", async () => {
  const notesBearer = await getBearer("notes", "pres-allowed");
  const docsBearer = await getBearer("docs", "pres-allowed");

  const notesList = await callTool("notes", notesBearer, "list_directory", {});
  assert.match(notesList.content[0].text, /note\.txt/);
  assert.ok(!notesList.content[0].text.includes("readme.txt"), "notes mount must not see docs' files");

  const docsRead = await callTool("docs", docsBearer, "read_text_file", { path: "readme.txt" });
  assert.match(docsRead.content[0].text, /the docs/);
});

test("a bearer minted for one mount is not valid at another (separate stores)", async () => {
  const notesBearer = await getBearer("notes", "pres-allowed");
  const res = await fetch(`${ORIGIN}/docs/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${notesBearer}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }),
  });
  assert.equal(res.status, 401, "a notes bearer is unknown to the docs mount");
});

test("an unknown mount 404s", async () => {
  const res = await fetch(`${ORIGIN}/nope/.well-known/oauth-protected-resource`);
  assert.equal(res.status, 404);
});
