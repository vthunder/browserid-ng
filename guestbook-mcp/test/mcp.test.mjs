// The guestbook MCP surface: AUTH_REQUIRED payload when no presentation,
// forwarding to the guestbook API, and error translation (stale/revoked).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

const MOCK_PORT = 43210;
const PORT = 43211;
process.env.PORT = String(PORT);
process.env.GUESTBOOK_URL = `http://localhost:${MOCK_PORT}`;

const { createGuestbookService } = await import("../src/server.mjs");
const { AUDIENCE, WALLET_MCP_URL } = await import("../src/config.mjs");

// -- mock guestbook API: behavior keyed on the presentation string ----------
const seen = [];
const mock = createServer(async (req, res) => {
  const reply = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  if (req.method === "GET" && req.url === "/feed")
    return reply(200, {
      entries: [{ message: "hi", agent: "claude@agents.browserid.me", parent: "dan@example.com" }],
    });
  let body = "";
  for await (const c of req) body += c;
  const parsed = JSON.parse(body);
  seen.push(parsed);
  switch (parsed.presentation) {
    case "good":
      return reply(200, {
        success: true,
        url: "https://browserid.me/guestbook#e1",
        name: parsed.name || "Claude",
        agent: "claude@agents.browserid.me",
        parent: "dan@example.com",
      });
    case "stale":
      return reply(401, { reason: "assertion expired" });
    case "revoked":
      return reply(403, { reason: "warrant revoked by grantor" });
    default:
      return reply(401, { reason: "verification failed" });
  }
});

let service;
before(() => new Promise((resolve) => {
  mock.listen(MOCK_PORT, () => {
    service = createGuestbookService();
    service.server.listen(PORT, resolve);
  });
}));
after(() => { service.server.close(); mock.close(); });

let nextId = 1;
async function rpc(method, params = {}) {
  const res = await fetch(`http://localhost:${PORT}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  });
  assert.equal(res.status, 200, `${method} HTTP ${res.status}`);
  const body = await res.json();
  assert.ok(!body.error, `${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}
const callTool = async (name, args = {}) => {
  const r = await rpc("tools/call", { name, arguments: args });
  return r.content[0].text;
};

test("initialize identifies the guestbook server (authless)", async () => {
  const r = await rpc("initialize", {
    protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" },
  });
  assert.equal(r.serverInfo.name, "browserid-guestbook");
});

test("tool surface", async () => {
  const { tools } = await rpc("tools/list");
  assert.deepEqual(tools.map((t) => t.name).sort(), ["read_guestbook", "sign_guestbook"]);
  const sign = tools.find((t) => t.name === "sign_guestbook");
  assert.match(sign.description, /call this tool anyway/i, "description invites the discovery flow");
});

test("sign without presentation → AUTH_REQUIRED with the full recovery recipe", async () => {
  const t = await callTool("sign_guestbook", { message: "hello" });
  assert.match(t, /^AUTH_REQUIRED/);
  assert.ok(t.includes(`audience: ${AUDIENCE}`), "names the audience");
  assert.ok(t.includes("guestbook-sign"), "names the scope");
  assert.ok(t.includes(WALLET_MCP_URL), "carries the wallet connector URL");
  assert.match(t, /get_assertion/, "wallet-installed branch");
  assert.match(t, /custom connector/i, "wallet-missing branch");
  assert.match(t, /not a failure or a trick/, "legitimizes the flow");
  assert.match(t, /Never construct or guess/, "forbids fabrication");
});

test("sign with a valid presentation forwards and reports attribution", async () => {
  const t = await callTool("sign_guestbook", { message: "a haiku", presentation: "good", name: "Claude" });
  assert.match(t, /^Signed!/);
  assert.match(t, /acting for dan@example\.com/);
  const fwd = seen.at(-1);
  assert.deepEqual(fwd, { presentation: "good", message: "a haiku", name: "Claude" });
});

test("expired assertion → STALE_PRESENTATION, points back to get_assertion", async () => {
  const t = await callTool("sign_guestbook", { message: "m", presentation: "stale" });
  assert.match(t, /^STALE_PRESENTATION/);
  assert.match(t, /get_assertion/);
});

test("revoked warrant → WARRANT_REVOKED, points to authorize replace:true", async () => {
  const t = await callTool("sign_guestbook", { message: "m", presentation: "revoked" });
  assert.match(t, /^WARRANT_REVOKED/);
  assert.match(t, /replace: true/);
});

test("garbage presentation → AUTH_REQUIRED with the verifier's reason", async () => {
  const t = await callTool("sign_guestbook", { message: "m", presentation: "nonsense" });
  assert.match(t, /^AUTH_REQUIRED/);
  assert.match(t, /reason: verification failed/);
});

test("read_guestbook needs no auth", async () => {
  const t = await callTool("read_guestbook");
  assert.match(t, /“hi” — claude@agents\.browserid\.me, for dan@example\.com/);
});
