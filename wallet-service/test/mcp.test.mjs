// The MCP tool surface, per tenant: tools/list parity with the local wallet,
// NEED_CREDENTIAL before provisioning, and audit rows for admin ops.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

const PORT = 43118;
process.env.PORT = String(PORT);
process.env.WALLET_DATABASE_PATH = ":memory:";
process.env.WALLET_KEK = randomBytes(32).toString("base64url");
process.env.WALLET_SESSION_SECRET = randomBytes(32).toString("base64url");

const { createWalletService } = await import("../src/server.mjs");

const ORIGIN = `http://localhost:${PORT}`;
const REDIRECT = "http://localhost:9/cb";
const EMAIL = "dan@example.com";

let service, accessToken;

before(() => new Promise((resolve) => {
  service = createWalletService({ verifyLogin: async () => ({ ok: true, email: EMAIL }) });
  service.server.listen(PORT, async () => {
    accessToken = await obtainToken();
    resolve();
  });
}));
after(() => service.server.close());

const post = (path, body, headers = {}) =>
  fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

async function obtainToken() {
  const reg = await post("/oauth/register", { redirect_uris: [REDIRECT] });
  const { client_id } = await reg.json();
  const login = await post("/oauth/login", { presentation: "x" });
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const approve = await post("/oauth/approve", {
    client_id, redirect_uri: REDIRECT, response_type: "code",
    code_challenge: challenge, code_challenge_method: "S256",
  }, { cookie });
  const code = new URL((await approve.json()).redirect).searchParams.get("code");
  const tok = await post("/oauth/token", new URLSearchParams({
    grant_type: "authorization_code", code, code_verifier: verifier,
    client_id, redirect_uri: REDIRECT,
  }).toString(), { "content-type": "application/x-www-form-urlencoded" });
  return (await tok.json()).access_token;
}

let nextId = 1;
async function rpc(method, params = {}) {
  const res = await post("/mcp", { jsonrpc: "2.0", id: nextId++, method, params }, {
    authorization: `Bearer ${accessToken}`,
    accept: "application/json, text/event-stream",
  });
  assert.equal(res.status, 200, `${method} HTTP ${res.status}`);
  const body = await res.json();
  assert.ok(!body.error, `${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

const callTool = (name, args = {}) => rpc("tools/call", { name, arguments: args });

test("initialize identifies the wallet", async () => {
  const r = await rpc("initialize", {
    protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" },
  });
  assert.equal(r.serverInfo.name, "browserid-wallet");
});

test("tool surface matches the local wallet", async () => {
  const { tools } = await rpc("tools/list");
  assert.deepEqual(
    tools.map((t) => t.name).sort(),
    ["authorize", "drop_grant", "forget", "get_assertion", "identity", "provision", "read_guestbook", "sign_guestbook", "warrants"]
  );
});

test("identity before provisioning says NEED_CREDENTIAL", async () => {
  const r = await callTool("identity");
  assert.match(r.content[0].text, /NEED_CREDENTIAL/);
});

test("warrants and get_assertion also need a credential first", async () => {
  for (const [name, args] of [["warrants", {}], ["get_assertion", { audience: "https://rp.example.com" }]]) {
    const r = await callTool(name, args);
    assert.match(r.content[0].text, /NEED_CREDENTIAL/, name);
  }
});

test("forget is safe with nothing stored and is audited", async () => {
  const r = await callTool("forget");
  assert.match(r.content[0].text, /0 credential/);
  const rows = service.db
    .prepare("SELECT op FROM audit_log WHERE account_email = ? ORDER BY id")
    .all(EMAIL)
    .map((x) => x.op);
  assert.ok(rows.includes("credential.forget"), `audit ops: ${rows.join(",")}`);
  assert.ok(rows.includes("account.login"));
  assert.ok(rows.includes("oauth.token"));
});

test("tenant isolation: another account sees no shared state", async () => {
  // Same DB, different tenant: the store keys everything by account email.
  assert.equal(service.store.hasCredential("someone-else@example.com"), false);
  assert.equal(service.store.loadAgent("someone-else@example.com"), null);
});
