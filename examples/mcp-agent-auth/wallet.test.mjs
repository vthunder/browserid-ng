// Acceptance test for the wallet MCP server: an MCP client drives its tools
// (authorize → get_assertion) against a REAL local mock broker/IdP over HTTP
// (the SDK uses global fetch), with no shell and no Rust. Proves the full
// agent-native flow works through MCP tool calls.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { KeyPair, publicKeyField, decodeJwtClaims, b64u } from "../../sdk/agent/src/crypto.mjs";
import { nowS } from "../../sdk/agent/src/protocol.mjs";

const HDR = { alg: "EdDSA", typ: "JWT" };

// A real-HTTP mock broker+IdP that auto-approves warrants (no human).
function startMockBroker() {
  const issuerKey = KeyPair.generate();
  const userKey = KeyPair.generate();
  const provKey = KeyPair.generate();
  let host;
  const lastReq = (bundle) => decodeJwtClaims(bundle.split("~").pop());

  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = JSON.parse(raw || "{}");
      const send = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ success: true, ...o })); };
      const domain = host;
      if (req.url === "/provision/endorse") return send({ endorsement: issuerKey.jws(HDR, { typ: "e", iat: nowS() }) });
      if (req.url === "/provision/mint") {
        const r = lastReq(body.request_bundle);
        const email = `${r.name}@${domain}`;
        return send({ email, cert: issuerKey.jws(HDR, {
          typ: "browserid-agent-cert-v1", iss: domain, iat: nowS(), exp: nowS() + 6 * 3600,
          "public-key": publicKeyField(r["agent-key"].publicKey), principal: { email },
          agent: { parent: "alice@mingo.place" }, registrar: `http://${domain}`,
          status: { uri: `http://${domain}/s`, idx: 1 } }) });
      }
      if (req.url === "/warrant/request") {
        const r = lastReq(body.request_bundle);
        server._grants = r["warrant-grants"];
        server._agent = `${r.name}@${domain}`;
        return send({ code: "wrq_1", verification_uri: `http://${domain}/consent/wrq_1`, expires_in: 900, interval: 1 });
      }
      if (req.url === "/warrant/poll") {
        const warrants = server._grants.map((g) => userKey.jws(HDR, {
          typ: "browserid-agent-warrant-v1", iss: "alice@mingo.place", agent: server._agent,
          aud: g.aud, ...(g.scopes ? { scopes: g.scopes } : {}), "parent-cert": "u.cert",
          status: { uri: `http://${domain}/s`, idx: 2 }, iat: nowS(), exp: nowS() + 90 * 86400 }));
        return send({ status: "approved", warrants, warrant: warrants[0] });
      }
      res.writeHead(404); res.end("{}");
    });
  });
  return { server, userKey, provKey, setHost: (h) => (host = h) };
}

test("wallet MCP server: authorize → get_assertion over MCP (no shell)", async () => {
  const mock = startMockBroker();
  mock.server.listen(0, "127.0.0.1");
  await once(mock.server, "listening");
  const host = `127.0.0.1:${mock.server.address().port}`;
  mock.setHost(host);
  const base = `http://${host}`;

  // A credential whose broker+idp point at the mock, with one reserved name.
  const userKey = mock.userKey;
  const uCert = userKey.jws(HDR, { iss: "mingo.place", exp: nowS() + 99999, iat: nowS(),
    "public-key": publicKeyField(userKey.publicKeyB64), principal: { email: "alice@mingo.place" } });
  const pCert = userKey.jws(HDR, { typ: "browserid-provisioning-cert-v1", iss: "alice@mingo.place",
    iat: nowS(), exp: nowS() + 99999, "public-key": publicKeyField(mock.provKey.publicKeyB64),
    constraint: { names: ["researcher"], patterns: [] } });
  const credential = { secret_key: b64u(mock.provKey.seed), delegation: `${uCert}~${pCert}`, broker: base, idp: base };

  const credPath = join(tmpdir(), `wallet-test-cred-${process.pid}.json`);
  const idPath = join(tmpdir(), `wallet-test-id-${process.pid}.json`);
  await writeFile(credPath, JSON.stringify(credential));

  const client = new Client({ name: "wallet-test", version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [new URL("./wallet.mjs", import.meta.url).pathname],
    env: { ...process.env, AGENT_CREDENTIAL: credPath, AGENT_IDENTITY: idPath },
  });
  await client.connect(transport);
  const audience = "https://notes.mcp.example";
  const textOf = (r) => r.content.map((c) => c.text).join("\n");

  try {
    // identity — provisions on demand, reports who it acts as
    const who = await client.callTool({ name: "identity", arguments: {} });
    assert.match(textOf(who), /Acting as researcher@/);

    // authorize — returns an approve URL (mock auto-approves on poll)
    const auth = await client.callTool({ name: "authorize", arguments: { audience, scopes: ["post", "read"] } });
    assert.match(textOf(auth), /APPROVE_URL: http:\/\//);

    // get_assertion — waits for approval, returns the backed presentation
    const got = await client.callTool({ name: "get_assertion", arguments: { audience } });
    const m = textOf(got).match(/ASSERTION: (\S+)/);
    assert.ok(m, "expected an ASSERTION, got: " + textOf(got));
    const parts = m[1].split("~");
    assert.equal(parts.length, 3); // agent_cert ~ warrant ~ assertion
    assert.equal(decodeJwtClaims(parts[2]).aud, audience);
    assert.equal(decodeJwtClaims(parts[1]).typ, "browserid-agent-warrant-v1");
  } finally {
    await client.close();
    mock.server.close();
    await rm(credPath, { force: true });
    await rm(idPath, { force: true });
  }
});
