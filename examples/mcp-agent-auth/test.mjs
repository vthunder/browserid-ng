// End-to-end test: real MCP client ↔ real MCP server (stdio), with a mock
// /verify-access so no network or human consent is needed. Proves the
// auth-gating — scope enforcement, delegation attribution, fail-closed — over
// the actual protocol.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { startMockVerifier } from "./mock-verifier.mjs";

const AUDIENCE = "https://notes.mcp.example";

async function withClient(verifierUrl, fn) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [new URL("./server.mjs", import.meta.url).pathname],
    env: { ...process.env, SERVER_AUDIENCE: AUDIENCE, VERIFIER_URL: verifierUrl },
  });
  const client = new Client({ name: "test", version: "0.1.0" });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

const call = (client, name, args) => client.callTool({ name, arguments: args });
const textOf = (res) => (res.content || []).map((c) => c.text).join("\n");

test("MCP agent auth: scope enforcement over the real protocol", async () => {
  const mock = await startMockVerifier(AUDIENCE);
  try {
    await withClient(mock.url, async (client) => {
      // tools are discoverable
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name).sort(), ["list_notes", "post_note"]);

      // agent with post scope → allowed; attributed to alice, actor surfaced
      const posted = await call(client, "post_note", { presentation: "good-post", text: "hello" });
      assert.equal(posted.isError, undefined);
      assert.match(textOf(posted), /by alice@acme\.com \(via agent alice\+researcher@acme\.com\)/);

      // read-only agent → post denied with a scope reason
      const denied = await call(client, "post_note", { presentation: "good-read-only", text: "nope" });
      assert.equal(denied.isError, true);
      assert.match(textOf(denied), /not authorized/);
      assert.match(textOf(denied), /post/);

      // read-only agent → list allowed, sees the earlier post with provenance
      const listed = await call(client, "list_notes", { presentation: "good-read-only" });
      assert.equal(listed.isError, undefined);
      assert.match(textOf(listed), /\[alice@acme\.com via alice\+researcher@acme\.com\] hello/);

      // a presentation without the notes scopes → rejected by scope, not
      // by any (unverifiable) human/agent distinction
      const loginOnly = await call(client, "post_note", { presentation: "login-only", text: "x" });
      assert.equal(loginOnly.isError, true);
      assert.match(textOf(loginOnly), /not authorized/);

      // garbage presentation → fail closed
      const bad = await call(client, "list_notes", { presentation: "nonsense" });
      assert.equal(bad.isError, true);
      assert.match(textOf(bad), /authentication failed/);
    });
  } finally {
    mock.close();
  }
});
