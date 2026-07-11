// Minimal MCP client that presents a browserid-ng agent assertion to the
// browserid-notes server and calls a tool.
//
// In real use the assertion comes from the agent CLI:
//   cargo run -p browserid-agent --example agent_cli -- \
//     agent-credential.json assert https://notes.mcp.example
// then:
//   node client.mjs --assertion "<that string>" post "hello from my agent"
//   node client.mjs --assertion "<that string>" list
//
// Env passes through to the spawned server (SERVER_AUDIENCE, VERIFIER_URL, ...).

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

function arg(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const assertion = arg("--assertion") || process.env.ASSERTION;
if (!assertion) {
  console.error('missing --assertion (or ASSERTION env). Get one from the agent CLI "assert" command.');
  process.exit(2);
}
const rest = process.argv.slice(2).filter((a) => a !== "--assertion" && a !== assertion);
const cmd = rest[0] || "list";
const text = rest.slice(1).join(" ") || "hello from my agent";

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [new URL("./server.mjs", import.meta.url).pathname],
  env: process.env,
});
const client = new Client({ name: "browserid-notes-client", version: "0.1.0" });
await client.connect(transport);

const call =
  cmd === "post"
    ? { name: "post_note", arguments: { assertion, text } }
    : { name: "list_notes", arguments: { assertion } };

const res = await client.callTool(call);
const out = (res.content || []).map((c) => c.text).join("\n");
console.log(res.isError ? `DENIED: ${out}` : out);

await client.close();
process.exit(res.isError ? 1 : 0);
