// Minimal MCP client that presents a browserid-ng access presentation to the
// browserid-notes server and calls a tool.
//
// In real use the presentation comes from the agent SDK/CLI (device-cert
// model: mint an access cert with your device cert, attach your stored
// warrant + config cert), then:
//   node client.mjs --presentation "<that string>" post "hello from my agent"
//   node client.mjs --presentation "<that string>" list
//
// Env passes through to the spawned server (SERVER_AUDIENCE, VERIFIER_URL, ...).

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

function arg(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const presentation = arg("--presentation") || process.env.PRESENTATION;
if (!presentation) {
  console.error('missing --presentation (or PRESENTATION env). Get one from the agent SDK.');
  process.exit(2);
}
const rest = process.argv.slice(2).filter((a) => a !== "--presentation" && a !== presentation);
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
    ? { name: "post_note", arguments: { presentation, text } }
    : { name: "list_notes", arguments: { presentation } };

const res = await client.callTool(call);
const out = (res.content || []).map((c) => c.text).join("\n");
console.log(res.isError ? `DENIED: ${out}` : out);

await client.close();
process.exit(res.isError ? 1 : 0);
