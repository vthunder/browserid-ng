#!/usr/bin/env node
// A minimal REAL-filesystem stdio MCP server, used as the wrapped child under
// test. It reads/lists an actual directory (argv[2]) so the gate proxy returns
// genuine filesystem results — the same shape the official
// @modelcontextprotocol/server-filesystem produces, without a network install.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const ROOT = resolve(process.argv[2] || process.cwd());
const within = (p) => {
  const full = resolve(ROOT, p);
  if (full !== ROOT && !full.startsWith(ROOT + "/")) throw new Error("path escapes the served root");
  return full;
};

const server = new Server({ name: "fs-child", version: "0.0.1" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "read_text_file",
      description: "Read a UTF-8 text file under the served root.",
      inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
    },
    {
      name: "list_directory",
      description: "List entries of a directory under the served root.",
      inputSchema: { type: "object", properties: { path: { type: "string" } }, properties_note: "path optional" },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  try {
    if (name === "read_text_file") {
      const text = readFileSync(within(args.path), "utf8");
      return { content: [{ type: "text", text }] };
    }
    if (name === "list_directory") {
      const dir = args.path ? within(args.path) : ROOT;
      const entries = readdirSync(dir, { withFileTypes: true })
        .map((e) => `${e.isDirectory() ? "[DIR] " : "[FILE] "}${e.name}`)
        .join("\n");
      return { content: [{ type: "text", text: entries || "(empty)" }] };
    }
    return { isError: true, content: [{ type: "text", text: `unknown tool ${name}` }] };
  } catch (e) {
    return { isError: true, content: [{ type: "text", text: `ERROR: ${e.message}` }] };
  }
});

await server.connect(new StdioServerTransport());
console.error(`fs-child serving ${ROOT}`);
