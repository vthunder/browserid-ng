// Reference MCP server that authenticates its callers with browserid-ng.
//
// The pattern: an agent (an AI acting for a human) presents a warrant-backed
// assertion. The server verifies it — learning the agent's identity, the HUMAN
// it acts for, and the SCOPES that human signed for THIS server — and gates each
// tool on the right scope. The human stays in control: they approved a warrant
// naming this server and these scopes, and can revoke it anytime.
//
// Here the assertion is passed as a tool argument so the verification is visible
// in one file. A production server would hoist auth to the transport / MCP OAuth
// layer and verify once per session; the check itself — verify → agent+parent+
// scopes → enforce — is identical.
//
// Config (env):
//   SERVER_AUDIENCE     the audience the agent's assertion must target
//                       (default "https://notes.mcp.example")
//   VERIFIER_URL        hosted /verify URL (default https://browserid.me/verify)
//   ACCEPTED_FALLBACKS  optional comma-separated fallback-IdP issuer domains

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createVerifier } from "@browserid/verify";
import { z } from "zod";

const SERVER_AUDIENCE = process.env.SERVER_AUDIENCE || "https://notes.mcp.example";
const verifier = createVerifier({
  verifierUrl: process.env.VERIFIER_URL || undefined,
  acceptedFallbacks: process.env.ACCEPTED_FALLBACKS
    ? process.env.ACCEPTED_FALLBACKS.split(",").map((s) => s.trim())
    : undefined,
});

// A trivial resource the tools act on, so scope enforcement is observable.
const notes = [];

/**
 * Verify the caller's assertion and require a scope. Returns the verified
 * identity, or throws an Error whose message is safe to surface to the caller.
 * This is the whole security boundary — every tool goes through it.
 */
async function authorize(assertion, requiredScope) {
  const r = await verifier.verify(assertion, SERVER_AUDIENCE, { allowAgent: true });
  if (!r.ok) throw new Error(`authentication failed: ${r.reason}`);
  if (!r.agent) throw new Error("this server is for agents acting for a human; no warrant present");
  if (!r.agent.scopes.includes(requiredScope)) {
    throw new Error(
      `not authorized: your principal (${r.agent.parent}) did not grant "${requiredScope}" here ` +
        `(granted: ${r.agent.scopes.join(", ") || "none"})`
    );
  }
  return r; // { ok, email, issuer, agent: { parent, scopes } }
}

const server = new McpServer({ name: "browserid-notes", version: "0.1.0" });

server.registerTool(
  "post_note",
  {
    title: "Post a note",
    description:
      "Append a note. Requires an agent assertion carrying the 'post' scope for this server.",
    inputSchema: {
      assertion: z.string().describe("browserid-ng backed assertion (certificate~assertion~warrant)"),
      text: z.string().describe("the note body"),
    },
  },
  async ({ assertion, text }) => {
    let id;
    try {
      id = await authorize(assertion, "post");
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: e.message }] };
    }
    const note = { text, by: id.email, for: id.agent.parent, at: notes.length };
    notes.push(note);
    return {
      content: [
        {
          type: "text",
          text:
            `posted (#${note.at}) by agent ${note.by}, acting for ${note.for}. ` +
            `every action here is attributable to ${note.for}.`,
        },
      ],
    };
  }
);

server.registerTool(
  "list_notes",
  {
    title: "List notes",
    description:
      "Read all notes. Requires an agent assertion carrying the 'read' scope for this server.",
    inputSchema: {
      assertion: z.string().describe("browserid-ng backed assertion"),
    },
  },
  async ({ assertion }) => {
    let id;
    try {
      id = await authorize(assertion, "read");
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: e.message }] };
    }
    const body = notes.length
      ? notes.map((n) => `#${n.at} [${n.for}] ${n.text}`).join("\n")
      : "(no notes yet)";
    return { content: [{ type: "text", text: body }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
// stderr so it doesn't corrupt the stdio JSON-RPC stream
console.error(`browserid-notes MCP server ready — audience ${SERVER_AUDIENCE}`);
