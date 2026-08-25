// Reference MCP server that authenticates its callers with browserid-ng
// (device-cert model).
//
// The pattern: an agent (an AI acting for a human) presents an access
// presentation (`access_cert~assertion~warrant~config_cert`). The server
// verifies it — learning the agent's identity and the SCOPES the human's
// warrant grants for THIS server — and gates each tool on the right scope.
// The human stays in control: they approved a warrant naming this server and
// these scopes, and can revoke it anytime.
//
// Here the presentation is passed as a tool argument so the verification is
// visible in one file. A production server would hoist auth to the transport /
// MCP OAuth layer and verify once per session; the check itself — verify →
// scopes → enforce — is identical.
//
// Config (env):
//   SERVER_AUDIENCE     the audience the agent's presentation must target
//                       (default "https://notes.mcp.example")
//   VERIFIER_URL        hosted /verify URL (default https://browserid.me/verify)
//   ACCEPTED_FALLBACKS  optional comma-separated fallback-IdP issuer domains

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createVerifier } from "@browserid-ng/verify";
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
 * Verify the caller's presentation and require a scope. Returns the verified
 * identity, or throws an Error whose message is safe to surface to the caller.
 * This is the whole security boundary — every tool goes through it.
 */
async function authorize(presentation, requiredScope) {
  const r = await verifier.verify(presentation, SERVER_AUDIENCE);
  if (!r.ok) throw new Error(`authentication failed: ${r.reason}`);
  // `r.email` is the ATTRIBUTED identity (the human the warrant grantor
  // vouches for); `r.grantee` is the actor of record, differing from `email`
  // when a named agent acted on the human's behalf. Whether the caller is
  // software is not verifiable (an "as-you" agent is indistinguishable from
  // its owner by design) — authorization rests on the warrant's SCOPES, which
  // the human approved for exactly this audience.
  if (!r.scopes.includes(requiredScope)) {
    throw new Error(
      `not authorized: the human did not grant "${requiredScope}" here ` +
        `(granted: ${r.scopes.join(", ") || "none"})`
    );
  }
  return r; // { ok, email, grantee, issuer, scopes }
}

const server = new McpServer({ name: "browserid-notes", version: "0.1.0" });

server.registerTool(
  "post_note",
  {
    title: "Post a note",
    description:
      "Append a note. Requires an agent presentation carrying the 'post' scope for this server.",
    inputSchema: {
      presentation: z.string().describe("browserid-ng access presentation (access_cert~assertion~warrant~config_cert)"),
      text: z.string().describe("the note body"),
    },
  },
  async ({ presentation, text }) => {
    let id;
    try {
      id = await authorize(presentation, "post");
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: e.message }] };
    }
    const note = { text, by: id.email, via: id.grantee, at: notes.length };
    notes.push(note);
    const actor = note.via !== note.by ? ` (via agent ${note.via})` : "";
    return {
      content: [
        {
          type: "text",
          text:
            `posted (#${note.at}) by ${note.by}${actor}. ` +
            `every action here is attributable to that identity.`,
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
      "Read all notes. Requires an agent presentation carrying the 'read' scope for this server.",
    inputSchema: {
      presentation: z.string().describe("browserid-ng access presentation"),
    },
  },
  async ({ presentation }) => {
    let id;
    try {
      id = await authorize(presentation, "read");
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: e.message }] };
    }
    const body = notes.length
      ? notes
          .map((n) => `#${n.at} [${n.by}${n.via !== n.by ? ` via ${n.via}` : ""}] ${n.text}`)
          .join("\n")
      : "(no notes yet)";
    return { content: [{ type: "text", text: body }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
// stderr so it doesn't corrupt the stdio JSON-RPC stream
console.error(`browserid-notes MCP server ready — audience ${SERVER_AUDIENCE}`);
