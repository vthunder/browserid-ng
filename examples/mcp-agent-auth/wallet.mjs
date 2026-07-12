// The agent's "wallet" — an MCP server built on @browserid/agent that lets an
// agent obtain and present a browserid-ng identity entirely through MCP tool
// calls. No shell, no Rust: this runs the whole provision → consent → assertion
// flow in-process, so the demo works even in pure-MCP clients (Claude Desktop).
//
// Tools:
//   identity()                       → who this agent acts as (guides credential setup)
//   authorize(audience, scopes?)     → returns an APPROVE_URL for the human (or READY)
//   get_assertion(audience)          → waits for approval, returns the ASSERTION
//
// Config (env): AGENT_CREDENTIAL, AGENT_IDENTITY (file paths), AGENT_NAME
// (reserved name for multi-name credentials), BROWSERID_BROKER override.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Agent, NeedCredentialError, AmbiguousNameError, NoWarrantError, WarrantDeniedError, WarrantExpiredError } from "@browserid/agent";
import { z } from "zod";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CREDENTIAL = process.env.AGENT_CREDENTIAL || join(HERE, "agent-credential.json");
const IDENTITY = process.env.AGENT_IDENTITY || join(HERE, "agent.identity.json");
const DEFAULT_SCOPES = ["post", "read"];

const text = (t) => ({ content: [{ type: "text", text: t }] });
const pending = new Map(); // audience -> Promise<void> (approval in flight)

let agentPromise = null;
function loadAgent() {
  if (!agentPromise) {
    agentPromise = Agent.open(CREDENTIAL, IDENTITY, { name: process.env.AGENT_NAME }).catch((e) => {
      agentPromise = null; // let a later call retry (e.g. after the human adds the credential)
      throw e;
    });
  }
  return agentPromise;
}

// Translate the SDK's typed errors into agent-actionable text.
function explain(e) {
  if (e instanceof NeedCredentialError)
    return text(
      "NEED_CREDENTIAL: no agent identity yet. Ask the human to create an agent key at " +
        "https://browserid.me/agents and save the downloaded file as:\n  " + CREDENTIAL
    );
  if (e instanceof AmbiguousNameError)
    return text(
      "AMBIGUOUS_NAME: this credential reserves several names (" + e.names.join(", ") +
        "). Ask the human which to use, then restart this server with AGENT_NAME set."
    );
  if (e instanceof WarrantDeniedError) return text("DENIED: the human declined this request.");
  if (e instanceof WarrantExpiredError) return text("EXPIRED: the request expired before approval; call authorize again.");
  return null;
}

const server = new McpServer({ name: "browserid-wallet", version: "0.1.0" });

server.registerTool(
  "identity",
  { title: "Agent identity", description: "Who this agent acts as (and how to set up a credential if missing)." },
  async () => {
    try {
      const agent = await loadAgent();
      const id = agent.identity();
      return text(
        `Acting as ${agent.email}.` +
          (id.names.length ? ` Reserved names: ${id.names.join(", ")}.` : "") +
          (id.patterns.length ? ` Patterns: ${id.patterns.join(", ")}.` : "")
      );
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "authorize",
  {
    title: "Request access",
    description:
      "Ask the human to grant this agent access to an audience with scopes. Returns an APPROVE_URL to show them (or READY if already authorized).",
    inputSchema: {
      audience: z.string().describe("the RP/server audience, e.g. https://notes.mcp.example"),
      scopes: z.array(z.string()).optional().describe('scopes to request (default ["post","read"])'),
    },
  },
  async ({ audience, scopes }) => {
    try {
      const agent = await loadAgent();
      const { approveUrl, approved } = await agent.requestWarrant(audience, scopes?.length ? scopes : DEFAULT_SCOPES);
      if (!approveUrl) return text(`READY — already authorized for ${audience}. Call get_assertion.`);
      // Poll in the background; persist on approval. get_assertion awaits this.
      pending.set(audience, approved.then(() => agent.save(IDENTITY)));
      return text(`APPROVE_URL: ${approveUrl}\nShow this to the human; when they approve, call get_assertion for ${audience}.`);
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "get_assertion",
  {
    title: "Get an assertion",
    description:
      "Return a browserid-ng assertion for the audience, waiting for the human to approve if needed. Present the ASSERTION value to the target server.",
    inputSchema: { audience: z.string().describe("the audience authorized via `authorize`") },
  },
  async ({ audience }) => {
    try {
      const agent = await loadAgent();
      const inFlight = pending.get(audience);
      if (inFlight) {
        const timedOut = Symbol("t");
        const race = await Promise.race([inFlight.then(() => null), new Promise((r) => setTimeout(() => r(timedOut), 150000))]);
        if (race === timedOut) return text("PENDING — not approved yet. Ask the human to approve the link, then call get_assertion again.");
        pending.delete(audience);
      }
      const assertion = await agent.assertionFor(audience);
      await agent.save(IDENTITY);
      return text(`ASSERTION: ${assertion}`);
    } catch (e) {
      if (e instanceof NoWarrantError) return text(`PENDING — no warrant for ${audience} yet. Call authorize first.`);
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

await server.connect(new StdioServerTransport());
console.error(`browserid-wallet MCP server ready — credential ${CREDENTIAL}`);
