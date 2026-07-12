// The agent's "wallet" — an MCP server built on @browserid-ng/agent that lets an
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
import { Agent, NeedCredentialError, AmbiguousNameError, NoWarrantError, WarrantDeniedError, WarrantExpiredError } from "@browserid-ng/agent";
import { z } from "zod";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { existsSync, readdirSync, statSync } from "node:fs";
import { writeFile } from "node:fs/promises";

const HERE = dirname(fileURLToPath(import.meta.url));
const IDENTITY = process.env.AGENT_IDENTITY || join(HERE, "agent.identity.json");
const BROKER = process.env.BROWSERID_BROKER || "https://browserid.me";
const DEFAULT_SCOPES = ["post", "read"];

// Find the agent credential. Precedence: an explicit AGENT_CREDENTIAL; then a
// credential placed in this directory; then the newest `agent-credential*.json`
// the human just downloaded (Downloads / Desktop / home). Returns { path } or
// { path: null, searched } so the caller can tell the human where to look.
function resolveCredential() {
  if (process.env.AGENT_CREDENTIAL) return { path: process.env.AGENT_CREDENTIAL, source: "AGENT_CREDENTIAL" };
  const dirs = [HERE, join(homedir(), "Downloads"), join(homedir(), "Desktop"), homedir()];
  const matches = [];
  for (const dir of dirs) {
    let names = [];
    try { names = readdirSync(dir); } catch { continue; }
    for (const n of names) {
      if (/^agent-credential.*\.json$/.test(n) || /\.agent-credential\.json$/.test(n)) {
        const p = join(dir, n);
        try { matches.push({ path: p, mtime: statSync(p).mtimeMs }); } catch {}
      }
    }
  }
  if (!matches.length) return { path: null, searched: dirs };
  matches.sort((a, b) => b.mtime - a.mtime); // newest first (just-downloaded)
  return { path: matches[0].path, source: "auto-discovered", others: matches.slice(1).map((m) => m.path) };
}

const text = (t) => ({ content: [{ type: "text", text: t }] });
const pending = new Map(); // audience -> Promise<void> (approval in flight)

let agentPromise = null;
let provisioning = null; // a paired-provisioning bootstrap in flight
let credSource = null; // where the credential was found, for reporting
function loadAgent() {
  if (agentPromise) return agentPromise;
  if (provisioning) return provisioning; // waiting on a pairing to complete
  if (!agentPromise) {
    const cred = resolveCredential();
    if (!cred.path) {
      const e = new NeedCredentialError(join(HERE, "agent-credential.json"));
      e.searched = cred.searched;
      return Promise.reject(e);
    }
    credSource = cred;
    agentPromise = Agent.open(cred.path, IDENTITY, { name: process.env.AGENT_NAME }).catch((e) => {
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
      "NEED_CREDENTIAL: no agent identity yet. Call the `provision` tool to pair one — " +
        "the human approves a link and the identity is picked up automatically, no file needed. " +
        "(Or, advanced: they can download a credential from https://browserid.me/agents and " +
        "leave it in Downloads; I search: " + (e.searched || []).join(", ") + ".)"
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
  "provision",
  {
    title: "Provision an identity (pairing)",
    description:
      "Start pairing a new browserid-ng agent identity with the human. Returns an approval URL to show them; once they approve, the identity is picked up automatically (no file to download). Use this when identity says NEED_CREDENTIAL.",
    inputSchema: {
      handles: z.array(z.string()).optional().describe("handles to suggest (the human confirms/edits)"),
      label: z.string().optional().describe("a label shown to the human, e.g. what this agent is"),
    },
  },
  async ({ handles, label }) => {
    try {
      const pairing = await Agent.bootstrap({
        broker: BROKER,
        requestedHandles: handles?.length ? { names: handles } : undefined,
        label: label || "MCP agent",
      });
      // On approval: persist the credential (generated here, never transmitted)
      // + identity locally, and adopt it as the wallet's agent.
      provisioning = pairing.ready.then(async (agent) => {
        const credPath = join(HERE, `agent-credential-${agent.email.split("@")[0]}.json`);
        await writeFile(credPath, JSON.stringify(agent.credential.toJSON(), null, 2));
        await agent.save(IDENTITY);
        agentPromise = Promise.resolve(agent);
        provisioning = null;
        return agent;
      });
      provisioning.catch(() => { provisioning = null; }); // surfaced on the next tool call
      return text(
        `APPROVE_URL: ${pairing.verificationUriComplete}\n` +
          `(or go to ${pairing.verificationUri} and enter code ${pairing.userCode})\n` +
          `Agent key fingerprint: ${pairing.fingerprint}\n` +
          `Show the human this link. Once they approve, I'll have my identity — then call identity or authorize.`
      );
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "identity",
  { title: "Agent identity", description: "Who this agent acts as (and how to set up a credential if missing)." },
  async () => {
    try {
      const agent = await loadAgent();
      const id = agent.identity();
      const from = credSource?.source === "auto-discovered" ? ` (credential: ${credSource.path})` : "";
      return text(
        `Acting as ${agent.email}.` +
          (id.names.length ? ` Reserved names: ${id.names.join(", ")}.` : "") +
          (id.patterns.length ? ` Patterns: ${id.patterns.join(", ")}.` : "") +
          from
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
console.error("browserid-wallet MCP server ready");
