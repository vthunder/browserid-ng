#!/usr/bin/env node
// @browserid/wallet — an MCP server that gives an agent a browserid-ng identity.
//
// Run it straight from npm, no checkout:
//   npx -y @browserid/wallet
// and add it to your MCP client (Claude Code / Cursor / Claude Desktop):
//   { "mcpServers": { "browserid": { "command": "npx", "args": ["-y", "@browserid/wallet"] } } }
//
// Tools:
//   identity                       who this agent acts as (or how to provision)
//   provision(handles?, label?)    pair a new identity — human approves a link
//   authorize(audience, scopes)    request a warrant for an audience
//   get_assertion(audience)        a backed assertion to present to that audience
//   sign_guestbook(message)        the demo: sign the public browserid.me guestbook
//   read_guestbook()               read recent guestbook entries
//
// The identity (a non-transmittable provisioning key + delegation + cert) lives
// in ~/.browserid. Config: BROWSERID_BROKER (default https://browserid.me),
// BROWSERID_HOME, GUESTBOOK_URL.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  Agent, NeedCredentialError, AmbiguousNameError, NoWarrantError,
  WarrantDeniedError, WarrantExpiredError,
} from "@browserid/agent";
import { z } from "zod";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";

const BROKER = (process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/$/, "");
const HOME = process.env.BROWSERID_HOME || join(homedir(), ".browserid");
const GUESTBOOK_URL = process.env.GUESTBOOK_URL || `${BROKER}/guestbook`;
const CREDENTIAL = join(HOME, "agent-credential.json");
const IDENTITY = join(HOME, "agent.identity.json");
mkdirSync(HOME, { recursive: true });

const text = (t) => ({ content: [{ type: "text", text: t }] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let agentPromise = null;
let provisioning = null;
const pendingWarrants = new Map(); // audience -> Promise (approval in flight)

function loadAgent() {
  if (agentPromise) return agentPromise;
  if (provisioning) return provisioning;
  agentPromise = Agent.open(CREDENTIAL, IDENTITY, { name: process.env.AGENT_NAME }).catch((e) => {
    agentPromise = null;
    throw e;
  });
  return agentPromise;
}

function explain(e) {
  if (e instanceof NeedCredentialError)
    return text("NEED_CREDENTIAL: no identity yet. Call the `provision` tool to pair one — the human approves a link, nothing to download.");
  if (e instanceof AmbiguousNameError)
    return text(`AMBIGUOUS_NAME: pick one of [${e.names.join(", ")}] and restart with AGENT_NAME set.`);
  if (e instanceof WarrantDeniedError) return text("DENIED: the human declined.");
  if (e instanceof WarrantExpiredError) return text("EXPIRED: the request expired; try again.");
  return null;
}

// Ensure a warrant for `audience`+`scopes`: returns { ready } if held, or
// { approveUrl } (with the approval polling in the background) if not.
async function ensureWarrant(agent, audience, scopes) {
  if (agent.warrantCovers(audience, scopes)) return { ready: true };
  const inflight = pendingWarrants.get(audience);
  if (inflight) {
    const ok = await Promise.race([inflight.then(() => true), sleep(150000).then(() => false)]);
    if (!ok) return { pending: true };
    pendingWarrants.delete(audience);
    return { ready: true };
  }
  const { approveUrl, approved } = await agent.requestWarrant(audience, scopes);
  if (!approveUrl) return { ready: true };
  pendingWarrants.set(audience, approved.then(() => agent.save(IDENTITY)));
  return { approveUrl };
}

const server = new McpServer({ name: "browserid-wallet", version: "0.1.0" });

server.registerTool(
  "provision",
  {
    title: "Provision an identity",
    description: "Pair a new browserid-ng identity with the human (they approve a link; nothing to download).",
    inputSchema: {
      handles: z.array(z.string()).optional().describe("handles to suggest"),
      label: z.string().optional().describe("what this agent is, shown to the human"),
    },
  },
  async ({ handles, label }) => {
    try {
      const pairing = await Agent.bootstrap({
        broker: BROKER,
        requestedHandles: handles?.length ? { names: handles } : undefined,
        label: label || "agent",
      });
      provisioning = pairing.ready.then(async (agent) => {
        writeFileSync(CREDENTIAL, JSON.stringify(agent.credential.toJSON(), null, 2));
        await agent.save(IDENTITY);
        agentPromise = Promise.resolve(agent);
        provisioning = null;
        return agent;
      });
      provisioning.catch(() => { provisioning = null; });
      return text(
        `APPROVE_URL: ${pairing.verificationUriComplete}\n` +
          `(or go to ${pairing.verificationUri} and enter code ${pairing.userCode})\n` +
          `Agent key fingerprint: ${pairing.fingerprint}\n` +
          `Show the human this link. Once they approve, call identity to confirm.`
      );
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "identity",
  { title: "Agent identity", description: "Who this agent acts as (or how to provision if there's none)." },
  async () => {
    try {
      const agent = await loadAgent();
      const id = agent.identity();
      return text(
        `Acting as ${agent.email}.` +
          (id.names.length ? ` Reserved: ${id.names.join(", ")}.` : "") +
          (agent.warrantedAudiences().length ? ` Warrants for: ${agent.warrantedAudiences().join(", ")}.` : "")
      );
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "authorize",
  {
    title: "Request a warrant",
    description: "Ask the human to grant this agent an audience + scopes. Returns an APPROVE_URL (or READY).",
    inputSchema: { audience: z.string(), scopes: z.array(z.string()).optional() },
  },
  async ({ audience, scopes }) => {
    try {
      const agent = await loadAgent();
      const r = await ensureWarrant(agent, audience, scopes?.length ? scopes : ["use"]);
      if (r.approveUrl) return text(`APPROVE_URL: ${r.approveUrl}\nShow the human; then call get_assertion.`);
      if (r.pending) return text("PENDING — not approved yet; ask the human to approve, then retry.");
      return text(`READY — authorized for ${audience}.`);
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "get_assertion",
  {
    title: "Get an assertion",
    description: "A backed assertion to present to an audience (call authorize first if needed).",
    inputSchema: { audience: z.string() },
  },
  async ({ audience }) => {
    try {
      const agent = await loadAgent();
      const assertion = await agent.assertionFor(audience);
      await agent.save(IDENTITY);
      return text("ASSERTION: " + assertion);
    } catch (e) {
      if (e instanceof NoWarrantError) return text(`PENDING — no warrant for ${audience}. Call authorize first.`);
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "sign_guestbook",
  {
    title: "Sign the guestbook (demo)",
    description:
      "Sign the public browserid.me guestbook as yourself, acting for the human. If not yet authorized, returns an APPROVE_URL to show them; call again after they approve.",
    inputSchema: { message: z.string().describe("the message to post (max ~280 chars)") },
  },
  async ({ message }) => {
    try {
      const agent = await loadAgent();
      const w = await ensureWarrant(agent, GUESTBOOK_URL, ["sign"]);
      if (w.approveUrl)
        return text(
          `APPROVE_URL: ${w.approveUrl}\nAsk the human to approve you signing the guestbook, then call sign_guestbook again with the same message.`
        );
      if (w.pending) return text("PENDING — approve the link, then call sign_guestbook again.");

      const assertion = await agent.assertionFor(GUESTBOOK_URL);
      await agent.save(IDENTITY);
      const res = await fetch(GUESTBOOK_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ assertion, message }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || !body.success) return text("ERROR: " + (body.reason || `HTTP ${res.status}`));
      return text(`Signed! Live at ${body.url} — posted as ${body.agent}, acting for ${body.parent}.`);
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "read_guestbook",
  { title: "Read the guestbook (demo)", description: "Recent public guestbook entries." },
  async () => {
    try {
      const res = await fetch(`${GUESTBOOK_URL}/feed`);
      const { entries } = await res.json();
      if (!entries?.length) return text("The guestbook is empty.");
      return text(entries.slice(0, 10).map((e) => `“${e.message}” — ${e.agent}, for ${e.parent}`).join("\n"));
    } catch (e) {
      return text("ERROR: " + e.message);
    }
  }
);

await server.connect(new StdioServerTransport());
console.error(`browserid-wallet ready — identity in ${HOME}, broker ${BROKER}`);
