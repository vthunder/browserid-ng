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
  WarrantDeniedError, WarrantExpiredError, RequestError,
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
// How long a tool call waits for a pending approval before returning "still
// pending" (so the human can approve while the agent's call is in flight). If a
// client cuts the call short, a retry still works — the background poll persists.
const APPROVAL_WAIT_MS = 90000;

// A provisioning is a two-step handshake (start → human approves → pickup). The
// tools must NEVER block waiting for the human — they return the approve URL and
// the agent shows it. Approval is picked up in the BACKGROUND; the next tool
// call finds the identity ready.
let readyAgent = null; // the resolved Agent, once available
let pendingProvisionUrl = null; // set while a provision awaits approval
let provisionError = null; // a failed background provision, surfaced on next call

/** Raised (non-blocking) when a provision is started but not yet approved. */
class PendingProvision extends Error {
  constructor(url) {
    super("provisioning pending");
    this.url = url;
  }
}

const pendingWarrants = new Map(); // audience -> { approveUrl } while awaiting approval

// Never blocks: returns the ready agent, loads one from disk, or signals pending.
async function loadAgent() {
  if (readyAgent) return readyAgent;
  const throwProvErr = () => { const e = provisionError; provisionError = null; throw e; };
  if (provisionError) throwProvErr();
  if (pendingProvisionUrl) {
    // Wait (bounded) for the human to approve, so the agent auto-proceeds.
    const deadline = Date.now() + APPROVAL_WAIT_MS;
    while (pendingProvisionUrl && Date.now() < deadline) {
      await sleep(1500);
      if (readyAgent) return readyAgent;
      if (provisionError) throwProvErr();
    }
    if (readyAgent) return readyAgent;
    if (provisionError) throwProvErr();
    if (pendingProvisionUrl) throw new PendingProvision(pendingProvisionUrl);
  }
  readyAgent = await Agent.open(CREDENTIAL, IDENTITY, { name: process.env.AGENT_NAME });
  return readyAgent;
}

function explain(e) {
  if (e instanceof PendingProvision)
    return text(
      `PENDING — the human hasn't approved provisioning yet. Show them this link and wait for them to approve, then try again:\n${e.url}`
    );
  if (e instanceof RequestError)
    return text(
      `PROVISIONING FAILED: ${e.reason}. ` +
        (/quota/i.test(e.reason) ? "The human has too many agent identities — they can revoke old ones at https://browserid.me/account. " : "") +
        "Fix that, then call provision again."
    );
  if (e instanceof NeedCredentialError)
    return text("NEED_CREDENTIAL: no identity yet. Call the `provision` tool to pair one — the human approves a link, nothing to download.");
  if (e instanceof AmbiguousNameError)
    return text(
      `AMBIGUOUS_NAME: the credential reserves several names [${e.names.join(", ")}]. ` +
        `Call provision again with a SINGLE handle, e.g. handles: ["${e.names[0]}"].`
    );
  if (e instanceof WarrantDeniedError) return text("DENIED: the human declined.");
  if (e instanceof WarrantExpiredError) return text("EXPIRED: the request expired; try again.");
  return null;
}

// Non-blocking. { ready } if held; { approveUrl } to show the human; { pending }
// if approval is still in flight. Approval is polled in the background — once the
// human approves, `warrantCovers` becomes true and a retry proceeds.
async function ensureWarrant(agent, audience, scopes) {
  if (agent.warrantCovers(audience, scopes)) return { ready: true };
  const inflight = pendingWarrants.get(audience);
  if (inflight) {
    // Wait (bounded) for the human to approve the warrant, so we auto-proceed.
    const deadline = Date.now() + APPROVAL_WAIT_MS;
    while (Date.now() < deadline) {
      await sleep(1500);
      if (agent.warrantCovers(audience, scopes)) return { ready: true };
      if (!pendingWarrants.has(audience)) break; // settled (approved/denied/expired)
    }
    if (agent.warrantCovers(audience, scopes)) return { ready: true };
    return { pending: true, approveUrl: inflight.approveUrl };
  }
  const { approveUrl, approved } = await agent.requestWarrant(audience, scopes);
  if (!approveUrl) return { ready: true };
  pendingWarrants.set(audience, { approveUrl });
  approved.then(() => agent.save(IDENTITY)).catch(() => {}).finally(() => pendingWarrants.delete(audience));
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
        name: process.env.AGENT_NAME || handles?.[0], // mint as this handle — no env-var dance
      });
      pendingProvisionUrl = pairing.verificationUriComplete;
      // Pick up the identity in the BACKGROUND when the human approves.
      provisionError = null;
      pairing.ready
        .then(async (agent) => {
          writeFileSync(CREDENTIAL, JSON.stringify(agent.credential.toJSON(), null, 2));
          await agent.save(IDENTITY);
          readyAgent = agent;
        })
        .catch((e) => { provisionError = e; })
        .finally(() => { pendingProvisionUrl = null; });
      return text(
        `APPROVE_URL: ${pairing.verificationUriComplete}\n` +
          `(or go to ${pairing.verificationUri} and enter code ${pairing.userCode})\n` +
          `Agent key fingerprint: ${pairing.fingerprint}\n\n` +
          `⚠ Show the human this APPROVE_URL and ask them to open it and approve. ` +
          `Do NOT call other tools until they tell you they've approved — then call identity to confirm.`
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
      if (r.ready) return text(`READY — authorized for ${audience}. Call get_assertion.`);
      return text(
        `APPROVE_URL: ${r.approveUrl}\n⚠ Show the human this link and ask them to approve. ` +
          `Wait for them to confirm, then call get_assertion (or authorize again to check).`
      );
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
      if (!w.ready)
        return text(
          `APPROVE_URL: ${w.approveUrl}\n⚠ Show the human this link and ask them to approve you signing ` +
            `the guestbook. Wait for them to confirm, then call sign_guestbook again with the same message.`
        );

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
