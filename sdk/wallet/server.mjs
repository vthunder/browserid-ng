#!/usr/bin/env node
// @browserid-ng/wallet — an MCP server that gives an agent a browserid-ng identity.
//
// Run it straight from npm, no checkout:
//   npx -y @browserid-ng/wallet
// and add it to your MCP client (Claude Code / Cursor / Claude Desktop):
//   { "mcpServers": { "browserid": { "command": "npx", "args": ["-y", "@browserid-ng/wallet"] } } }
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
} from "@browserid-ng/agent";
import { z } from "zod";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";

const BROKER = (process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/$/, "");
const HOME = process.env.BROWSERID_HOME || join(homedir(), ".browserid");
const GUESTBOOK_URL = process.env.GUESTBOOK_URL || `${BROKER}/guestbook`;
const CREDENTIAL = join(HOME, "agent-credential.json");
const IDENTITY = join(HOME, "agent.identity.json");
// The home dir + files hold private keys — keep them owner-only (700 / 600).
mkdirSync(HOME, { recursive: true, mode: 0o700 });
try { chmodSync(HOME, 0o700); } catch {}

/** Write JSON to a private (0600) file. */
function writePrivate(path, obj) {
  writeFileSync(path, JSON.stringify(obj, null, 2), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch {}
}

const text = (t) => ({ content: [{ type: "text", text: t }] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// How long a tool call waits for a pending approval before returning "still
// waiting" (so the human can approve while the agent's call is in flight). Kept
// under the MCP client's default 60s request timeout; if the human is slower,
// the agent just calls again (the background poll persists across calls).
const APPROVAL_WAIT_MS = 45000;

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
      `STILL WAITING for the human to approve — this is normal. Keep this link visible and call your ` +
        `tool AGAIN to keep waiting (each call polls ~45s):\n${e.url}`
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
    description: "Pair a new browserid-ng identity with the human (they approve a link; nothing to download). Suggest a SINGLE short handle unless the human asked for more.",
    inputSchema: {
      handles: z.array(z.string()).optional().describe("Prefer ONE short handle to suggest, e.g. [\"claude\"] (the human confirms/edits). Only pass several if the human explicitly wants multiple identities."),
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
          writePrivate(CREDENTIAL, agent.credential.toJSON());
          await agent.save(IDENTITY); // 0600, array format (sdk/agent)
          readyAgent = agent;
        })
        .catch((e) => { provisionError = e; })
        .finally(() => { pendingProvisionUrl = null; });
      return text(
        `APPROVE_URL: ${pairing.verificationUriComplete}\n` +
          `(or go to ${pairing.verificationUri} and enter code ${pairing.userCode})\n` +
          `Agent key fingerprint: ${pairing.fingerprint}\n\n` +
          `⚠ Show the human this APPROVE_URL and ask them to open it and approve. ` +
          `Then IMMEDIATELY call your next tool (e.g. sign_guestbook, or identity) — it waits for their ` +
          `approval and continues automatically. Do NOT wait for the human to tell you; just call the next tool.`
      );
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "forget",
  {
    title: "Forget this identity",
    description:
      "Delete this agent's local identity (credential + cert) so a fresh one can be provisioned. Does NOT revoke it server-side — that's done at browserid.me/account.",
  },
  async () => {
    readyAgent = null;
    provisionError = null;
    pendingProvisionUrl = null;
    pendingWarrants.clear();
    let removed = 0;
    for (const p of [CREDENTIAL, IDENTITY]) {
      try { rmSync(p); removed++; } catch {}
    }
    return text(
      `Forgot the local identity (${removed} file(s) removed). Call provision to set up a new one. ` +
        `(The old identity still exists at browserid.me/account until revoked there.)`
    );
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
          `Then IMMEDIATELY call get_assertion — it waits for their approval and continues. Do NOT wait for the human to tell you.`
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
      "Sign the public browserid.me guestbook as yourself, acting for the human. If not yet authorized, returns an APPROVE_URL to show them; call again after they approve. Write a SHORT, FUN, ORIGINAL message in your own voice — a quip, an observation, a tiny haiku, whatever feels like you. Avoid generic 'Hello world' / 'first post' — the wall is more fun when every agent sounds different.",
    inputSchema: { message: z.string().describe("your own short, original, fun message (max ~280 chars) — surprise us, don't just say hello") },
  },
  async ({ message }) => {
    try {
      const agent = await loadAgent();
      const w = await ensureWarrant(agent, GUESTBOOK_URL, ["guestbook-sign"]);
      if (!w.ready)
        return text(
          `APPROVE_URL: ${w.approveUrl}\n⚠ Show the human this link and ask them to approve you signing ` +
            `the guestbook. Then IMMEDIATELY call sign_guestbook again with the same message — it waits for ` +
            `their approval and continues. Do NOT wait for the human to tell you.`
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
