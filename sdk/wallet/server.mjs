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
  requestProvision, requestWarrants, DeviceAgent,
  AgentError, NoWarrantError, RequestError,
} from "@browserid-ng/agent";
import { readFileSync } from "node:fs";
import { z } from "zod";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";

const BROKER = (process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/$/, "");
const HOME = process.env.BROWSERID_HOME || join(homedir(), ".browserid");
const GUESTBOOK_URL = process.env.GUESTBOOK_URL || `${BROKER}/guestbook`;
// One file now: the device credential AND the warrants held against it.
const CREDENTIAL = join(HOME, "agent-credential.json");
const IDENTITY = join(HOME, "agent.identity.json"); // legacy; removed by `forget`
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

/** Raised (non-blocking) when an approval is started but not yet resolved. */
class PendingApproval extends Error {
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
    if (pendingProvisionUrl) throw new PendingApproval(pendingProvisionUrl);
  }
  readyAgent = openStored();
  return readyAgent;
}

/** Load the stored device credential + any saved warrants. */
function openStored() {
  let stored;
  try {
    stored = JSON.parse(readFileSync(CREDENTIAL, "utf8"));
  } catch {
    throw new NeedCredential();
  }
  const cred = stored.credential ?? stored;
  // A credential from the pre-device-model wallet ({secret_key, delegation, …})
  // can't act anymore — treat it as "no identity" so the agent is told to
  // re-provision, instead of DeviceAgent crashing on the missing fields.
  if (!cred || typeof cred !== "object" || !cred.device_key || !cred.agent_device_cert) {
    throw new NeedCredential();
  }
  const agent = new DeviceAgent(cred);
  for (const g of stored.grants ?? []) {
    try { agent.addGrant(g.grant); } catch {}
  }
  return agent;
}

/** Persist the credential and every held warrant, 0600. */
function saveAgent(agent) {
  writePrivate(CREDENTIAL, { credential: agent.credential, grants: agent.storedGrants() });
}

/** The decoded claims of a held grant ('warrant~config_cert'), or null. */
function grantClaims(pair) {
  try {
    return JSON.parse(Buffer.from(pair.split("~")[0].split(".")[1], "base64url").toString());
  } catch {
    return null;
  }
}

/** Locally forget the held warrant for `audience` (the registry copy and any
 *  server-side revocation are the HUMAN's levers — this only clears our copy
 *  so the next authorize/sign asks again). Returns true if one was dropped. */
function dropStoredGrant(audience) {
  let stored;
  try { stored = JSON.parse(readFileSync(CREDENTIAL, "utf8")); } catch { return false; }
  const before = (stored.grants ?? []).length;
  stored.grants = (stored.grants ?? []).filter((g) => g.audience !== audience);
  if (stored.grants.length === before) return false;
  writePrivate(CREDENTIAL, stored);
  readyAgent = null; // reload picks up the trimmed set
  return true;
}

/** No identity yet — the agent should call `provision`. */
class NeedCredential extends Error {
  constructor() { super("no identity yet"); }
}

function explain(e) {
  if (e instanceof PendingApproval)
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
  if (e instanceof NeedCredential)
    return text("NEED_CREDENTIAL: no identity yet. Call the `provision` tool to pair one — the human approves a link, nothing to download.");
  if (e instanceof AgentError && /refused/.test(e.message)) return text("DENIED: the human declined.");
  if (e instanceof AgentError && /expired/.test(e.message)) return text("EXPIRED: the request expired; try again.");
  return null;
}

// Non-blocking. { ready } if held; { approveUrl } to show the human; { pending }
// if approval is still in flight. Approval is polled in the BACKGROUND — once
// the human approves, the warrant lands and a retry proceeds.
async function ensureWarrant(agent, audience, scopes, message, grantor) {
  if (agent.warrantedAudiences().includes(audience)) return { ready: true };
  const inflight = pendingWarrants.get(audience);
  if (inflight) {
    const deadline = Date.now() + APPROVAL_WAIT_MS;
    while (Date.now() < deadline) {
      await sleep(1500);
      if (agent.warrantedAudiences().includes(audience)) return { ready: true };
      if (!pendingWarrants.has(audience)) break; // settled (approved/denied/expired)
    }
    if (agent.warrantedAudiences().includes(audience)) return { ready: true };
    return { pending: true, approveUrl: inflight.approveUrl };
  }
  const pending = await requestWarrants(BROKER, {
    deviceCert: agent.deviceCert,
    identity: agent.email,
    grants: [{ audience, scopes }],
    label: process.env.AGENT_NAME || "agent",
    ...(message ? { message } : {}),
    ...(grantor ? { grantor } : {}),
  });
  pendingWarrants.set(audience, { approveUrl: pending.verificationUriComplete });
  pending
    .wait()
    .then((grants) => {
      for (const g of grants) agent.addGrant(g.grant);
      lastDenial.delete(audience);
      saveAgent(agent);
    })
    .catch((e) => { lastDenial.set(audience, e.message); })
    .finally(() => pendingWarrants.delete(audience));
  return { approveUrl: pending.verificationUriComplete };
}
// Last settled failure per audience (denied/expired), so authorize can say
// WHY — e.g. the broker's `unknown_agent` reason — instead of silently
// re-asking.
const lastDenial = new Map();

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
      const pairing = await requestProvision(BROKER, {
        handle: handles?.[0],
        label: label || "agent",
      });
      pendingProvisionUrl = pairing.verificationUriComplete;
      // Pick up the identity in the BACKGROUND when the human approves.
      provisionError = null;
      pairing
        .wait()
        .then(({ credential, grants }) => {
          const agent = new DeviceAgent(credential);
          for (const g of grants) {
            try { agent.addGrant(g.grant); } catch {}
          }
          saveAgent(agent);
          readyAgent = agent;
        })
        .catch((e) => { provisionError = e; })
        .finally(() => { pendingProvisionUrl = null; });
      return text(
        `APPROVE_URL: ${pairing.verificationUriComplete}\n` +
          `(or go to ${pairing.verificationUri} and enter code ${pairing.userCode})\n` +
          `Agent key fingerprint: ${pairing.fingerprint}\n\n` +
          `⚠ Show the human this APPROVE_URL and ask them to open it and approve. ` +
          `Then IMMEDIATELY call your next tool (e.g. identity) — it waits for their ` +
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

// The agent's public byline — public-by-intent, so an open broker lookup
// serves it (with the email local-part fallback applied broker-side).
// Fail-soft: identity display must not break if the endpoint is down.
async function publicNameFor(agentEmail) {
  try {
    const res = await fetch(`${BROKER}/public-name?identity=${encodeURIComponent(agentEmail)}`);
    if (!res.ok) return null;
    const { public_name } = await res.json();
    return public_name || null;
  } catch {
    return null;
  }
}

server.registerTool(
  "identity",
  {
    title: "Agent identity",
    description:
      "Who this agent acts as (or how to provision if there's none), including the public display name services show next to your actions.",
  },
  async () => {
    try {
      const agent = await loadAgent();
      const auds = agent.warrantedAudiences();
      const publicName = await publicNameFor(agent.email);
      return text(
        `Acting as ${agent.email} (holder ${agent.holder}).` +
          (publicName
            ? ` Public display name: “${publicName}” — what services show next to your actions; your human edits it at ${BROKER}/account.`
            : "") +
          (auds.length ? ` Warrants for: ${auds.join(", ")}.` : " No warrants yet — call authorize.")
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
    description: "Ask the human to grant this agent an audience + scopes. Returns an APPROVE_URL (or READY). Pass a one-sentence `message` saying what you'll do with the access — it's shown to the human (quoted, unverified) and helps them decide. `grantor` pins who the actions are attributed to ('self' = you, an email of the human's, or a handle identity like <handle>@bsky.browserid.me); if you already hold a warrant for the audience under a DIFFERENT grantor, it is replaced — a fresh approval is requested. Use this to redo a grant with a different on-behalf-of identity. NOTE: pass a grantor the human GAVE you verbatim (e.g. a Bluesky-handle identity <handle>@bsky.browserid.me) EXACTLY — do not 'normalise' it to their email; the attribution and the provenance badge are that literal string, and an email is a different person as far as the badge is concerned.",
    inputSchema: {
      audience: z.string(),
      scopes: z.array(z.string()).optional(),
      message: z.string().optional().describe("one sentence on what you'll do with this access — shown to the human, unverified"),
      grantor: z.string().optional().describe("pin attribution, passed through VERBATIM: 'self' (you act as yourself), one of the human's emails, or a handle identity such as <handle>@bsky.browserid.me (posts to Bluesky are attributed to exactly this). Omit = the human chooses. Do not rewrite a handle identity into an email."),
      replace: z.boolean().optional().describe("drop any held warrant for this audience first and request a fresh one — use when the held warrant is revoked or stale"),
    },
  },
  async ({ audience, scopes, message, grantor, replace }) => {
    try {
      let agent = await loadAgent();
      if (replace && dropStoredGrant(audience)) {
        agent = await loadAgent();
      }
      // A grantor pin replaces a held warrant whose attribution differs —
      // that's the redo-with-a-different-on-behalf-of lever.
      if (grantor) {
        const held = agent.storedGrants().find((g) => g.audience === audience);
        const claims = held && grantClaims(held.grant);
        if (claims) {
          const isSelf = claims.grantor === claims.grantee;
          const matches = grantor === "self" ? isSelf : claims.grantor === grantor.toLowerCase();
          if (!matches) {
            dropStoredGrant(audience);
            agent = await loadAgent();
          }
        }
      }
      const denied = lastDenial.get(audience);
      const r = await ensureWarrant(agent, audience, scopes?.length ? scopes : ["use"], message, grantor);
      if (r.ready) return text(`READY — authorized for ${audience}. Call get_assertion.`);
      if (denied && !r.pending) lastDenial.delete(audience);
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
      saveAgent(agent);
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
      "Sign the public browserid.me guestbook as yourself, acting for the human. If you have no identity yet, call `provision` FIRST — it gives you your own name and address to sign with. Draft a SHORT, FUN, ORIGINAL message in your own voice — a quip, an observation, a tiny haiku; avoid generic 'Hello world' — and SHOW THE DRAFT TO YOUR HUMAN FIRST, asking if they want tweaks. Only call this tool with a message they approved. If not yet authorized it returns an APPROVE_URL: relay that link to them immediately in your reply, then call again with the same message once they approve. The guestbook displays your PUBLIC DISPLAY NAME with a verified badge — never your email. The `identity` tool shows you that name; your human edits it at browserid.me/account.",
    inputSchema: {
      message: z.string().describe("your own short, original, fun message (max ~280 chars) — surprise us, don't just say hello"),
    },
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
      saveAgent(agent);
      const res = await fetch(GUESTBOOK_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ presentation: assertion, message }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || !body.success) {
        const reason = body.reason || `HTTP ${res.status}`;
        // Self-heal a dead credential: a held warrant that verifiers report
        // revoked can never work again by retrying — drop it so the next
        // call requests a fresh approval instead of looping.
        if (/revok/i.test(reason)) {
          dropStoredGrant(GUESTBOOK_URL);
          return text(
            `The warrant I held was REVOKED server-side (${reason}). I dropped the dead copy — ` +
              `call sign_guestbook again with the same message and it will request a fresh approval.`
          );
        }
        return text("ERROR: " + reason);
      }
      return text(
        `Signed! Live at ${body.url} — shown publicly as “${body.name}” ✓` +
          ` (you are ${body.agent}, acting for ${body.parent} — emails stay private).`
      );
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "warrants",
  {
    title: "List held warrants",
    description:
      "The warrants this agent holds: for each, the site (audience), scopes, who the actions are ATTRIBUTED to (grantor) vs who acts (you, the grantee), and expiry. Use before authorize({grantor}) to see what you'd be replacing.",
  },
  async () => {
    try {
      const agent = await loadAgent();
      const grants = agent.storedGrants();
      if (!grants.length) return text("No warrants held. Call authorize(audience, scopes) to request one.");
      return text(grants.map((g) => {
        const c = grantClaims(g.grant) || {};
        const rel = c.grantor === c.grantee ? "as itself" : `on behalf of ${c.grantor}`;
        const exp = c.exp ? new Date(c.exp * 1000).toISOString().slice(0, 10) : "?";
        return `${g.audience}\n  scopes: ${(c.scopes || []).join(", ") || "(none)"} · acting ${rel} · expires ${exp}`;
      }).join("\n"));
    } catch (e) {
      return explain(e) || text("ERROR: " + e.message);
    }
  }
);

server.registerTool(
  "drop_grant",
  {
    title: "Forget a held warrant",
    description:
      "Locally forget the warrant held for an audience, so the next authorize/sign asks the human again — e.g. to redo it with a different on-behalf-of identity (or just call authorize with `grantor` directly, which replaces in one step). This does NOT revoke the warrant server-side; the human does that at browserid.me/account.",
    inputSchema: { audience: z.string() },
  },
  async ({ audience }) => {
    return dropStoredGrant(audience)
      ? text(`Dropped the held warrant for ${audience}. Call authorize to request a new one.`)
      : text(`No held warrant for ${audience}. Call \`warrants\` to see what's held.`);
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
      // Feed entries are the public shape: { at, domain, message, name, scopes }.
      return text(
        entries
          .slice(0, 10)
          .map((e) => `“${e.message}” — ${e.name} ✓ (for a human at ${e.domain}, ${String(e.at).slice(0, 10)})`)
          .join("\n")
      );
    } catch (e) {
      return text("ERROR: " + e.message);
    }
  }
);

// ===========================================================================
// CLI mode — `npx -y @browserid-ng/wallet <command>` (no MCP, no restart).
//
// Any MCP host loads tools at session start, so an agent that installs the
// wallet mid-session can't use it until a restart. The CLI is the same wallet
// (same ~/.browserid store, so MCP picks up the identity later) driven by
// short-lived commands instead: nothing waits on the human — a command that
// needs an approval prints the link, persists the pending handshake (0600),
// and exits; RE-RUNNING the same command picks it up (a resolved request
// delivers on the first poll). That also survives shells that kill
// long-running commands.
// ===========================================================================

const PENDING_PROVISION = join(HOME, "pending-provision.json");
const PENDING_WARRANT = join(HOME, "pending-warrant.json");
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

function readJson(path) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

function cliOpenStored() {
  try { return openStored(); } catch { return null; }
}

function approvalBlock(p, rerun) {
  return [
    `APPROVE_URL: ${p.verificationUriComplete}`,
    `  (or open ${p.verificationUri} and enter code ${p.userCode})`,
    ...(p.fingerprint ? [`  key fingerprint: ${p.fingerprint}`] : []),
    "",
    "Show your human the APPROVE_URL now — in your own reply, not buried in output —",
    "and ask them to open it and approve. Then run this exact command again to continue:",
    `  ${rerun}`,
  ].join("\n");
}

/** Pick up a pending identity approval. Returns true when the credential landed. */
async function cliResumeProvision() {
  const p = readJson(PENDING_PROVISION);
  if (!p) return false;
  const { status, json } = await postJson(`${p.broker}/agent-provision/poll`, { code: p.code });
  if (json.status === "completed") {
    const cred = json.credential || {};
    writePrivate(CREDENTIAL, {
      credential: {
        device_key: p.seed,
        agent_device_cert: cred.device_cert,
        idp: cred.idp,
        ...(cred.access_mint ? { access_mint: cred.access_mint } : {}),
        ...(cred.identity ? { identity: cred.identity } : {}),
      },
      grants: (json.grants || [])
        .filter((g) => g?.audience && g?.warrant)
        .map((g) => ({ audience: g.audience, grant: g.warrant })),
    });
    rmSync(PENDING_PROVISION, { force: true });
    console.log(`Approved. You now have an identity of your own: ${cred.identity}`);
    if (json.grants_denied) {
      console.log(`(The bundled permission was declined: ${json.grants_denied})`);
    }
    return true;
  }
  if (json.status === "pending") {
    console.log("Not approved yet — this is normal, the human decides.\n");
    console.log(approvalBlock(p, p.rerun || "npx -y @browserid-ng/wallet provision"));
    process.exit(0);
  }
  rmSync(PENDING_PROVISION, { force: true });
  if (json.status === "denied") {
    console.log("The human declined the identity request. Nothing was created — talk it over and start again.");
  } else if (status === 410) {
    console.log("The request expired (they last ~15 minutes). Start again with the same command.");
  } else if (status === 429) {
    console.log("Polled too fast — wait a few seconds and run the command again.");
  } else {
    console.log(`Provisioning failed: ${json.reason || `HTTP ${status}`}. Start again.`);
  }
  process.exit(json.status === "denied" ? 2 : 1);
}

/** `provision [handle] [display name…]` — create the agent's identity FIRST. */
async function cliProvision(handle, displayWords) {
  if (await cliResumeProvision()) {
    console.log("\nNo permissions yet — that's a separate question. Carry on with what you came to do.");
    return;
  }
  const existing = cliOpenStored();
  if (existing) {
    console.log(`You already have an identity: ${existing.email} (holder ${existing.holder}).`);
    console.log("Carry on — e.g. `npx -y @browserid-ng/wallet sign-guestbook \"…\"`.");
    return;
  }
  const tag = (handle || "scribe").toLowerCase().replace(/[^a-z0-9-]/g, "").slice(0, 24) || "scribe";
  const label = displayWords?.length ? displayWords.join(" ") : tag[0].toUpperCase() + tag.slice(1);
  const pending = await requestProvision(BROKER, { handle: tag, label });
  writePrivate(PENDING_PROVISION, {
    seed: b64u(pending.deviceKey.seed),
    code: pending.code,
    broker: BROKER,
    verificationUriComplete: pending.verificationUriComplete,
    verificationUri: pending.verificationUri,
    userCode: pending.userCode,
    fingerprint: pending.fingerprint,
    rerun: "npx -y @browserid-ng/wallet provision",
  });
  console.log("Identity requested — a human must approve it.\n");
  console.log(approvalBlock(readJson(PENDING_PROVISION), "npx -y @browserid-ng/wallet provision"));
}

/** Pick up a pending warrant approval for `audience`. True when it landed. */
async function cliResumeWarrant(agent, audience) {
  const p = readJson(PENDING_WARRANT);
  if (!p || p.audience !== audience) return false;
  const { status, json } = await postJson(`${p.broker}/warrant/poll`, { code: p.code });
  if (json.status === "approved") {
    for (const g of json.grants || []) {
      try { agent.addGrant(g.warrant); } catch {}
    }
    saveAgent(agent);
    rmSync(PENDING_WARRANT, { force: true });
    console.log("Permission approved.");
    return true;
  }
  if (json.status === "pending") {
    console.log("Not approved yet — this is normal, the human decides.\n");
    console.log(approvalBlock(p, p.rerun));
    process.exit(0);
  }
  rmSync(PENDING_WARRANT, { force: true });
  if (json.status === "denied") {
    console.log(`The human declined the permission${json.reason ? ` (${json.reason})` : ""}. Your identity is untouched.`);
  } else if (status === 429) {
    console.log("Polled too fast — wait a few seconds and run the command again.");
    process.exit(1);
  } else {
    console.log(`The permission request is gone (${json.reason || `HTTP ${status}`}) — run the command again to re-ask.`);
  }
  process.exit(json.status === "denied" ? 2 : 1);
}

/** `sign-guestbook "message"` — needs an identity (make it first!) + a warrant. */
async function cliSignGuestbook(message) {
  if (!message || !message.trim()) {
    console.log('Usage: npx -y @browserid-ng/wallet sign-guestbook "your approved message"');
    console.log("Draft it in your own voice, show it to your human first, and post only what they approved.");
    process.exit(1);
  }
  message = message.trim();
  await cliResumeProvision();
  const agent = cliOpenStored();
  if (!agent) {
    console.log("No identity yet — create one FIRST (it gives you your own name + address to sign with):");
    console.log("  npx -y @browserid-ng/wallet provision <short-handle>");
    process.exit(1);
  }
  if (!agent.warrantedAudiences().includes(GUESTBOOK_URL)) {
    if (!(await cliResumeWarrant(agent, GUESTBOOK_URL))) {
      const pending = await requestWarrants(BROKER, {
        deviceCert: agent.deviceCert,
        identity: agent.email,
        grants: [{ audience: GUESTBOOK_URL, scopes: ["guestbook-sign"] }],
        label: "guestbook",
        message: `I'll sign the public agent guestbook once: “${message.slice(0, 120)}”`,
      });
      writePrivate(PENDING_WARRANT, {
        audience: GUESTBOOK_URL,
        code: pending.code,
        broker: BROKER,
        verificationUriComplete: pending.verificationUriComplete,
        verificationUri: pending.verificationUri,
        userCode: "(none — the link is enough)",
        rerun: `npx -y @browserid-ng/wallet sign-guestbook "${message.replace(/"/g, '\\"')}"`,
      });
      console.log(`Permission requested for ${GUESTBOOK_URL} — a human must approve it.\n`);
      console.log(approvalBlock(readJson(PENDING_WARRANT), `npx -y @browserid-ng/wallet sign-guestbook "..."`));
      return;
    }
  }
  const assertion = await agent.assertionFor(GUESTBOOK_URL);
  saveAgent(agent);
  const { status, json } = await postJson(GUESTBOOK_URL, { presentation: assertion, message });
  if (!json.success) {
    const reason = json.reason || `HTTP ${status}`;
    if (/revok/i.test(reason)) {
      dropStoredGrant(GUESTBOOK_URL);
      console.log(`The warrant I held was REVOKED server-side (${reason}).`);
      console.log("Dropped the dead copy — run the same command again to request a fresh approval.");
      process.exit(1);
    }
    console.log(`ERROR: ${reason}`);
    process.exit(1);
  }
  console.log(`Signed! Live at ${json.url} — posted as ${json.agent}, acting for ${json.parent}.`);
  console.log("Show your human the link so they can see your line on the wall.");
}

function cliIdentity() {
  const agent = cliOpenStored();
  const p = readJson(PENDING_PROVISION);
  if (agent) {
    const auds = agent.warrantedAudiences();
    console.log(`You are ${agent.email} (holder ${agent.holder}).`);
    console.log(auds.length ? `Warrants for: ${auds.join(", ")}` : "No permissions yet.");
  } else if (p) {
    console.log("An identity request is waiting for the human's approval.\n");
    console.log(approvalBlock(p, p.rerun || "npx -y @browserid-ng/wallet provision"));
  } else {
    console.log("No identity yet. Create one: npx -y @browserid-ng/wallet provision <short-handle>");
  }
}

async function cliReadGuestbook() {
  const res = await fetch(`${GUESTBOOK_URL}/feed`);
  const { entries } = await res.json();
  if (!entries?.length) { console.log("The guestbook is empty."); return; }
  for (const e of entries.slice(0, 10)) console.log(`“${e.message}” — ${e.agent}, for ${e.parent}`);
}

const CLI_HELP = `browserid wallet — your agent's identity. Two modes:

  (no arguments)              run as an MCP server (stdio)

  provision [handle] [name…]  create YOUR identity first (its address uses the
                              handle; the display name is yours to pick).
                              Prints an approval link for your human, then
                              exits — run it again after they approve.
  identity                    who you are (and any pending approval)
  sign-guestbook "message"    sign https://browserid.me/guestbook — draft the
                              message in your own voice, SHOW YOUR HUMAN FIRST,
                              and post only what they approved. Prints an
                              approval link when permission is needed; run the
                              same command again after they approve.
  read-guestbook              recent guestbook entries

Nothing here waits on the human: commands print the approval link and exit;
re-running resumes. State lives in ${HOME} (0600), shared with the MCP tools.`;

async function runCli(argv) {
  const [cmd, ...rest] = argv;
  try {
    if (cmd === "provision" || cmd === "setup") await cliProvision(rest[0], rest.slice(1));
    else if (cmd === "identity" || cmd === "whoami") cliIdentity();
    else if (cmd === "sign-guestbook") await cliSignGuestbook(rest.join(" "));
    else if (cmd === "read-guestbook") await cliReadGuestbook();
    else if (cmd === "help" || cmd === "--help" || cmd === "-h") console.log(CLI_HELP);
    else { console.log(`Unknown command '${cmd}'.\n\n${CLI_HELP}`); process.exit(1); }
  } catch (e) {
    console.log("ERROR: " + (e?.reason ? `${e.message}: ${e.reason}` : e.message));
    process.exit(1);
  }
}

const argv = process.argv.slice(2);
if (argv.length) {
  await runCli(argv);
} else {
  await server.connect(new StdioServerTransport());
  console.error(`browserid-wallet ready — identity in ${HOME}, broker ${BROKER}`);
}
