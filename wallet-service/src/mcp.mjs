// The wallet MCP tool surface, per tenant. This is the hosted port of
// sdk/wallet/server.mjs: same tools, same prompts, same non-blocking approval
// pattern — but state lives in the tenant store (encrypted at rest) instead
// of ~/.browserid, and every operation lands in the audit log.
//
// A server instance is built per HTTP request (stateless streamable HTTP),
// so all pending-approval state is module-level, keyed by tenant.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  requestProvision, requestWarrants,
  AgentError, NoWarrantError, RequestError,
} from "@browserid-ng/agent";
import { BROKER, GUESTBOOK_URL } from "./config.mjs";

const text = (t) => ({ content: [{ type: "text", text: t }] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Bounded wait for an in-flight approval, so the human can approve while the
// call is in flight. Remote-connector budgets are tighter than local stdio
// (claude.ai's request timeout is not published), so stay well under 30s;
// the agent is instructed to just call again.
const APPROVAL_WAIT_MS = 20000;

// ---- module-level pending state, keyed by tenant ---------------------------
const pendingProvisions = new Map(); // email -> { url }
const provisionErrors = new Map(); // email -> Error
const pendingWarrants = new Map(); // `${email}\n${audience}` -> { approveUrl }
const lastDenials = new Map(); // `${email}\n${audience}` -> reason
const wkey = (email, audience) => `${email}\n${audience}`;

class PendingApproval extends Error {
  constructor(url) { super("provisioning pending"); this.url = url; }
}
class NeedCredential extends Error {
  constructor() { super("no identity yet"); }
}

function explain(e) {
  if (e instanceof PendingApproval)
    return text(
      `STILL WAITING for the human to approve — this is normal. Keep this link visible and call your ` +
        `tool AGAIN to keep waiting (each call polls ~${APPROVAL_WAIT_MS / 1000}s):\n${e.url}`
    );
  if (e instanceof RequestError)
    return text(
      `PROVISIONING FAILED: ${e.reason}. ` +
        (/quota/i.test(e.reason) ? `The human has too many agent identities — they can revoke old ones at ${BROKER}/account. ` : "") +
        "Fix that, then call provision again."
    );
  if (e instanceof NeedCredential)
    return text("NEED_CREDENTIAL: no identity yet. Call the `provision` tool to pair one — the human approves a link, nothing to download.");
  if (e instanceof AgentError && /refused/.test(e.message)) return text("DENIED: the human declined.");
  if (e instanceof AgentError && /expired/.test(e.message)) return text("EXPIRED: the request expired; try again.");
  return null;
}

/** The decoded claims of a held grant ('warrant~config_cert'), or null. */
function grantClaims(pair) {
  try {
    return JSON.parse(Buffer.from(pair.split("~")[0].split(".")[1], "base64url").toString());
  } catch {
    return null;
  }
}

/**
 * Build the MCP server for one authenticated request.
 * @param {{email: string, clientId: string, ip: string}} tenant
 * @param {{store: import('./store.mjs').WalletStore, audit: import('./audit.mjs').Audit}} deps
 */
export function createWalletMcpServer(tenant, { store, audit }) {
  const { email, clientId, ip } = tenant;
  const log = (op, extra = {}) => audit.log(email, op, { clientId, ip, ...extra });

  // Non-blocking tenant agent load: ready, stored, pending, or NeedCredential.
  async function loadAgent() {
    const throwErr = () => { const e = provisionErrors.get(email); provisionErrors.delete(email); throw e; };
    if (provisionErrors.has(email)) throwErr();
    const pending = () => pendingProvisions.get(email);
    if (pending()) {
      const deadline = Date.now() + APPROVAL_WAIT_MS;
      while (pending() && Date.now() < deadline) {
        await sleep(1500);
        if (provisionErrors.has(email)) throwErr();
      }
      if (provisionErrors.has(email)) throwErr();
      if (pending()) throw new PendingApproval(pending().url);
    }
    const agent = store.loadAgent(email);
    if (!agent) throw new NeedCredential();
    return agent;
  }

  // Non-blocking warrant flow — ported from the local wallet's ensureWarrant.
  async function ensureWarrant(agent, audience, scopes, message, grantor) {
    if (agent.warrantedAudiences().includes(audience)) return { ready: true };
    const key = wkey(email, audience);
    const inflight = pendingWarrants.get(key);
    if (inflight) {
      const deadline = Date.now() + APPROVAL_WAIT_MS;
      while (Date.now() < deadline) {
        await sleep(1500);
        if (agent.warrantedAudiences().includes(audience)) return { ready: true };
        if (!pendingWarrants.has(key)) break; // settled
      }
      if (agent.warrantedAudiences().includes(audience)) return { ready: true };
      return { pending: true, approveUrl: inflight.approveUrl };
    }
    const pending = await requestWarrants(BROKER, {
      deviceCert: agent.deviceCert,
      identity: agent.email,
      grants: [{ audience, scopes }],
      label: "agent",
      ...(message ? { message } : {}),
      ...(grantor ? { grantor } : {}),
    });
    log("warrant.request", { audience, detail: (scopes || []).join(" ") });
    pendingWarrants.set(key, { approveUrl: pending.verificationUriComplete });
    pending
      .wait()
      .then((grants) => {
        for (const g of grants) agent.addGrant(g.grant);
        lastDenials.delete(key);
        store.syncGrants(email, agent);
        log("warrant.grant", { audience });
      })
      .catch((e) => {
        lastDenials.set(key, e.message);
        log("warrant.deny", { audience, detail: e.message });
      })
      .finally(() => pendingWarrants.delete(key));
    return { approveUrl: pending.verificationUriComplete };
  }

  const server = new McpServer({ name: "browserid-wallet", version: "0.1.0" });

  server.registerTool(
    "provision",
    {
      title: "Provision an identity",
      description:
        "Pair a new browserid-ng identity with the human (they approve a link; nothing to download). Suggest a SINGLE short handle unless the human asked for more.",
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
        log("provision.request");
        pendingProvisions.set(email, { url: pairing.verificationUriComplete });
        provisionErrors.delete(email);
        pairing
          .wait()
          .then(({ credential, grants }) => {
            store.saveCredential(email, credential, grants);
            log("provision.complete", { detail: credential.identity ?? null });
          })
          .catch((e) => {
            provisionErrors.set(email, e);
            log("provision.fail", { detail: e.message });
          })
          .finally(() => pendingProvisions.delete(email));
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
        "Delete this wallet's stored identity (credential + warrants) so a fresh one can be provisioned. Does NOT revoke it server-side — that's done at browserid.me/account.",
    },
    async () => {
      pendingProvisions.delete(email);
      provisionErrors.delete(email);
      for (const key of [...pendingWarrants.keys()]) if (key.startsWith(`${email}\n`)) pendingWarrants.delete(key);
      const removed = store.forget(email);
      log("credential.forget");
      return text(
        `Forgot the stored identity (${removed.credentials} credential, ${removed.grants} warrant(s) removed). ` +
          `Call provision to set up a new one. (The old identity still exists at ${BROKER}/account until revoked there.)`
      );
    }
  );

  server.registerTool(
    "identity",
    { title: "Agent identity", description: "Who this agent acts as (or how to provision if there's none)." },
    async () => {
      try {
        const agent = await loadAgent();
        const auds = agent.warrantedAudiences();
        return text(
          `Acting as ${agent.email} (holder ${agent.holder}).` +
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
      description:
        "Ask the human to grant this agent an audience + scopes. Returns an APPROVE_URL (or READY). Pass a one-sentence `message` saying what you'll do with the access — it's shown to the human (quoted, unverified) and helps them decide. `grantor` pins who the actions are attributed to ('self' = you, an email of the human's, or a handle identity like <handle>@bsky.browserid.me); if you already hold a warrant for the audience under a DIFFERENT grantor, it is replaced — a fresh approval is requested. Use this to redo a grant with a different on-behalf-of identity. NOTE: pass a grantor the human GAVE you verbatim (e.g. a Bluesky-handle identity <handle>@bsky.browserid.me) EXACTLY — do not 'normalise' it to their email; the attribution and the provenance badge are that literal string, and an email is a different person as far as the badge is concerned.",
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
        if (replace && store.dropGrant(email, audience)) {
          agent = await loadAgent();
        }
        if (grantor) {
          const held = agent.storedGrants().find((g) => g.audience === audience);
          const claims = held && grantClaims(held.grant);
          if (claims) {
            const isSelf = claims.grantor === claims.grantee;
            const matches = grantor === "self" ? isSelf : claims.grantor === grantor.toLowerCase();
            if (!matches) {
              store.dropGrant(email, audience);
              agent = await loadAgent();
            }
          }
        }
        const key = wkey(email, audience);
        const denied = lastDenials.get(key);
        const r = await ensureWarrant(agent, audience, scopes?.length ? scopes : ["use"], message, grantor);
        if (r.ready) return text(`READY — authorized for ${audience}. Call get_assertion.`);
        if (denied && !r.pending) lastDenials.delete(key);
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
        log("assertion.issue", { audience });
        return text("ASSERTION: " + assertion);
      } catch (e) {
        if (e instanceof NoWarrantError) return text(`PENDING — no warrant for ${audience}. Call authorize first.`);
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
      const dropped = store.dropGrant(email, audience);
      if (dropped) log("grant.drop", { audience });
      return dropped
        ? text(`Dropped the held warrant for ${audience}. Call authorize to request a new one.`)
        : text(`No held warrant for ${audience}. Call \`warrants\` to see what's held.`);
    }
  );

  server.registerTool(
    "sign_guestbook",
    {
      title: "Sign the guestbook (demo)",
      description:
        "Sign the public browserid.me guestbook as yourself, acting for the human. If you have no identity yet, call `provision` FIRST — it gives you your own name and address to sign with. Draft a SHORT, FUN, ORIGINAL message in your own voice — a quip, an observation, a tiny haiku; avoid generic 'Hello world' — and SHOW THE DRAFT TO YOUR HUMAN FIRST, asking if they want tweaks. Only call this tool with a message they approved. If not yet authorized it returns an APPROVE_URL: relay that link to them immediately in your reply, then call again with the same message once they approve.",
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
        log("assertion.issue", { audience: GUESTBOOK_URL });
        const res = await fetch(GUESTBOOK_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ presentation: assertion, message }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok || !body.success) {
          const reason = body.reason || `HTTP ${res.status}`;
          if (/revok/i.test(reason)) {
            store.dropGrant(email, GUESTBOOK_URL);
            return text(
              `The warrant I held was REVOKED server-side (${reason}). I dropped the dead copy — ` +
                `call sign_guestbook again with the same message and it will request a fresh approval.`
            );
          }
          return text("ERROR: " + reason);
        }
        log("guestbook.sign");
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

  return server;
}
