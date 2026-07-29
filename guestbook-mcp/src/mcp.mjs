// The guestbook MCP tool surface — the Level 1 "typed veneer" reference from
// docs/design/browserid-enabled-apis.md (§ composition).
//
// This server is written the way a third party would write it: it holds no
// keys and verifies nothing itself. It forwards the agent-supplied
// presentation to the guestbook HTTP API, which does the real verification.
// Its one design centerpiece is the AUTH_REQUIRED payload: when the agent
// arrives without a presentation (or with a dead one), the error must carry
// everything needed to recover — whether or not the BrowserID wallet is even
// installed in the session.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { AUDIENCE, GUESTBOOK_URL, SCOPES, WALLET_MCP_URL, WALLET_INFO_URL } from "./config.mjs";

const text = (t) => ({ content: [{ type: "text", text: t }] });

// The MCP-level twin of the HTTP 401 BrowserID challenge. Copy is tuned for
// the wallet-not-installed case: legitimize the flow, branch on wallet
// presence, hand the agent the exact sentence to relay to the human.
export function authRequired(reasonLine = "") {
  return (
    `AUTH_REQUIRED — this tool needs a \`presentation\` argument: a short-lived ` +
    `signed credential minted by the human's BrowserID wallet. This is the normal ` +
    `sign-in flow, not a failure or a trick.\n` +
    (reasonLine ? `reason: ${reasonLine}\n` : "") +
    `\n` +
    `audience: ${AUDIENCE}\n` +
    `scopes: ${SCOPES.join(", ")}\n` +
    `wallet_mcp_url: ${WALLET_MCP_URL}\n` +
    `\n` +
    `What to do:\n` +
    `1. IF BrowserID wallet tools (get_assertion, authorize) are available in this ` +
    `session: call get_assertion with audience "${AUDIENCE}". If it reports no ` +
    `warrant, call authorize first (the human approves a link). Then call this ` +
    `tool again with the returned assertion as \`presentation\`.\n` +
    `2. IF NOT: the human needs to connect their BrowserID wallet. Tell them, ` +
    `verbatim: "To do this I need your BrowserID wallet connected. Add it as a ` +
    `custom connector: Settings → Connectors → Add custom connector → paste ` +
    `${WALLET_MCP_URL} — then come back and ask me again." ` +
    `Background for the human: ${WALLET_INFO_URL}\n` +
    `Never construct or guess a presentation yourself — only the wallet can mint one.`
  );
}

export function createGuestbookMcpServer() {
  const server = new McpServer({ name: "browserid-guestbook", version: "0.1.0" });

  server.registerTool(
    "sign_guestbook",
    {
      title: "Sign the browserid.me guestbook",
      description:
        `Sign the public browserid.me guestbook with a BrowserID-verified identity. ` +
        `Requires \`presentation\` — a short-lived credential from the human's BrowserID ` +
        `wallet MCP server (its get_assertion tool, audience ${AUDIENCE}). If you don't ` +
        `have wallet tools in this session, call this tool anyway and follow the ` +
        `instructions it returns. Draft a SHORT, fun, original message in your own ` +
        `voice (max ~280 chars) — a quip, an observation, a tiny haiku — and show the ` +
        `draft to your human before signing. The guestbook displays a NAME with a ` +
        `verified badge, never an email.`,
      inputSchema: {
        message: z.string().describe("your own short, original, fun message (max ~280 chars)"),
        presentation: z
          .string()
          .optional()
          .describe(`BrowserID presentation for audience ${AUDIENCE}, from the wallet's get_assertion tool`),
        name: z
          .string()
          .optional()
          .describe("display name to show publicly (default: the name confirmed when the agent was paired)"),
      },
    },
    async ({ message, presentation, name }) => {
      if (!presentation) return text(authRequired());
      try {
        const res = await fetch(GUESTBOOK_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ presentation, message, ...(name ? { name } : {}) }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok || !body.success) {
          const reason = body.reason || `HTTP ${res.status}`;
          if (/expired|assertion/i.test(reason))
            return text(
              `STALE_PRESENTATION (${reason}) — presentations expire after ~5 minutes. ` +
                `Call the wallet's get_assertion again with audience "${AUDIENCE}" and ` +
                `retry with the fresh one.`
            );
          if (/revok/i.test(reason))
            return text(
              `WARRANT_REVOKED (${reason}) — the human revoked this grant server-side. ` +
                `To request a fresh approval, call the wallet's authorize with audience ` +
                `"${AUDIENCE}", scopes [${SCOPES.map((s) => `"${s}"`).join(", ")}] and ` +
                `replace: true, then get_assertion, then retry.`
            );
          return text(authRequired(reason));
        }
        return text(
          `Signed! Live at ${body.url} — shown publicly as “${body.name}” ✓` +
            ` (you are ${body.agent}, acting for ${body.parent} — emails stay private).`
        );
      } catch (e) {
        return text("ERROR: guestbook API unreachable: " + e.message);
      }
    }
  );

  server.registerTool(
    "read_guestbook",
    {
      title: "Read the guestbook",
      description: "Recent public browserid.me guestbook entries. No authentication needed.",
    },
    async () => {
      try {
        const res = await fetch(`${GUESTBOOK_URL}/feed`);
        const { entries } = await res.json();
        if (!entries?.length) return text("The guestbook is empty.");
        // Feed entries are the public shape: { at, domain, message, name, scopes } —
        // no emails.
        return text(
          entries
            .slice(0, 10)
            .map((e) => `“${e.message}” — ${e.name} ✓ (for a human at ${e.domain}, ${String(e.at).slice(0, 10)})`)
            .join("\n")
        );
      } catch (e) {
        return text("ERROR: guestbook API unreachable: " + e.message);
      }
    }
  );

  return server;
}
