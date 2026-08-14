#!/usr/bin/env node
// browserid-ng MCP-auth demo — the "stop putting PATs in your MCP config"
// reference server. A warrant-gated MCP server built on @browserid-ng/mcp-auth,
// mounting BOTH auth lanes:
//
//   POST /token                            the embedded AS — Lane A (7521
//                                          assertion grant, headless agents +
//                                          tests) AND Lane B (authorization_code)
//   POST /register                         Lane B dynamic client registration
//   GET  /authorize  /authorize/return     Lane B PKCE dance (302 → broker consent)
//   GET  /.well-known/oauth-*              RFC 9728 / RFC 8414 discovery
//   POST /mcp                              the MCP endpoint (bearer-authed)
//   GET  /  /healthz                       landing + probe
//
// Lane B is what real MCP hosts (claude.ai, Claude Code, Cursor) speak — add
// the /mcp URL as a connector and the host's stock OAuth machinery lands the
// human on the broker's consent card. It needs the demo's OWN identity
// (gateway-as-agent): pass the device credential JSON via $BROWSERID_CREDENTIAL;
// without it the server still runs, Lane A only.
//
// Tools: `log_action` (scope demo:write) records an attributed action;
// `read_log` lists them. Every entry is attributed to "agent X on behalf of
// human Y" from the warrant — and a revoke at browserid.me/account kills the
// agent on its next call (fail-closed status re-check in the middleware).
//
// Design: docs/plans/2026-08-10-mcp-auth-flight-build-spec.md (bean 4w3n);
// Lane B retrofit: bean kpr4.
import { createServer } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createMcpAuth, createAuthCodeLane, McpAuthError } from "@browserid-ng/mcp-auth";

const PORT = Number(process.env.PORT || 3300);
const BROKER = (process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/+$/, "");
const RESOURCE = (process.env.MCP_RESOURCE || `http://localhost:${PORT}`).replace(/\/+$/, "");

const SCOPES = { log_action: ["demo:write"], read_log: [] };

const mcpAuth = createMcpAuth({
  resource: RESOURCE,
  broker: BROKER,
  scopesForTool: SCOPES,
});

// Lane B: credential-less by default — when the broker advertises
// connection-grant support (spec §7.5) the lane raises connection requests
// as the AUDIENCE and holds the delivered records; a provisioned
// $BROWSERID_CREDENTIAL is only the fallback for brokers without support.
let credential = null;
if (process.env.BROWSERID_CREDENTIAL) {
  try {
    credential = JSON.parse(process.env.BROWSERID_CREDENTIAL);
  } catch (e) {
    throw new Error(`$BROWSERID_CREDENTIAL is not valid JSON: ${e.message}`);
  }
}
const lane = createAuthCodeLane({
  mcpAuth,
  ...(credential ? { credential } : {}),
  broker: BROKER,
  label: "browserid MCP demo",
  clientName: undefined,
});

// The demo's "data": an in-memory attributed action log (last 100).
const LOG = [];
function record(action, ctx) {
  const entry = {
    action: String(action).slice(0, 280),
    grantor: ctx.grantor, // the human
    grantee: ctx.grantee, // the acting identity
    client: ctx.client, // the connection (auth-code lane: e.g. claude.ai), or null
    holder: ctx.holder,
    at: new Date().toISOString(),
  };
  LOG.unshift(entry);
  LOG.length = Math.min(LOG.length, 100);
  return entry;
}

// Human-readable attribution: for a connector bearer, name the CONNECTION
// (the thing the human actually plugged in), not the demo's own service
// identity; for the assertion lane, the grantee is the acting agent.
function who(e) {
  return e.client ? `via ${e.client.name}${e.client.host && e.client.host !== e.client.name ? ` (${e.client.host})` : ""}` : e.grantee;
}

// Build a fresh MCP server bound to one request's verified context. Each tool
// enforces its own scope against the warrant (ctx.scopes) so per-tool
// authority is explicit.
function buildMcpServer(ctx) {
  const server = new McpServer({ name: "browserid-mcp-demo", version: "0.1.0" });

  server.registerTool(
    "log_action",
    {
      title: "Log an attributed action",
      description:
        "Record an action in the demo log, attributed to you (the agent) acting " +
        "on behalf of your human. Requires the 'demo:write' scope in your warrant. " +
        "No API key: authority comes from the human's revocable warrant.",
      inputSchema: { action: z.string().describe("a short description of the action (max ~280 chars)") },
    },
    async ({ action }) => {
      if (!ctx.scopes.includes("demo:write")) {
        return text("INSUFFICIENT_SCOPE — your warrant lacks 'demo:write'. Ask your human to re-approve with that scope.");
      }
      const e = record(action, ctx);
      return text(
        `Logged ✓ — "${e.action}"\n` +
          (e.client
            ? `${who(e)} — authorized by ${e.grantor}.\n`
            : `attributed to ${e.grantee} on behalf of ${e.grantor} (holder ${e.holder}).\n`) +
          `Your human can revoke this at ${BROKER}/account → Authorized sites; the next call then fails closed.`
      );
    }
  );

  server.registerTool(
    "read_log",
    {
      title: "Read the attributed action log",
      description: "List recent actions in the demo log with their attribution. Any valid warrant may read.",
      inputSchema: {},
    },
    async () => {
      if (LOG.length === 0) return text("The log is empty. Call log_action first.");
      const lines = LOG.slice(0, 20).map(
        (e) => `• ${e.at} — "${e.action}" — ${who(e)}, authorized by ${e.grantor}`
      );
      return text(`Recent attributed actions:\n${lines.join("\n")}`);
    }
  );

  return server;
}

const text = (s) => ({ content: [{ type: "text", text: s }] });

// --- HTTP -------------------------------------------------------------------

const json = (res, code, obj, headers = {}) => {
  res.writeHead(code, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
};

async function readBody(req, max = 1024 * 1024) {
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > max) throw new Error("body too large");
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, RESOURCE);
  const path = url.pathname;
  if (path !== "/healthz") res.on("finish", () => console.log(`[mcp-demo] ${req.method} ${path} → ${res.statusCode}`));
  try {
    // CORS: hosts (claude.ai) preflight /register and read discovery
    // cross-origin during the Lane B dance.
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "content-type, authorization, mcp-protocol-version, mcp-session-id, last-event-id"
    );
    res.setHeader("Access-Control-Expose-Headers", "www-authenticate, mcp-session-id");
    res.setHeader("Access-Control-Max-Age", "600");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      return res.end();
    }

    if (req.method === "GET" && path === "/healthz") return json(res, 200, { ok: true });

    // Discovery — served at the ROOT form and the PATH-INSERTED form
    // (/.well-known/<doc>/mcp). Spec hosts (claude.ai) derive the latter from
    // the connector URL the user typed (…/mcp) per RFC 9728/8414; without it
    // the first add fails with a connection error before falling back to the
    // 401 challenge's root-form URL. Same lesson as gate 0.3.3.
    if (req.method === "GET" && (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp")) {
      return json(res, 200, mcpAuth.protectedResourceMetadata());
    }
    if (req.method === "GET" && (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/oauth-authorization-server/mcp")) {
      // The lane's metadata advertises BOTH grants (+ authorize/register).
      return json(res, 200, lane ? lane.authorizationServerMetadata() : mcpAuth.authorizationServerMetadata());
    }

    // Connection mode (spec §7.5): the audience-proof document. Must stay
    // published until the pending request resolves or expires.
    if (req.method === "GET" && path.startsWith("/.well-known/browserid-audience-proof/")) {
      const id = path.slice("/.well-known/browserid-audience-proof/".length);
      const body = lane.handleAudienceProof(id);
      if (body == null) {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        return res.end("no such pending request");
      }
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      return res.end(body);
    }

    // Lane B: dynamic client registration (RFC 7591).
    if (lane && req.method === "POST" && path === "/register") {
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw); } catch { body = {}; }
      try {
        return json(res, 201, lane.handleRegister(body), { "cache-control": "no-store" });
      } catch (e) {
        if (e instanceof McpAuthError) return json(res, e.httpStatus, e.toTokenErrorResponse());
        throw e;
      }
    }

    // Lane B: PKCE authorize → 302 to the broker's consent page.
    if (lane && req.method === "GET" && path === "/authorize") {
      try {
        const { redirect } = await lane.handleAuthorize(Object.fromEntries(url.searchParams));
        res.writeHead(302, { location: redirect });
        return res.end();
      } catch (e) {
        if (e instanceof McpAuthError) return json(res, e.httpStatus, e.toTokenErrorResponse());
        throw e;
      }
    }

    // Lane B: post-approval bounce → 302 back to the host's redirect_uri.
    if (lane && req.method === "GET" && path === "/authorize/return") {
      try {
        const { redirect } = await lane.handleAuthorizeReturn(Object.fromEntries(url.searchParams));
        res.writeHead(302, { location: redirect });
        return res.end();
      } catch (e) {
        // The consent page's auto-redirect consumes the single-use record; its
        // manual "return to the app" link then lands here with nothing left.
        // The sign-in already completed — show a friendly page, not an error.
        if (e instanceof McpAuthError && e.oauthError === "invalid_request") {
          res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
          return res.end(returnDoneHtml());
        }
        if (e instanceof McpAuthError) return json(res, e.httpStatus, e.toTokenErrorResponse());
        throw e;
      }
    }

    // The embedded AS token endpoint. With Lane B mounted it serves BOTH
    // grants (authorization_code + 7521 assertion); Lane A-only otherwise.
    // Accepts form-encoded (OAuth default) or JSON bodies.
    if (req.method === "POST" && path === "/token") {
      const raw = await readBody(req);
      let params;
      const ct = req.headers["content-type"] || "";
      if (ct.includes("application/json")) {
        try { params = JSON.parse(raw); } catch { params = {}; }
      } else {
        params = Object.fromEntries(new URLSearchParams(raw));
      }
      try {
        const out = await (lane ? lane.handleToken(params) : mcpAuth.handleToken(params));
        return json(res, 200, out, { "cache-control": "no-store" });
      } catch (e) {
        if (e instanceof McpAuthError) return json(res, e.httpStatus, e.toTokenErrorResponse());
        throw e;
      }
    }

    // The MCP endpoint (resource server). Bearer-gated + fail-closed status.
    if (path === "/mcp") {
      let ctx;
      try {
        ctx = await mcpAuth.authenticate(req.headers.authorization);
      } catch (e) {
        const err = e instanceof McpAuthError ? e : new McpAuthError("invalid_token", e.message, 401);
        return json(res, err.httpStatus, { error: err.oauthError, error_description: err.message }, {
          "www-authenticate": mcpAuth.challenge(),
        });
      }
      let body;
      if (req.method === "POST") {
        try { body = JSON.parse(await readBody(req)); } catch { body = undefined; }
      }
      const mcpServer = buildMcpServer(ctx);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on("close", () => { transport.close(); mcpServer.close(); });
      await mcpServer.connect(transport);
      return transport.handleRequest(req, res, body);
    }

    if (req.method === "GET" && path === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(landingHtml());
    }

    json(res, 404, { error: "not_found" });
  } catch (e) {
    console.error(`[mcp-demo] ${req.method} ${path}:`, e);
    if (!res.headersSent) json(res, 500, { error: "server_error" });
  }
});

function landingHtml() {
  return `<!doctype html><meta charset=utf-8><title>browserid MCP-auth demo</title>
<style>body{font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:640px;margin:6vh auto;padding:0 20px;color:#1a1a1a}code{background:#f2f3f5;padding:1px 5px;border-radius:5px}</style>
<h1>browserid MCP-auth demo</h1>
<p>A warrant-gated MCP server built on <code>@browserid-ng/mcp-auth</code> — no API keys.
Authority is a human's short-lived, scoped, <b>revocable</b> warrant; every tool call is
attributed to "agent X on behalf of human Y", and a revoke at
<a href="${BROKER}/account">${BROKER}/account</a> kills the agent on its next call.</p>
${lane ? `<p><b>Try it:</b> add <code>${RESOURCE}/mcp</code> to your MCP host (claude.ai:
Settings → Connectors → Add custom connector) and approve once — then ask your agent
to log an action. Full runbook: <a href="https://browserid.me/mcp-demo">browserid.me/mcp-demo</a>.</p>` : ""}
<p>OAuth discovery: <code>/.well-known/oauth-protected-resource</code> ·
<code>/.well-known/oauth-authorization-server</code>. MCP endpoint: <code>POST /mcp</code>.</p>
<p>Tools: <code>log_action</code> (scope <code>demo:write</code>), <code>read_log</code>.</p>`;
}

/** Friendly page for the already-consumed authorization return (benign
 *  double-submit from the consent page's auto-nav + manual link). */
function returnDoneHtml() {
  return `<!doctype html><meta charset=utf-8><title>All set</title>
<style>body{font:16px/1.6 -apple-system,system-ui,sans-serif;max-width:420px;margin:18vh auto;padding:0 24px;color:#1a1a1a;text-align:center}
.ok{font-size:40px}h1{font-size:20px;margin:.4em 0}p{color:#6b6b74}</style>
<div class="ok">✓</div>
<h1>You're all set</h1>
<p>This sign-in is complete — you can close this window and return to the app.
If the app didn't connect, add it again.</p>`;
}

server.listen(PORT, () => {
  console.log(
    `[mcp-demo] listening on :${PORT} (resource ${RESOURCE}, broker ${BROKER}, ` +
      `lanes: assertion${lane ? " + authorization_code" : " only"})`
  );
});
