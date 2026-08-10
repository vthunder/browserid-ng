#!/usr/bin/env node
// browserid-ng MCP-auth demo — the "stop putting PATs in your MCP config"
// reference server. A warrant-gated MCP server built on @browserid-ng/mcp-auth:
//
//   POST /token                            the embedded AS (7521 assertion grant)
//   GET  /.well-known/oauth-*              RFC 9728 / RFC 8414 discovery
//   POST /mcp                              the MCP endpoint (bearer-authed)
//   GET  /  /healthz                       landing + probe
//
// Tools: `log_action` (scope demo:write) records an attributed action;
// `read_log` lists them. Every entry is attributed to "agent X on behalf of
// human Y" from the warrant — and a revoke at browserid.me/account kills the
// agent on its next call (fail-closed status re-check in the middleware).
//
// Design: docs/plans/2026-08-10-mcp-auth-flight-build-spec.md (bean 4w3n).
import { createServer } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createMcpAuth, McpAuthError } from "@browserid-ng/mcp-auth";

const PORT = Number(process.env.PORT || 3300);
const BROKER = (process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/+$/, "");
const RESOURCE = (process.env.MCP_RESOURCE || `http://localhost:${PORT}`).replace(/\/+$/, "");

const SCOPES = { log_action: ["demo:write"], read_log: [] };

const mcpAuth = createMcpAuth({
  resource: RESOURCE,
  broker: BROKER,
  scopesForTool: SCOPES,
});

// The demo's "data": an in-memory attributed action log (last 100).
const LOG = [];
function record(action, ctx) {
  const entry = {
    action: String(action).slice(0, 280),
    grantor: ctx.grantor, // the human
    grantee: ctx.grantee, // the agent acting
    holder: ctx.holder,
    at: new Date().toISOString(),
  };
  LOG.unshift(entry);
  LOG.length = Math.min(LOG.length, 100);
  return entry;
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
        `Logged ✓ — "${e.action}"\nattributed to ${e.grantee} on behalf of ${e.grantor} (holder ${e.holder}).\n` +
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
        (e) => `• ${e.at} — "${e.action}" — ${e.grantee} for ${e.grantor}`
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
  try {
    if (req.method === "GET" && path === "/healthz") return json(res, 200, { ok: true });

    if (req.method === "GET" && path === "/.well-known/oauth-protected-resource") {
      return json(res, 200, mcpAuth.protectedResourceMetadata());
    }
    if (req.method === "GET" && path === "/.well-known/oauth-authorization-server") {
      return json(res, 200, mcpAuth.authorizationServerMetadata());
    }

    // The embedded AS: 7521 assertion-grant token endpoint. Accepts form-
    // encoded (OAuth default) or JSON bodies.
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
        const out = await mcpAuth.handleToken(params);
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
<p>OAuth discovery: <code>/.well-known/oauth-protected-resource</code> ·
<code>/.well-known/oauth-authorization-server</code>. MCP endpoint: <code>POST /mcp</code>.</p>
<p>Tools: <code>log_action</code> (scope <code>demo:write</code>), <code>read_log</code>.</p>`;
}

server.listen(PORT, () => {
  console.log(`[mcp-demo] listening on :${PORT} (resource ${RESOURCE}, broker ${BROKER})`);
});
