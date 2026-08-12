// @browserid-ng/gate — wrap ANY stdio MCP server as a remote, BrowserID-gated
// HTTP endpoint.
//
// One command fronts an arbitrary local MCP server (a filesystem server, an
// Obsidian vault, Home Assistant, …) and publishes it as a Streamable-HTTP MCP
// endpoint that:
//
//   POST /mcp                              the MCP endpoint (bearer-gated, proxied to the child)
//   GET  /.well-known/oauth-protected-resource   RFC 9728 discovery
//   GET  /.well-known/oauth-authorization-server RFC 8414 discovery (BOTH lanes)
//   POST /token                            Lane A (jwt-bearer) + Lane B (authorization_code)
//   POST /register                         Lane B dynamic client registration (RFC 7591)
//   GET  /authorize                        Lane B PKCE authorize (302 → broker consent)
//   GET  /authorize/return                 Lane B post-approval bounce (302 → host redirect_uri)
//   GET  /  /healthz                       landing + probe
//
// One SHARED stdio child (the wrapped server exposes the OWNER's resource; the
// gate decides who and with what scope — design decision #7). Every tool call
// is gated fail-closed on a warrant, scoped to `tool:<name>`, refused unless
// the grantor (the connecting human) is on the owner's `--allow` list, and
// logged with one attribution line.
//
// Design: docs/plans/2026-08-12-mcp-gateway-hobbyist-to-saas.md (bean in36).

import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { createMcpAuth, createAuthCodeLane, McpAuthError } from "@browserid-ng/mcp-auth";

/**
 * Build (and connect) a gate service around a stdio MCP child.
 *
 * @param {object} opts
 * @param {string[]} opts.allow        Allowlisted grantor emails (whose humans may connect).
 * @param {string} [opts.name]         Display label (consent card + landing).
 * @param {{command:string, args?:string[], env?:object, cwd?:string}} [opts.child]
 *                                     The wrapped stdio server to spawn+proxy.
 * @param {object} [opts.client]       A pre-connected MCP Client (tests) — used instead of spawning.
 * @param {object} opts.credential     The gateway's device credential (Lane B).
 * @param {string} opts.resource       Canonical public URL of THIS gate (OAuth resource + audience).
 * @param {string} [opts.broker]       Broker origin (default https://browserid.me).
 * @param {number} [opts.statusCacheS] Per-grant status cache seconds (default 5 — revoke lands fast).
 * @param {(line:string)=>void} [opts.log]  Attribution/log sink (default console.log).
 * @returns {Promise<{server, mcpAuth, lane, tools, scopesForTool, allow, resource, broker, close}>}
 */
export async function createGateService(opts) {
  const allow = new Set((opts.allow || []).map((e) => String(e).trim().toLowerCase()).filter(Boolean));
  const name = opts.name || "mcp gateway";
  const resource = req(opts, "resource").replace(/\/+$/, "");
  const broker = (opts.broker || "https://browserid.me").replace(/\/+$/, "");
  const statusCacheS = opts.statusCacheS ?? 5;
  const log = opts.log || ((line) => console.log(line));

  // --- 1. connect to the wrapped stdio child --------------------------------
  let child = opts.client || null;
  let ownsChild = false;
  if (!child) {
    const spec = req(opts, "child");
    const transport = new StdioClientTransport({
      command: spec.command,
      args: spec.args || [],
      env: spec.env || { ...process.env },
      cwd: spec.cwd,
      stderr: "inherit",
    });
    child = new Client({ name: "browserid-gate-proxy", version: "0.1.0" });
    await child.connect(transport);
    ownsChild = true;
  }

  // --- 2. auto-map the child's tools → scopes -------------------------------
  const listed = await child.listTools();
  const tools = listed.tools || [];
  const scopesForTool = {};
  for (const t of tools) scopesForTool[t.name] = [`tool:${t.name}`];

  // --- 3. auth: both lanes over the same bearer store -----------------------
  const mcpAuth = createMcpAuth({ resource, broker, scopesForTool, statusCacheS });
  const lane = createAuthCodeLane({ mcpAuth, credential: req(opts, "credential"), label: name });

  // --- 4. one attribution line per tool call --------------------------------
  function attribute(ctx, tool, args) {
    log(`[gate] grantor=${ctx.grantor} grantee=${ctx.grantee} tool=${tool} args=${argsDigest(args)}`);
  }

  // --- 5. a proxy MCP server bound to one request's verified context --------
  // The child's tool list (with its REAL JSON schemas) is served verbatim;
  // each tools/call is scope-gated against the warrant, attributed, then
  // forwarded to the shared child.
  function buildProxyServer(ctx) {
    const server = new Server(
      { name: `browserid-gate:${name}`, version: "0.1.0" },
      { capabilities: { tools: {} } }
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const toolName = request.params.name;
      const args = request.params.arguments || {};
      const required = scopesForTool[toolName] || [];
      const missing = required.filter((s) => !ctx.scopes.includes(s));
      if (missing.length) {
        return {
          isError: true,
          content: [{
            type: "text",
            text:
              `INSUFFICIENT_SCOPE — your warrant lacks '${missing.join("', '")}'. ` +
              `Ask your human to re-approve with that scope at ${broker}/account.`,
          }],
        };
      }
      attribute(ctx, toolName, args);
      // Forward to the shared child and relay its result verbatim.
      return child.callTool({ name: toolName, arguments: args });
    });
    return server;
  }

  // --- 6. HTTP (the mcp-demo / github-mcp skeleton) -------------------------
  const server = createServer(async (rq, res) => {
    const url = new URL(rq.url, resource);
    const path = url.pathname;
    // Request log: one line per request with its final status, so an operator
    // (and we, debugging a host's connect flow) can see exactly what a client
    // did — discovery, register, authorize, token, /mcp — and where it stopped.
    res.on("finish", () => log(`[gate] ${rq.method} ${path} → ${res.statusCode}`));
    // CORS: MCP hosts (claude.ai) run OAuth discovery + dynamic client
    // registration from a browser context, so the cross-origin POST /register
    // (JSON body) needs a passing preflight and the discovery/token responses
    // need an allow-origin header — without these the connector fails to
    // register even though server-to-server calls work. Bearer auth uses the
    // Authorization header (never cookies), so a wildcard origin is safe.
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "content-type, authorization, mcp-protocol-version, mcp-session-id, last-event-id"
    );
    res.setHeader("Access-Control-Expose-Headers", "www-authenticate, mcp-session-id");
    res.setHeader("Access-Control-Max-Age", "600");
    if (rq.method === "OPTIONS") {
      res.writeHead(204);
      return res.end();
    }
    try {
      if (rq.method === "GET" && path === "/healthz") return json(res, 200, { ok: true });

      if (rq.method === "GET" && path === "/.well-known/oauth-protected-resource") {
        return json(res, 200, mcpAuth.protectedResourceMetadata());
      }
      // Serve the LANE's metadata so both grant types are advertised.
      if (rq.method === "GET" && path === "/.well-known/oauth-authorization-server") {
        return json(res, 200, lane.authorizationServerMetadata());
      }

      // Lane B: dynamic client registration (RFC 7591).
      if (rq.method === "POST" && path === "/register") {
        const body = await readJsonBody(rq);
        try {
          return json(res, 201, lane.handleRegister(body), { "cache-control": "no-store" });
        } catch (e) {
          return tokenError(res, e);
        }
      }

      // Lane B: authorize → 302 to the broker's consent page.
      if (rq.method === "GET" && path === "/authorize") {
        try {
          const { redirect } = await lane.handleAuthorize(Object.fromEntries(url.searchParams));
          return redirect302(res, redirect);
        } catch (e) {
          return tokenError(res, e);
        }
      }
      // Lane B: post-approval bounce → 302 to the host's redirect_uri.
      if (rq.method === "GET" && path === "/authorize/return") {
        try {
          const { redirect } = await lane.handleAuthorizeReturn(Object.fromEntries(url.searchParams));
          return redirect302(res, redirect);
        } catch (e) {
          return tokenError(res, e);
        }
      }

      // The token endpoint: Lane A (jwt-bearer) + Lane B (authorization_code).
      if (rq.method === "POST" && path === "/token") {
        const raw = await readBody(rq);
        let params;
        const ct = rq.headers["content-type"] || "";
        if (ct.includes("application/json")) {
          try { params = JSON.parse(raw); } catch { params = {}; }
        } else {
          params = Object.fromEntries(new URLSearchParams(raw));
        }
        try {
          const out = await lane.handleToken(params);
          return json(res, 200, out, { "cache-control": "no-store" });
        } catch (e) {
          return tokenError(res, e);
        }
      }

      // The MCP endpoint (resource server): bearer-gated, fail-closed status
      // re-check, grantor allowlist, then proxied to the child.
      if (path === "/mcp") {
        let ctx;
        try {
          ctx = await mcpAuth.authenticate(rq.headers.authorization);
        } catch (e) {
          const err = e instanceof McpAuthError ? e : new McpAuthError("invalid_token", e.message, 401);
          return json(res, err.httpStatus, { error: err.oauthError, error_description: err.message }, {
            "www-authenticate": mcpAuth.challenge(),
          });
        }
        // Grantor allowlist — refused BEFORE any tool runs (403).
        if (!allow.has(String(ctx.grantor || "").toLowerCase())) {
          log(`[gate] REFUSED grantor=${ctx.grantor} (not on the allowlist)`);
          return json(res, 403, {
            error: "access_denied",
            error_description: `'${ctx.grantor}' is not on this gateway's allowlist`,
          });
        }
        let body;
        if (rq.method === "POST") {
          try { body = JSON.parse(await readBody(rq)); } catch { body = undefined; }
        }
        const proxy = buildProxyServer(ctx);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        res.on("close", () => { transport.close(); proxy.close(); });
        await proxy.connect(transport);
        return transport.handleRequest(rq, res, body);
      }

      if (rq.method === "GET" && path === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        return res.end(landingHtml({ name, broker, tools, allow }));
      }

      json(res, 404, { error: "not_found" });
    } catch (e) {
      console.error(`[gate] ${rq.method} ${path}:`, e);
      if (!res.headersSent) json(res, 500, { error: "server_error" });
    }
  });

  async function close() {
    try { server.close(); } catch {}
    if (ownsChild) { try { await child.close(); } catch {} }
  }

  return { server, mcpAuth, lane, tools, scopesForTool, allow, resource, broker, close };
}

// --- helpers -----------------------------------------------------------------

function req(o, k) {
  if (!o || o[k] == null || o[k] === "") throw new Error(`gate: '${k}' is required`);
  return o[k];
}

/** A short, side-effect-free digest of a tool's arguments for the audit line —
 *  keys plus a truncated value preview, never the full payload. */
export function argsDigest(args, max = 80) {
  if (args == null) return "-";
  let s;
  try { s = JSON.stringify(args); } catch { return "?"; }
  if (s === "{}" || s === undefined) return "-";
  return s.length > max ? `${s.slice(0, max)}…(${s.length}b)` : s;
}

const json = (res, code, obj, headers = {}) => {
  res.writeHead(code, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
};

const redirect302 = (res, location) => {
  res.writeHead(302, { location });
  res.end();
};

const tokenError = (res, e) => {
  if (e instanceof McpAuthError) return json(res, e.httpStatus, e.toTokenErrorResponse());
  throw e;
};

async function readBody(rq, max = 1024 * 1024) {
  const chunks = [];
  let n = 0;
  for await (const c of rq) {
    n += c.length;
    if (n > max) throw new Error("body too large");
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readJsonBody(rq) {
  try { return JSON.parse(await readBody(rq)); } catch { return {}; }
}

function landingHtml({ name, broker, tools, allow }) {
  const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  const toolList = tools.map((t) => `<code>${esc(t.name)}</code>`).join(", ") || "(none)";
  return `<!doctype html><meta charset=utf-8><title>${esc(name)} — BrowserID gate</title>
<style>body{font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:640px;margin:6vh auto;padding:0 20px;color:#1a1a1a}code{background:#f2f3f5;padding:1px 5px;border-radius:5px}</style>
<h1>${esc(name)}</h1>
<p>A local MCP server, published as a remote <b>BrowserID-gated</b> endpoint via
<code>@browserid-ng/gate</code>. No static tokens: whoever connects presents a human's
short-lived, scoped, <b>revocable</b> warrant, every tool call is attributed to
"agent X on behalf of human Y", and a revoke at <a href="${esc(broker)}/account">${esc(broker)}/account</a>
kills that agent on its next call.</p>
<p>Allowed grantors: ${allow.size} · Tools: ${toolList}.</p>
<p>OAuth discovery: <code>/.well-known/oauth-protected-resource</code> ·
<code>/.well-known/oauth-authorization-server</code>. MCP endpoint: <code>POST /mcp</code>.</p>`;
}
