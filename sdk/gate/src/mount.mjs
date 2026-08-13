// A "mount" — the reusable unit both the single-server gate (src/gate.mjs) and
// the multi-server gateway (src/gateway.mjs) are built from. One mount wraps
// ONE stdio MCP child and is a self-contained BrowserID OAuth resource.
//
// The KEY structural fact: a mount's `resource` is passed in whole, so the
// single-server case uses `https://<host>` and the gateway uses
// `https://<host>/<slug>`. Because mcp-auth + the auth-code lane build every
// OAuth URL as `${resource}/…`, path-prefixing under the gateway is automatic:
// the advertised token/authorize/register endpoints and the /mcp 401 challenge
// all carry the `/<slug>` prefix with ZERO mcp-auth changes. One shared gateway
// agent identity (the DeviceCredential) backs every mount's Lane B; mounts
// differ only by resource (audience), child, and allowlist.

import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { createMcpAuth, createAuthCodeLane, McpAuthError } from "@browserid-ng/mcp-auth";

/**
 * Build (and connect) a mount around a stdio MCP child.
 *
 * @param {object} opts
 * @param {string} opts.resource      Canonical URL of THIS mount (OAuth resource + audience).
 * @param {object} opts.credential    The gateway's device credential (Lane B).
 * @param {string[]} [opts.allow]     Allowlisted grantor emails (whose humans may connect).
 * @param {(email:string)=>'all'|Set<string>|null} [opts.access]
 *                                    Role-based resolver (gateway mode): maps a
 *                                    grantor email to the tools their roles
 *                                    grant HERE ('all', a Set, or null =
 *                                    refused). Supersedes `allow` when given.
 * @param {string} [opts.name]        Display label (consent card).
 * @param {{command:string, args?:string[], env?:object, cwd?:string}} [opts.child]
 *                                    The wrapped stdio server to spawn+proxy.
 * @param {object} [opts.client]      A pre-connected MCP Client (tests) — used instead of spawning.
 * @param {string} [opts.broker]      Broker origin (default https://browserid.me).
 * @param {number} [opts.statusCacheS] Per-grant status cache seconds (default 5).
 * @param {object} [opts.store]       Bearer store (mcp-auth default if omitted).
 * @param {typeof fetch} [opts.fetch] Injectable fetch (tests).
 * @param {(line:string)=>void} [opts.log]
 * @param {{id?:string, slug?:string}} [opts.meta]  identity for the gateway.
 * @returns {Promise<Mount>}
 */
export async function createMount(opts) {
  const resource = req(opts, "resource").replace(/\/+$/, "");
  const name = opts.name || "mcp gateway";
  const broker = (opts.broker || "https://browserid.me").replace(/\/+$/, "");
  const statusCacheS = opts.statusCacheS ?? 5;
  const doFetch = opts.fetch || globalThis.fetch;
  const log = opts.log || (() => {});
  const allow = new Set((opts.allow || []).map((e) => String(e).trim().toLowerCase()).filter(Boolean));
  const access = typeof opts.access === "function" ? opts.access : null;

  // --- 1. connect to the wrapped stdio child --------------------------------
  let child = opts.client || null;
  let ownsChild = false;
  let childProc = null;
  if (!child) {
    const spec = req(opts, "child");
    // ARGV, never a shell string: StdioClientTransport → cross-spawn spawns
    // command + args as literal argv. No interpolation, no `sh -c`.
    const transport = new StdioClientTransport({
      command: spec.command,
      args: spec.args || [],
      env: spec.env || { ...process.env },
      cwd: spec.cwd,
      stderr: "inherit",
    });
    child = new Client({ name: "browserid-gate-proxy", version: "0.3.0" });
    await child.connect(transport);
    ownsChild = true;
    childProc = transport; // close() tears down the child process
  }

  // --- 2. auto-map the child's tools → scopes -------------------------------
  const listed = await child.listTools();
  const tools = listed.tools || [];
  const scopesForTool = {};
  for (const t of tools) scopesForTool[t.name] = [`tool:${t.name}`];

  // --- 3. auth: both lanes over the same bearer store -----------------------
  const mcpAuth = createMcpAuth({ resource, broker, scopesForTool, statusCacheS, store: opts.store, fetch: doFetch });
  const lane = createAuthCodeLane({ mcpAuth, credential: req(opts, "credential"), broker, fetch: doFetch, label: name });

  function attribute(ctx, tool, args) {
    log(`[gate] grantor=${ctx.grantor} grantee=${ctx.grantee} tool=${tool} args=${argsDigest(args)}`);
  }

  // --- 4. a proxy MCP server bound to one request's verified context --------
  // `granted` is the role-derived tool set for THIS grantor ('all' or a Set);
  // in allowlist mode (no access resolver) every tool is granted.
  function buildProxyServer(ctx, granted = "all") {
    const has = (t) => granted === "all" || granted.has(t);
    const server = new Server({ name: `browserid-gate:${name}`, version: "0.3.0" }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: tools.filter((t) => has(t.name)) }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const toolName = request.params.name;
      const args = request.params.arguments || {};
      if (!has(toolName)) {
        return {
          isError: true,
          content: [{
            type: "text",
            text:
              `ACCESS_DENIED — your role doesn't grant '${toolName}' on this server. ` +
              `Ask the gateway's admin to grant it in the console.`,
          }],
        };
      }
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
      return child.callTool({ name: toolName, arguments: args });
    });
    return server;
  }

  /**
   * Dispatch one request already routed to this mount, with the mount prefix
   * stripped (`subpath`). Returns true iff handled.
   * @param {import('node:http').IncomingMessage} rq
   * @param {import('node:http').ServerResponse} res
   * @param {{subpath:string, url:URL}} ctx
   */
  async function handle(rq, res, { subpath, url }) {
    const method = rq.method;
    const p = subpath || "/";

    if (method === "GET" && p === "/.well-known/oauth-protected-resource") {
      json(res, 200, mcpAuth.protectedResourceMetadata());
      return true;
    }
    if (method === "GET" && p === "/.well-known/oauth-authorization-server") {
      json(res, 200, lane.authorizationServerMetadata());
      return true;
    }
    if (method === "POST" && p === "/register") {
      const body = await readJsonBody(rq);
      try {
        json(res, 201, lane.handleRegister(body), { "cache-control": "no-store" });
      } catch (e) {
        tokenError(res, e);
      }
      return true;
    }
    if (method === "GET" && p === "/authorize") {
      try {
        const { redirect } = await lane.handleAuthorize(Object.fromEntries(url.searchParams));
        redirect302(res, redirect);
      } catch (e) {
        tokenError(res, e);
      }
      return true;
    }
    if (method === "GET" && p === "/authorize/return") {
      try {
        const { redirect } = await lane.handleAuthorizeReturn(Object.fromEntries(url.searchParams));
        redirect302(res, redirect);
      } catch (e) {
        // The authorization record is single-use: the consent page's auto-
        // redirect consumes it, then its manual "return to the app" link hits
        // this again with nothing left. The first hit already completed the
        // sign-in — so show a friendly "you're done" page, not a raw error.
        if (e instanceof McpAuthError && e.oauthError === "invalid_request") {
          res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
          res.end(returnDonePage());
        } else {
          tokenError(res, e);
        }
      }
      return true;
    }
    if (method === "POST" && p === "/token") {
      const raw = await readBody(rq);
      const ct = rq.headers["content-type"] || "";
      let params;
      if (ct.includes("application/json")) {
        try { params = JSON.parse(raw); } catch { params = {}; }
      } else {
        params = Object.fromEntries(new URLSearchParams(raw));
      }
      try {
        const out = await lane.handleToken(params);
        json(res, 200, out, { "cache-control": "no-store" });
      } catch (e) {
        tokenError(res, e);
      }
      return true;
    }
    if (p === "/mcp") {
      let vctx;
      try {
        vctx = await mcpAuth.authenticate(rq.headers.authorization);
      } catch (e) {
        const err = e instanceof McpAuthError ? e : new McpAuthError("invalid_token", e.message, 401);
        json(res, err.httpStatus, { error: err.oauthError, error_description: err.message }, {
          "www-authenticate": mcpAuth.challenge(),
        });
        return true;
      }
      // Grantor gate — refused BEFORE any tool runs (403). Roles mode (access
      // resolver): the grantor must have ≥1 tool granted here. Allowlist mode:
      // exact email match.
      const grantor = String(vctx.grantor || "").toLowerCase();
      let granted = "all";
      if (access) {
        granted = access(grantor);
        if (granted !== "all" && !(granted instanceof Set && granted.size)) {
          log(`[gate] REFUSED grantor=${vctx.grantor} (no role grants tools here)`);
          json(res, 403, {
            error: "access_denied",
            error_description: `'${vctx.grantor}' has no role granting tools on this server`,
          });
          return true;
        }
      } else if (!allow.has(grantor)) {
        log(`[gate] REFUSED grantor=${vctx.grantor} (not on the allowlist)`);
        json(res, 403, {
          error: "access_denied",
          error_description: `'${vctx.grantor}' is not on this gateway's allowlist`,
        });
        return true;
      }
      let body;
      if (method === "POST") {
        try { body = JSON.parse(await readBody(rq)); } catch { body = undefined; }
      }
      const proxy = buildProxyServer(vctx, granted);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => { transport.close(); proxy.close(); });
      await proxy.connect(transport);
      await transport.handleRequest(rq, res, body);
      return true;
    }
    return false;
  }

  async function close() {
    if (ownsChild) {
      // client.close() also closes its transport, which kills the child.
      try { await child.close(); } catch { /* best effort */ }
    }
    void childProc;
  }

  return {
    id: opts.meta?.id || null,
    slug: opts.meta?.slug || null,
    name,
    resource,
    broker: mcpAuth.broker,
    allow,
    tools,
    toolNames: tools.map((t) => t.name),
    scopesForTool,
    mcpAuth,
    lane,
    child,
    handle,
    close,
  };
}

// --- shared helpers (also used by gate.mjs / gateway.mjs) --------------------

export function req(o, k) {
  if (!o || o[k] == null || o[k] === "") throw new Error(`gate: '${k}' is required`);
  return o[k];
}

/** A short, side-effect-free digest of a tool's arguments for the audit line. */
export function argsDigest(args, max = 80) {
  if (args == null) return "-";
  let s;
  try { s = JSON.stringify(args); } catch { return "?"; }
  if (s === "{}" || s === undefined) return "-";
  return s.length > max ? `${s.slice(0, max)}…(${s.length}b)` : s;
}

export const json = (res, code, obj, headers = {}) => {
  res.writeHead(code, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
};

/** A friendly page for the already-consumed authorization return (a benign
 *  double-submit from the consent page's auto-nav + manual link). */
export function returnDonePage() {
  return `<!doctype html><meta charset=utf-8><title>All set</title>
<style>body{font:16px/1.6 -apple-system,system-ui,sans-serif;max-width:420px;margin:18vh auto;padding:0 24px;color:#1a1a1a;text-align:center}
.ok{font-size:40px}h1{font-size:20px;margin:.4em 0}p{color:#6b6b74}</style>
<div class="ok">✓</div>
<h1>You're all set</h1>
<p>This sign-in is complete — you can close this window and return to the app.
If the app didn't connect, add it again.</p>`;
}

export const redirect302 = (res, location) => {
  res.writeHead(302, { location });
  res.end();
};

export const tokenError = (res, e) => {
  if (e instanceof McpAuthError) return json(res, e.httpStatus, e.toTokenErrorResponse());
  throw e;
};

export async function readBody(rq, max = 1024 * 1024) {
  const chunks = [];
  let n = 0;
  for await (const c of rq) {
    n += c.length;
    if (n > max) throw new Error("body too large");
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function readJsonBody(rq) {
  try { return JSON.parse(await readBody(rq)); } catch { return {}; }
}

/** Set the standard CORS headers the gate uses on every response. Returns true
 *  if it fully handled an OPTIONS preflight (caller should stop). */
export function applyCors(rq, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "content-type, authorization, x-csrf-token, mcp-protocol-version, mcp-session-id, last-event-id"
  );
  res.setHeader("Access-Control-Expose-Headers", "www-authenticate, mcp-session-id");
  res.setHeader("Access-Control-Max-Age", "600");
  if (rq.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return true;
  }
  return false;
}

export { McpAuthError, spawn };
