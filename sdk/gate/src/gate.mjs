// @browserid-ng/gate — wrap ANY stdio MCP server as a remote, BrowserID-gated
// HTTP endpoint (the single-server / library mode).
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
// v0.3 refactored the per-server machinery into a reusable `mount` (src/mount.mjs)
// that the multi-server gateway (src/gateway.mjs, the `--admin` console) also
// uses. Since v0.5 the CLI runs ONLY the console; `createGateService` remains
// the single-server LIBRARY entry point (allowlist-based) for embedders and
// the tests.
//
// Design: docs/plans/2026-08-12-gate-v2-admin-console.md (bean oxio),
//         docs/plans/2026-08-12-mcp-gateway-hobbyist-to-saas.md (bean in36).

import { createServer } from "node:http";
import { createMount, argsDigest, json, applyCors } from "./mount.mjs";
import { createSessionManager } from "./session.mjs";
import { createConnectAuth } from "./connectauth.mjs";

/**
 * Build (and connect) a single-server gate around a stdio MCP child.
 *
 * @param {object} opts  See index.d.ts (GateOptions).
 * @returns {Promise<{server, mcpAuth, lane, tools, scopesForTool, allow, resource, broker, close}>}
 */
export async function createGateService(opts) {
  const name = opts.name || "mcp gateway";
  const log = opts.log || ((line) => console.log(line));

  // Identity-first connect (policy mode): the member login lives at this
  // origin's /connect/*; sessions are HMAC cookies like the console's.
  let connectAuth = null;
  if (opts.owners?.length) {
    const secure = String(opts.resource || "").startsWith("https");
    const sessions = createSessionManager({
      secret: opts.sessionSecret, ttlS: opts.sessionTtlS, secure, cookieName: "gate_user",
    });
    connectAuth = createConnectAuth({
      broker: (opts.broker || "https://browserid.me").replace(/\/+$/, ""),
      origin: () => String(opts.resource).replace(/\/+$/, ""),
      sessions,
      fetch: opts.fetch || globalThis.fetch,
    });
  }

  // The single mount serves at the resource root (no path prefix).
  const mount = await createMount({
    resource: opts.resource,
    credential: opts.credential,
    owners: opts.owners,
    policyStore: opts.policyStore,
    userFor: connectAuth ? (rq) => connectAuth.userFor(rq) : undefined,
    entitlementFor: opts.entitlementFor,
    allow: opts.allow,
    name,
    child: opts.child,
    client: opts.client,
    broker: opts.broker,
    statusCacheS: opts.statusCacheS,
    fetch: opts.fetch,
    log,
  });

  const server = createServer(async (rq, res) => {
    const url = new URL(rq.url, mount.resource);
    const path = url.pathname;
    res.on("finish", () => log(`[gate] ${rq.method} ${path} → ${res.statusCode}`));
    if (applyCors(rq, res)) return;
    try {
      if (rq.method === "GET" && path === "/healthz") return json(res, 200, { ok: true });
      if (rq.method === "GET" && path === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        return res.end(landingHtml({ name, broker: mount.broker, tools: mount.tools, allow: mount.allow }));
      }
      // Identity-first connect: the member login at the origin.
      if (connectAuth && (path === "/connect/login" || path === "/connect/logout")) {
        if (await connectAuth.handle(rq, res, { path, url })) return;
      }
      // Everything else is a mount subpath at the root.
      const handled = await mount.handle(rq, res, { subpath: path, url });
      if (!handled) json(res, 404, { error: "not_found" });
    } catch (e) {
      console.error(`[gate] ${rq.method} ${path}:`, e);
      if (!res.headersSent) json(res, 500, { error: "server_error" });
    }
  });

  async function close() {
    try { server.close(); } catch { /* best effort */ }
    await mount.close();
  }

  return {
    server,
    mcpAuth: mount.mcpAuth,
    lane: mount.lane,
    tools: mount.tools,
    scopesForTool: mount.scopesForTool,
    allow: mount.allow,
    resource: mount.resource,
    broker: mount.broker,
    close,
  };
}

export { argsDigest };
// v0.3 multi-server gateway + admin console, and the config-store helpers.
export { createGateway } from "./gateway.mjs";
export { configPath, loadConfig, saveConfig, normalizeConfig, normalizeMountDef, normalizePersonDef, normalizeGrants, tokenizeArgv } from "./config.mjs";

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
