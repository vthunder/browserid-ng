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
import { createMcpAuth, createAuthCodeLane, McpAuthError, identityEq, granteeCovers } from "@browserid-ng/mcp-auth";

/**
 * Build (and connect) a mount around a stdio MCP child.
 *
 * @param {object} opts
 * @param {string} opts.resource      Canonical URL of THIS mount (OAuth resource + audience).
 * @param {object} [opts.credential]  The gateway's device credential — the
 *                                    agent-mode FALLBACK only. With a broker
 *                                    that supports connection grants the
 *                                    mount is fully credential-less.
 * @param {string[]} [opts.owners]    Policy owners (spec §6.5): admission then
 *                                    requires the connecting identity to be an
 *                                    owner or covered by an owner-signed policy
 *                                    record (share via lane.requestAuthoring);
 *                                    supersedes `allow` at the grantor gate.
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
  const owners = (opts.owners || []).map((e) => String(e).trim()).filter(Boolean);
  // Record-policy admission at the lane (§6.5). Library default: owners ⇒
  // signed; the gateway passes an explicit false in local-roles mode (the
  // identity-first flow is identical either way — only the entitlement
  // source changes).
  const signedGrants = opts.signedGrants ?? owners.length > 0;
  // Identity-first connect (policy mode): who is signed in at the gate, and
  // what do the held records entitle them to HERE. The gateway passes both;
  // the single-server gate gets a default that reads the policy store.
  const userFor = typeof opts.userFor === "function" ? opts.userFor : () => null;
  const entitlementFor =
    typeof opts.entitlementFor === "function"
      ? opts.entitlementFor
      : async (email) => {
          if (owners.some((o) => identityEq(o, email))) return "all";
          // The lane's store when none was injected (single-server default) —
          // rows landed by lane.requestAuthoring must be the ones read here.
          const store = opts.policyStore || lane.policyStore;
          if (!store) return null;
          const rows = (await store.list(resource)).filter((r) => granteeCovers(r.grantee, email));
          if (!rows.length) return null;
          return [...new Set(rows.flatMap((r) => r.scopes || []))];
        };

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
  const lane = createAuthCodeLane({
    mcpAuth,
    ...(opts.credential ? { credential: opts.credential } : {}),
    ...(owners.length && signedGrants ? { policy: { owners, store: opts.policyStore } } : {}),
    broker,
    fetch: doFetch,
    label: name,
  });

  function attribute(ctx, tool, args) {
    // §6.5 audit shape: the actor, via their connection, under the
    // permitter's grant — the permitter is the reason, never the author.
    const under = ctx.permittedBy ? ` under=${ctx.permittedBy}` : "";
    log(`[gate] grantor=${ctx.grantor} grantee=${ctx.grantee}${under} tool=${tool} args=${argsDigest(args)}`);
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
              `ACCESS_DENIED — your access here doesn't include '${toolName}'. ` +
              `Ask the person who runs this gateway to share it with you.`,
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

    // Connection mode (spec §7.5): the audience-proof document. Reaches a
    // mount directly only in the single-server case (resource == origin);
    // the gateway serves it at origin scope via its own fan-out route.
    if (method === "GET" && p.startsWith("/.well-known/browserid-audience-proof/")) {
      const id = p.slice("/.well-known/browserid-audience-proof/".length);
      const body = lane.handleAudienceProof(id);
      if (body == null) {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        res.end("no such pending request");
      } else {
        res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
        res.end(body);
      }
      return true;
    }
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
        // Identity-first (policy mode): authenticate the connecting user at
        // THIS gate before raising any broker request — then the request is
        // pinned to their identity and scoped to their actual entitlement,
        // and strangers are refused before any consent ceremony.
        let authCtx = null;
        if (owners.length) {
          const user = userFor(rq);
          if (!user) {
            const next = `${resource}/authorize?${url.searchParams.toString()}`;
            redirect302(res, `/connect/login?next=${encodeURIComponent(next)}`);
            return true;
          }
          // A live gate session never bounces SILENTLY: say who is
          // connecting and offer the switch — one click to continue, so a
          // second mount stays nearly free, but never invisible identity.
          if (!url.searchParams.get("gate_continue")) {
            const params = new URLSearchParams(url.searchParams);
            params.set("gate_continue", "1");
            const continueUrl = `${resource}/authorize?${params.toString()}`;
            const switchUrl = `/connect/login?next=${encodeURIComponent(continueUrl)}&switch=1`;
            res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
            res.end(continueAsPage(user, name, continueUrl, switchUrl));
            return true;
          }
          const ent = await entitlementFor(user);
          if (ent == null) {
            res.writeHead(403, { "content-type": "text/html; charset=utf-8" });
            res.end(noAccessPage(user, name));
            return true;
          }
          const entScopes = ent === "all"
            ? [...new Set(Object.values(scopesForTool).flat())]
            : ent;
          const requested = String(url.searchParams.get("scope") || "").split(/\s+/).filter(Boolean);
          const scopes = requested.length ? requested.filter((sc) => entScopes.includes(sc)) : entScopes;
          authCtx = { grantor: user, scopes };
        }
        const { redirect } = await lane.handleAuthorize(Object.fromEntries(url.searchParams), authCtx);
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
      if (owners.length) {
        // Policy mode (§6.5): the grantor must be an owner or covered by a
        // held policy record — enforced for EVERY bearer (the jwt-bearer
        // lane's self-signed warrant scopes are not an entitlement); tool
        // visibility then derives from the bearer's effective scopes (the
        // record ∩ connection intersection for connection bearers).
        const ent = await entitlementFor(grantor);
        if (ent == null) {
          log(`[gate] REFUSED grantor=${vctx.grantor} (no grant covers them here)`);
          json(res, 403, {
            error: "access_denied",
            error_description: `no grant covers '${vctx.grantor}' on this server`,
          });
          return true;
        }
        // Effective tools = bearer scopes ∩ the record entitlement (S ∩ S′).
        // Connection bearers already carry the intersection; jwt-bearer
        // scopes are warrant-asserted, so the entitlement must cut here too.
        granted = new Set(
          tools
            .filter((t) => {
              const need = scopesForTool[t.name] || [];
              return (
                need.every((sc) => vctx.scopes.includes(sc)) &&
                (ent === "all" || need.every((sc) => ent.includes(sc)))
              );
            })
            .map((t) => t.name)
        );
      } else if (access) {
        granted = access(grantor);
        if (granted !== "all" && !(granted instanceof Set && granted.size)) {
          log(`[gate] REFUSED grantor=${vctx.grantor} (no role grants tools here)`);
          json(res, 403, {
            error: "access_denied",
            error_description: `'${vctx.grantor}' has no role granting tools on this server`,
          });
          return true;
        }
      } else if (!owners.length && !allow.has(grantor)) {
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

/** The identity interstitial: a live gate session is visible, never silent —
 *  confirm who's connecting or switch accounts before anything is asked on
 *  their behalf. */
export function continueAsPage(email, serverName, continueUrl, switchUrl) {
  const esc = (x) => String(x).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Connect — ${esc(serverName)}</title>
<style>body{font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:420px;margin:16vh auto;padding:0 24px;color:#1a1a1a;text-align:center}
.btn{display:inline-block;font:600 15px system-ui;padding:11px 22px;border-radius:10px;border:0;background:#17171a;color:#fff;cursor:pointer;text-decoration:none}
.alt{display:block;margin-top:14px;font-size:13.5px;color:#6b6b74}</style>
<h1 style="font-size:20px">Connect to ${esc(serverName)}</h1>
<p>You're signed in here as <b>${esc(email)}</b>. The next screen shows exactly
what this connection may do as that identity.</p>
<a class="btn" id="continue" href="${esc(continueUrl)}">Continue as ${esc(email)}</a>
<a class="alt" id="switch" href="${esc(switchUrl)}">Use a different account</a>`;
}

/** Refusal page for a signed-in user with no grants here (identity-first
 *  connect: refused BEFORE any consent ceremony). */
export function noAccessPage(email, serverName) {
  const esc = (x) => String(x).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  return `<!doctype html><meta charset=utf-8><title>No access</title>
<style>body{font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:440px;margin:16vh auto;padding:0 24px;color:#1a1a1a;text-align:center}p{color:#6b6b74}</style>
<h1 style="font-size:20px">You don't have access to ${esc(serverName)}</h1>
<p>You're signed in as <b>${esc(email)}</b>, but nothing has been shared with
that address here. Ask the person who runs this gateway to share it with you,
then connect again.</p>`;
}

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
