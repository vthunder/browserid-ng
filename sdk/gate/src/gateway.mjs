// The multi-server gateway — the `--admin` console appliance. One Node HTTP
// server (auto-port, one 443 funnel) hosts N warrant-gated MCP endpoints plus a
// BrowserID-gated admin console that EDITS which servers run.
//
// Routing (src/gateway.mjs is the router; per-mount work lives in src/mount.mjs):
//   /  and /admin/*   → the admin console (login + config UI + config API)
//   /<slug>/*         → that mount's gated MCP endpoint (its own mcp-auth+lane)
//
// Each mount's `resource` = `<publicOrigin>/<slug>`, so mcp-auth path-prefixes
// every advertised OAuth URL for free. One shared gateway agent identity backs
// every mount's Lane B; audiences (and thus warrants + revocation) stay per
// mount.
//
// SECURITY — STAGED config (defense in depth). The console can only WRITE
// config.json; it NEVER spawns or kills a child. The running set of commands is
// fixed at STARTUP (and each command is printed to the terminal — that print IS
// the review checkpoint) and only changes on a restart (Ctrl-C + rerun). So
// even a login bypass is not immediate RCE: an attacker can edit config data,
// but the command they inject does not execute until the operator restarts at a
// terminal — a human-gated review the web attacker cannot trigger. The console
// surfaces "pending changes — restart to apply" so the admin knows a restart is
// needed. The login itself is the primary gate (exact audience + exact admin
// email, HMAC session cookie, CSRF on writes) — see src/session.mjs.
//
// Design: docs/plans/2026-08-12-gate-v2-admin-console.md (bean oxio).

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyPresentation } from "@browserid-ng/verify";
import { createMount, json, applyCors, readBody } from "./mount.mjs";
import { createSessionManager, parseCookies } from "./session.mjs";
import { loadConfig, saveConfig, normalizeMountDef } from "./config.mjs";
import { ensureFunnel } from "./tunnel.mjs";

const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "public");

/**
 * @param {object} opts  see index.d.ts (GatewayOptions).
 */
export function createGateway(opts) {
  const adminEmail = String(reqOpt(opts, "adminEmail")).trim().toLowerCase();
  const credential = reqOpt(opts, "credential");
  const broker = (opts.broker || "https://browserid.me").replace(/\/+$/, "");
  const doFetch = opts.fetch || globalThis.fetch;
  const log = opts.log || ((l) => console.log(l));
  const statusCacheS = opts.statusCacheS ?? 5;
  const consoleLocal = !!opts.consoleLocal;
  const persist = opts.persist ?? !opts.config;
  const funnelFn = opts.ensureFunnel || ensureFunnel;

  const mounts = new Map(); // slug -> live mount (spawned at startup, fixed)
  const byId = new Map(); // id -> live mount
  let startupDefs = []; // snapshot of config at startup (for the pending diff)
  let config = opts.config ? { mounts: (opts.config.mounts || []).map((m) => ({ ...m })) } : loadConfig();

  let publicOrigin = opts.origin ? String(opts.origin).replace(/\/+$/, "") : null;
  let port = null;
  let publicServer = null;
  let localServer = null;

  const adminSecure = () => (consoleLocal ? false : String(publicOrigin || "").startsWith("https"));
  let sessions = createSessionManager({ secret: opts.sessionSecret, ttlS: opts.sessionTtlS, secure: adminSecure() });

  // --- startup spawning (the ONLY place a child is ever spawned) ------------

  async function spawnMount(def) {
    const resource = `${publicOrigin}/${def.mount}`;
    log(`[gate] starting mount /${def.mount} → ${def.command.join(" ")}`);
    const mount = await createMount({
      resource,
      credential,
      allow: def.allow,
      name: def.name,
      child: { command: def.command[0], args: def.command.slice(1) },
      broker,
      statusCacheS,
      fetch: doFetch,
      log,
      meta: { id: def.id, slug: def.mount },
    });
    mounts.set(def.mount, mount);
    byId.set(def.id, mount);
    log(`[gate] mounted /${def.mount} → ${resource}/mcp (${mount.toolNames.length} tools)`);
    return mount;
  }

  // --- config editing (STAGED — persist only, never touches live children) --

  function persistConfig() { if (persist) saveConfig(config); }

  function addMount(rawDef) {
    const def = normalizeMountDef(rawDef);
    if (config.mounts.some((m) => m.mount === def.mount)) {
      throw badRequest(`mount path '${def.mount}' is already in use`);
    }
    config.mounts.push(def);
    persistConfig();
    return statusRow(def);
  }

  function updateMount(id, patch) {
    const def = config.mounts.find((m) => m.id === id);
    if (!def) throw notFound("no such mount");
    if (patch.name != null) def.name = String(patch.name).trim() || def.name;
    if (Array.isArray(patch.allow)) {
      def.allow = [...new Set(patch.allow.map((e) => String(e).trim().toLowerCase()).filter(Boolean))];
    }
    if (Array.isArray(patch.command) || typeof patch.command === "string") {
      // Re-validate via normalize (also tokenizes a string form to argv).
      def.command = normalizeMountDef({ ...def, command: patch.command }).command;
    }
    if (patch.enabled != null) def.enabled = !!patch.enabled;
    persistConfig();
    return statusRow(def);
  }

  function removeMount(id) {
    const idx = config.mounts.findIndex((m) => m.id === id);
    if (idx < 0) throw notFound("no such mount");
    config.mounts.splice(idx, 1);
    persistConfig();
    return true;
  }

  // --- status: running (startup) vs saved (config), with the pending diff ---

  const sig = (d) => JSON.stringify({ mount: d.mount, command: d.command, allow: [...d.allow].sort(), enabled: d.enabled !== false });

  /** One row per mount id present in either the saved config or the running
   *  set, tagged with its pending state relative to startup. */
  function statusRow(savedDef) {
    const id = savedDef.id;
    const startDef = startupDefs.find((m) => m.id === id) || null;
    const live = byId.get(id) || null;
    let pending = null; // null | "new" | "changed" | "removed"
    if (!startDef) pending = "new";
    else if (sig(savedDef) !== sig(startDef)) pending = "changed";
    return {
      id,
      name: savedDef.name,
      mount: savedDef.mount,
      url: `${publicOrigin}/${savedDef.mount}/mcp`,
      command: savedDef.command,
      allow: savedDef.allow,
      allowCount: savedDef.allow.length,
      enabled: savedDef.enabled !== false,
      running: !!live,
      tools: live ? live.toolNames : [],
      toolCount: live ? live.toolNames.length : 0,
      pending, // "new"/"changed" — needs a restart to take effect
    };
  }

  function listMounts() {
    const rows = config.mounts.map(statusRow);
    // Startup mounts that are no longer in the saved config = pending removals;
    // they keep running until restart, so surface them too.
    for (const s of startupDefs) {
      if (!config.mounts.some((m) => m.id === s.id)) {
        const live = byId.get(s.id);
        rows.push({
          id: s.id, name: s.name, mount: s.mount, url: `${publicOrigin}/${s.mount}/mcp`,
          command: s.command, allow: s.allow, allowCount: s.allow.length,
          enabled: false, running: !!live, tools: live ? live.toolNames : [],
          toolCount: live ? live.toolNames.length : 0, pending: "removed",
        });
      }
    }
    const pendingCount = rows.filter((r) => r.pending).length;
    return { mounts: rows, pending: pendingCount, needsRestart: pendingCount > 0 };
  }

  // --- HTTP router ----------------------------------------------------------

  async function route(rq, res, { adminAllowed }) {
    const url = new URL(rq.url, publicOrigin || `http://${rq.headers.host}`);
    const path = url.pathname;
    res.on("finish", () => log(`[gate] ${rq.method} ${path} → ${res.statusCode}`));
    if (applyCors(rq, res)) return;

    try {
      if (rq.method === "GET" && path === "/healthz") return json(res, 200, { ok: true, mounts: mounts.size });

      if (path === "/" || path === "/admin" || path.startsWith("/admin/")) {
        if (!adminAllowed) return json(res, 404, { error: "not_found" });
        return admin(rq, res, { url, path, adminOrigin: adminOriginFor(rq) });
      }

      // RFC 8414 / RFC 9728 PATH-INSERTED discovery: a mount's OAuth issuer is
      // `<origin>/<mount>`, so a spec client (claude.ai) fetches the metadata at
      // `/.well-known/<doc>/<mount>` (inserted), NOT `/<mount>/.well-known/<doc>`
      // (suffixed — what mcp-auth's URLs use). For a root single-server the two
      // coincide; for a mount they differ. Serve the inserted form by rewriting
      // to the suffixed subpath the mount already handles.
      const wk = /^\/\.well-known\/(oauth-authorization-server|oauth-protected-resource)\/([^/]+)$/.exec(path);
      if (rq.method === "GET" && wk) {
        const m = mounts.get(wk[2]);
        if (m) {
          const handled = await m.handle(rq, res, { subpath: `/.well-known/${wk[1]}`, url });
          if (!handled) json(res, 404, { error: "not_found" });
          return;
        }
        return json(res, 404, { error: "not_found" });
      }

      const seg = path.slice(1).split("/")[0];
      const mount = mounts.get(seg);
      if (mount) {
        const subpath = path.slice(seg.length + 1) || "/";
        const handled = await mount.handle(rq, res, { subpath, url });
        if (!handled) json(res, 404, { error: "not_found" });
        return;
      }
      json(res, 404, { error: "not_found" });
    } catch (e) {
      console.error(`[gate] ${rq.method} ${path}:`, e);
      if (!res.headersSent) json(res, 500, { error: "server_error" });
    }
  }

  // Login audience = the origin the admin's browser actually used. Public
  // listener → the pinned funnel origin (never the client Host header, to avoid
  // audience confusion). Local listener → the loopback Host (already trusted).
  function adminOriginFor(rq) {
    return consoleLocal ? `http://${rq.headers.host}` : publicOrigin;
  }

  // --- admin console --------------------------------------------------------

  async function admin(rq, res, { path, adminOrigin }) {
    if (rq.method === "GET" && (path === "/" || path === "/admin" || path === "/admin/")) {
      return serveStatic(res, "index.html", "text/html; charset=utf-8");
    }
    if (rq.method === "GET" && path === "/admin/app.js") return serveStatic(res, "app.js", "text/javascript; charset=utf-8");
    if (rq.method === "GET" && path === "/admin/style.css") return serveStatic(res, "style.css", "text/css; charset=utf-8");

    if (rq.method === "GET" && path === "/admin/bootstrap") {
      const s = sessions.verify(parseCookies(rq.headers.cookie));
      const signedIn = !!s && s.email.toLowerCase() === adminEmail;
      return json(res, 200, { broker, origin: adminOrigin, signedIn, admin: signedIn ? s.email : null });
    }

    // Login — the security gate.
    if (rq.method === "POST" && path === "/admin/login") {
      const body = await readJson(rq);
      const presentation = body?.presentation;
      if (!presentation || typeof presentation !== "string") {
        return json(res, 400, { error: "invalid_request", error_description: "missing presentation" });
      }
      const result = await verifyPresentation(presentation, adminOrigin, {
        verifierUrl: `${broker}/verify-access`,
        fetch: doFetch,
      });
      if (!result.ok) {
        return json(res, 403, { error: "access_denied", error_description: `verification failed: ${result.reason}` });
      }
      if (String(result.email).toLowerCase() !== adminEmail) {
        log(`[gate] admin login DENIED for ${result.email} (not ${adminEmail})`);
        return json(res, 403, { error: "access_denied", error_description: "not the admin identity" });
      }
      const { csrf, setCookies } = sessions.issue(result.email);
      res.setHeader("Set-Cookie", setCookies);
      log(`[gate] admin login OK for ${result.email}`);
      return json(res, 200, { ok: true, admin: result.email, csrf });
    }

    // Below: valid admin session required (fail closed).
    const session = requireSession(rq, res);
    if (!session) return;

    if (rq.method === "GET" && path === "/admin/whoami") {
      return json(res, 200, { admin: session.email, host: publicOrigin, csrf: sessions.csrfForNonce(session.nonce) });
    }
    if (rq.method === "POST" && path === "/admin/logout") {
      if (!requireCsrf(rq, res, session)) return;
      res.setHeader("Set-Cookie", sessions.clearCookies());
      return json(res, 200, { ok: true });
    }

    if (path === "/admin/mounts") {
      if (rq.method === "GET") return json(res, 200, listMounts());
      if (rq.method === "POST") {
        if (!requireCsrf(rq, res, session)) return;
        try { return json(res, 201, { ...addMount(await readJson(rq)), needsRestart: true }); }
        catch (e) { return json(res, e.status || 400, { error: "invalid_request", error_description: e.message }); }
      }
    }
    const m = /^\/admin\/mounts\/([^/]+)$/.exec(path);
    if (m) {
      const id = decodeURIComponent(m[1]);
      if (rq.method === "PATCH") {
        if (!requireCsrf(rq, res, session)) return;
        try { return json(res, 200, { ...updateMount(id, await readJson(rq)), needsRestart: true }); }
        catch (e) { return json(res, e.status || 400, { error: "invalid_request", error_description: e.message }); }
      }
      if (rq.method === "DELETE") {
        if (!requireCsrf(rq, res, session)) return;
        try { removeMount(id); return json(res, 200, { ok: true, needsRestart: true }); }
        catch (e) { return json(res, e.status || 400, { error: "invalid_request", error_description: e.message }); }
      }
    }
    json(res, 404, { error: "not_found" });
  }

  function requireSession(rq, res) {
    const session = sessions.verify(parseCookies(rq.headers.cookie));
    if (!session || session.email.toLowerCase() !== adminEmail) {
      json(res, 401, { error: "unauthorized", error_description: "admin session required" });
      return null;
    }
    return session;
  }
  function requireCsrf(rq, res, session) {
    const token = rq.headers["x-csrf-token"];
    if (!sessions.checkCsrf(session, Array.isArray(token) ? token[0] : token)) {
      json(res, 403, { error: "forbidden", error_description: "missing or invalid CSRF token" });
      return false;
    }
    return true;
  }
  async function serveStatic(res, file, type) {
    try {
      const buf = await readFile(join(PUBLIC_DIR, file));
      res.writeHead(200, { "content-type": type, "cache-control": "no-cache" });
      res.end(buf);
    } catch { json(res, 404, { error: "not_found" }); }
  }
  async function readJson(rq) { try { return JSON.parse(await readBody(rq)); } catch { return {}; } }

  // --- start / stop ---------------------------------------------------------

  async function start(startOpts = {}) {
    const wantPort = startOpts.port ?? 0;
    publicServer = createServer((rq, res) => route(rq, res, { adminAllowed: !consoleLocal }));
    await listen(publicServer, wantPort, consoleLocal ? "0.0.0.0" : undefined);
    port = publicServer.address().port;

    if (consoleLocal) {
      localServer = createServer((rq, res) => route(rq, res, { adminAllowed: true }));
      await listen(localServer, 0, "127.0.0.1");
    }

    if (!publicOrigin) publicOrigin = (await funnelFn(port)).replace(/\/+$/, "");
    sessions = createSessionManager({ secret: opts.sessionSecret, ttlS: opts.sessionTtlS, secure: adminSecure() });

    // Snapshot the config as the immutable "running set", then spawn enabled
    // entries. Nothing spawned after this until a restart.
    startupDefs = config.mounts.map((m) => ({ ...m, allow: [...m.allow], command: [...m.command] }));
    for (const def of startupDefs) {
      if (def.enabled === false) { log(`[gate] mount /${def.mount} is disabled — not started`); continue; }
      try { await spawnMount(def); }
      catch (e) { log(`[gate] FAILED to start mount /${def.mount}: ${e.message}`); }
    }

    const consoleUrl = consoleLocal ? `http://127.0.0.1:${localServer.address().port}/` : `${publicOrigin}/`;
    return { origin: publicOrigin, port, consoleUrl, localPort: localServer?.address().port || null };
  }

  async function close() {
    for (const id of [...byId.keys()]) {
      const mount = byId.get(id);
      byId.delete(id);
      mounts.delete(mount.slug);
      try { await mount.close(); } catch { /* best effort */ }
    }
    for (const s of [publicServer, localServer]) {
      if (!s) continue;
      try { s.closeAllConnections?.(); } catch { /* best effort */ }
      await new Promise((r) => s.close(r));
    }
    publicServer = localServer = null;
  }

  return {
    start, close, addMount, updateMount, removeMount, listMounts,
    get origin() { return publicOrigin; },
    get port() { return port; },
    get publicServer() { return publicServer; },
    get localServer() { return localServer; },
    get sessions() { return sessions; },
    get mounts() { return mounts; },
    adminEmail, broker,
  };
}

// --- helpers ----------------------------------------------------------------

function reqOpt(o, k) {
  if (!o || o[k] == null || o[k] === "") throw new Error(`gate/gateway: '${k}' is required`);
  return o[k];
}
function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => { server.off("error", reject); resolve(); });
  });
}
function badRequest(msg) { const e = new Error(msg); e.status = 400; return e; }
function notFound(msg) { const e = new Error(msg); e.status = 404; return e; }
