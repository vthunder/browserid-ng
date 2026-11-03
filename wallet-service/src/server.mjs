#!/usr/bin/env node
// browserid-ng hosted wallet — HTTP entry point.
//
//   /mcp                                   the remote MCP endpoint (bearer-authed)
//   /authorize, /oauth/*                   the embedded OAuth 2.1 AS
//   /.well-known/oauth-*                   RFC 9728 / RFC 8414 discovery
//   /                                      landing page; /healthz for probes
//
// Design: docs/plans/2026-07-29-hosted-wallet-remote-mcp-design.md
import { createServer } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createVerifier } from "@browserid-ng/verify";
import {
  PORT, WALLET_ORIGIN, BROKER, VERIFIER_URL, DATABASE_PATH, KEK, PRODUCTION,
} from "./config.mjs";
import { openDb } from "./db.mjs";
import { EnvKeyWrapper } from "./custody.mjs";
import { WalletStore } from "./store.mjs";
import { Audit } from "./audit.mjs";
import {
  protectedResourceMetadata, authorizationServerMetadata, registerClient, getClient,
  checkAuthorizeRequest, approveAuthorization, tokenGrant, authenticateBearer,
  wwwAuthenticate, signSession, verifySession, sessionCookie,
  revokeToken, disconnectAll, listConnections,
} from "./oauth.mjs";
import { createWalletMcpServer } from "./mcp.mjs";
import { authorizePage, landingPage, accountPage } from "./pages.mjs";

export function createWalletService({ verifyLogin, checkStatus } = {}) {
  const db = openDb(DATABASE_PATH);
  const store = new WalletStore(db, new EnvKeyWrapper(KEK));
  const audit = new Audit(db);
  const verifier = createVerifier({ verifierUrl: VERIFIER_URL });
  // The sign-in's revocation re-check (spec §6.4; audit 2026-11 D13): run
  // before a session approves a connection and at every token refresh.
  // Fail-closed by contract: anything but {ok:true, revoked:false} refuses.
  const recheck = checkStatus || ((refs) => verifier.checkStatus(refs));
  // Injectable for tests; production verifies at the broker's hosted verifier.
  // Human sign-in only (decision Q16 (a), audit 2026-11 W4-22): the verifier
  // cannot tell humans from agents, so /oauth/login itself requires the
  // presentation to be self-asserted (grantee == email) AND to carry the
  // `login` scope. A delegated presentation never opens the human's tenant.
  const verify = verifyLogin || ((presentation) => verifier.verify(presentation, WALLET_ORIGIN));
  const hasLoginScope = (scopes) =>
    Array.isArray(scopes) &&
    scopes.some((s) => s === "login" || (s && typeof s === "object" && s.scope === "login"));
  const humanLoginRefusal = (r) => {
    if (typeof r.grantee !== "string" || r.grantee !== r.email) return "delegated presentation: this wallet signs in the account holder only";
    if (!hasLoginScope(r.scopes)) return "presentation does not carry the login scope";
    return null;
  };

  // -- tiny fixed-window rate limiter (per key per route class) --------------
  const buckets = new Map(); // key -> { windowStart, count }
  function limited(key, max, windowMs = 60_000) {
    const now = Date.now();
    const b = buckets.get(key);
    if (!b || now - b.windowStart > windowMs) {
      buckets.set(key, { windowStart: now, count: 1 });
      return false;
    }
    return ++b.count > max;
  }
  setInterval(() => {
    const cutoff = Date.now() - 300_000;
    for (const [k, b] of buckets) if (b.windowStart < cutoff) buckets.delete(k);
  }, 300_000).unref();
  setInterval(() => audit.prune(), 6 * 60 * 60 * 1000).unref();

  const json = (res, code, obj, headers = {}) => {
    res.writeHead(code, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(obj));
  };
  const html = (res, code, body) => {
    res.writeHead(code, {
      "content-type": "text/html; charset=utf-8",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    });
    res.end(body);
  };
  const readBody = (req, limit = 256 * 1024) =>
    new Promise((resolve, reject) => {
      let d = "";
      req.on("data", (c) => {
        d += c;
        if (d.length > limit) { reject(new Error("body too large")); req.destroy(); }
      });
      req.on("end", () => resolve(d));
      req.on("error", reject);
    });
  const clientIp = (req) =>
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "?";
  // Browser-facing state-changing endpoints: same-origin only (CSRF).
  const badOrigin = (req) => req.headers.origin && req.headers.origin !== WALLET_ORIGIN;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, WALLET_ORIGIN);
    const path = url.pathname.replace(/\/$/, "") || "/";
    const ip = clientIp(req);

    try {
      // ---- discovery + pages ----
      if (req.method === "GET" && path === "/") return html(res, 200, landingPage());
      if (req.method === "GET" && path === "/healthz") return json(res, 200, { ok: true });
      if (req.method === "GET" && path === "/.well-known/oauth-protected-resource")
        return json(res, 200, protectedResourceMetadata());
      if (req.method === "GET" && path === "/.well-known/oauth-authorization-server")
        return json(res, 200, authorizationServerMetadata());

      // ---- OAuth AS ----
      if (req.method === "POST" && path === "/oauth/register") {
        if (limited(`reg:${ip}`, 10)) return json(res, 429, { error: "rate_limited" });
        let body;
        try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: "invalid_client_metadata" }); }
        const out = registerClient(db, body);
        return json(res, out.error ? 400 : 201, out);
      }

      if (req.method === "GET" && path === "/authorize") {
        const q = Object.fromEntries(url.searchParams);
        const check = checkAuthorizeRequest(db, q);
        if (!check.ok) return html(res, check.status, `<!doctype html><p>Invalid authorization request: ${check.error}</p>`);
        return html(res, 200, authorizePage({ clientName: check.client.name }));
      }

      if (req.method === "POST" && path === "/oauth/login") {
        if (badOrigin(req)) return json(res, 403, { reason: "cross-origin" });
        if (limited(`login:${ip}`, 20)) return json(res, 429, { reason: "rate limited" });
        let presentation;
        try { ({ presentation } = JSON.parse(await readBody(req))); } catch {}
        const r = await verify(presentation);
        if (!r.ok) return json(res, 401, { reason: r.reason });
        const refusal = humanLoginRefusal(r);
        if (refusal) {
          audit.log(r.email, "account.login_refused", { ip, detail: refusal });
          return json(res, 401, { reason: refusal });
        }
        store.ensureAccount(r.email);
        audit.log(r.email, "account.login", { ip });
        return json(res, 200, { email: r.email }, { "set-cookie": sessionCookie(signSession(r.email, r.statusRefs)) });
      }

      if (req.method === "GET" && path === "/oauth/me") {
        const s = verifySession(req.headers.cookie);
        return json(res, 200, s ? { email: s.email } : {});
      }

      // A session may act (approve a connection, disconnect) only while the
      // sign-in behind it is provably unrevoked.
      const liveSession = async () => {
        const s = verifySession(req.headers.cookie);
        if (!s) return { error: "not signed in", status: 401 };
        const st = await recheck(Array.isArray(s.refs) ? s.refs : []);
        if (!st || st.ok !== true) return { error: "sign-in status unavailable (fail-closed)", status: 503 };
        if (st.revoked === true) return { error: "sign-in revoked; sign in again", status: 401 };
        return { session: s };
      };

      if (req.method === "POST" && path === "/oauth/approve") {
        if (badOrigin(req)) return json(res, 403, { error: "cross-origin" });
        const live = await liveSession();
        if (!live.session) return json(res, live.status, { error: live.error });
        const s = live.session;
        let params;
        try { params = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: "bad request" }); }
        const out = approveAuthorization(db, s.email, params, s.refs);
        if (!out.ok) return json(res, out.status ?? 400, { error: out.error });
        audit.log(s.email, "oauth.connect", { clientId: params.client_id, ip });
        return json(res, 200, { redirect: out.redirect });
      }

      if (req.method === "POST" && path === "/oauth/token") {
        if (limited(`token:${ip}`, 60)) return json(res, 429, { error: "rate_limited" });
        const form = Object.fromEntries(new URLSearchParams(await readBody(req)));
        const out = await tokenGrant(db, form, { checkStatus: recheck });
        if (out.error) return json(res, 400, out);
        const { account_email, ...body } = out;
        audit.log(account_email, "oauth.token", { clientId: form.client_id, ip, detail: form.grant_type });
        return json(res, 200, body);
      }

      // RFC 7009: a client (or the human holding a token) ends the connection.
      if (req.method === "POST" && path === "/oauth/revoke") {
        if (limited(`revoke:${ip}`, 60)) return json(res, 429, { error: "rate_limited" });
        const form = Object.fromEntries(new URLSearchParams(await readBody(req)));
        const out = revokeToken(db, form);
        if (out.error) return json(res, 400, out);
        if (out.account_email) audit.log(out.account_email, "oauth.revoke", { clientId: form.client_id, ip, detail: `${out.revoked} tokens` });
        return json(res, 200, {});
      }

      // The tenant's own lever: see connected clients, disconnect them all.
      if (req.method === "GET" && path === "/account") return html(res, 200, accountPage());
      if (req.method === "GET" && path === "/oauth/connections") {
        const s = verifySession(req.headers.cookie);
        if (!s) return json(res, 401, { error: "not signed in" });
        return json(res, 200, { email: s.email, connections: listConnections(db, s.email) });
      }
      if (req.method === "POST" && path === "/oauth/disconnect") {
        if (badOrigin(req)) return json(res, 403, { error: "cross-origin" });
        const live = await liveSession();
        if (!live.session) return json(res, live.status, { error: live.error });
        const out = disconnectAll(db, live.session.email);
        audit.log(live.session.email, "oauth.disconnect_all", { ip, detail: `${out.revoked} tokens` });
        return json(res, 200, { ok: true, revoked: out.revoked });
      }

      // ---- the MCP endpoint (RS) ----
      if (path === "/mcp") {
        const tenant = authenticateBearer(db, req.headers.authorization);
        if (!tenant) {
          return json(res, 401, { error: "unauthorized" }, { "www-authenticate": wwwAuthenticate() });
        }
        if (limited(`mcp:${tenant.email}`, 120)) return json(res, 429, { error: "rate_limited" });
        let body;
        if (req.method === "POST") {
          try { body = JSON.parse(await readBody(req, 1024 * 1024)); } catch { body = undefined; }
        }
        // Stateless mode: a fresh server + transport per request; pending
        // approvals live at module level in mcp.mjs, keyed by tenant.
        const mcpServer = createWalletMcpServer({ ...tenant, ip }, { store, audit });
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        res.on("close", () => { transport.close(); mcpServer.close(); });
        await mcpServer.connect(transport);
        return transport.handleRequest(req, res, body);
      }

      json(res, 404, { reason: "not found" });
    } catch (e) {
      console.error(`[wallet-service] ${req.method} ${path}:`, e);
      if (!res.headersSent) json(res, 500, { reason: "internal error" });
      else res.end();
    }
  });

  return { server, db, store, audit };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { server } = createWalletService();
  server.listen(PORT, () => {
    console.error(
      `[wallet-service] ${WALLET_ORIGIN} (broker ${BROKER}, db ${DATABASE_PATH}${PRODUCTION ? ", production" : ", dev"})`
    );
  });
}
