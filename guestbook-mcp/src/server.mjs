#!/usr/bin/env node
// browserid-ng guestbook MCP — HTTP entry point.
//
//   /mcp        the remote MCP endpoint — AUTHLESS by design (the whole demo:
//               no OAuth anywhere; auth happens at tool-call time via
//               BrowserID presentations, per docs/design/browserid-enabled-apis.md)
//   /           landing page; /healthz for probes
import { createServer } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { PORT, SERVICE_ORIGIN, GUESTBOOK_URL, WALLET_MCP_URL, WALLET_INFO_URL } from "./config.mjs";
import { createGuestbookMcpServer } from "./mcp.mjs";

export function createGuestbookService() {
  // -- tiny fixed-window rate limiter, per IP (same shape as wallet-service) --
  const buckets = new Map();
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

  const json = (res, code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  const readBody = (req, limit = 1024 * 1024) =>
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

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, SERVICE_ORIGIN);
    const path = url.pathname.replace(/\/$/, "") || "/";

    try {
      if (req.method === "GET" && path === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        return res.end(landingPage());
      }
      if (req.method === "GET" && path === "/healthz") return json(res, 200, { ok: true });

      if (path === "/mcp") {
        if (limited(`mcp:${clientIp(req)}`, 120)) return json(res, 429, { error: "rate_limited" });
        let body;
        if (req.method === "POST") {
          try { body = JSON.parse(await readBody(req)); } catch { body = undefined; }
        }
        // Stateless mode: a fresh server + transport per request (claude.ai
        // does not reliably echo mcp-session-id — see the design doc).
        const mcpServer = createGuestbookMcpServer();
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
      console.error(`[guestbook-mcp] ${req.method} ${path}:`, e);
      if (!res.headersSent) json(res, 500, { reason: "internal error" });
      else res.end();
    }
  });

  return { server };
}

function landingPage() {
  return `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>browserid guestbook MCP</title>
<style>body{font:16px/1.5 system-ui;max-width:38em;margin:4em auto;padding:0 1em;color:#222}code{background:#f4f4f4;padding:.1em .3em;border-radius:3px}</style>
<h1>Guestbook MCP</h1>
<p>A demo <strong>BrowserID-enabled service</strong>: a remote MCP server for the
<a href="${GUESTBOOK_URL}">browserid.me guestbook</a> that implements no login of its
own. Add it to your agent as a custom connector — no OAuth, no account:</p>
<p><code>${SERVICE_ORIGIN}/mcp</code></p>
<p>When an agent tries to sign, the tool asks it for a BrowserID
<em>presentation</em> — a short-lived credential the agent obtains from its human's
<a href="${WALLET_INFO_URL}">BrowserID wallet</a> (connector URL
<code>${WALLET_MCP_URL}</code>) after a one-time human approval. The guestbook
verifies it and records who acted, and on whose behalf.</p>
<p>Pattern reference: <a href="https://github.com/vthunder/browserid-ng/blob/main/docs/design/browserid-enabled-apis.md">browserid-enabled APIs</a>.</p>`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { server } = createGuestbookService();
  server.listen(PORT, () => {
    console.error(`[guestbook-mcp] ${SERVICE_ORIGIN} (guestbook ${GUESTBOOK_URL})`);
  });
}
