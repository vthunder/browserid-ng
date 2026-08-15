// The identity-first connect flow's member login (spec §7.5 grantor pin,
// Dan's flow decision 2026-08-14): before a connection request is ever
// raised, the GATE authenticates the connecting user with a browserid login
// at its own origin. The mount then raises the broker request pinned to
// that identity, scoped to their actual entitlement — the consent card
// shows the truth, strangers are refused before any consent, and the
// origin-wide session means connecting a second mount skips the login.
//
// The session cookie is separate from the admin console's (`gate_user`),
// same HMAC machinery. The login page runs the broker's standard dialog
// (include.js + navigator.id) and POSTs the presentation back; we verify it
// against the hosted verifier with THIS origin as the audience.

import { verifyPresentation } from "@browserid-ng/verify";
import { parseCookies } from "./session.mjs";
import { json, readJsonBody } from "./mount.mjs";

/**
 * @param {object} opts
 * @param {string} opts.broker      Broker origin.
 * @param {() => string} opts.origin  The gate's public origin (login audience).
 * @param {object} opts.sessions    A createSessionManager instance (cookieName "gate_user").
 * @param {typeof fetch} [opts.fetch]
 */
export function createConnectAuth({ broker, origin, sessions, fetch: doFetch = fetch }) {
  /** The signed-in member on this request, or null. */
  function userFor(rq) {
    const s = sessions.verify(parseCookies(rq.headers.cookie));
    return s ? s.email.toLowerCase() : null;
  }

  /** Handle /connect/* routes. Returns true iff handled. */
  async function handle(rq, res, { path, url }) {
    if (rq.method === "GET" && path === "/connect/login") {
      // `next` is re-validated server-side on POST; here it only round-trips.
      // `switch=1` (the interstitial's "use a different account") drops the
      // current member session before showing the login.
      const headers = { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" };
      if (url.searchParams.get("switch")) headers["set-cookie"] = sessions.clearCookies();
      res.writeHead(200, headers);
      res.end(loginPage(broker));
      return true;
    }
    if (rq.method === "POST" && path === "/connect/login") {
      const body = await readJsonBody(rq);
      const presentation = body?.presentation;
      if (!presentation || typeof presentation !== "string") {
        json(res, 400, { error: "invalid_request", error_description: "missing presentation" });
        return true;
      }
      const aud = origin();
      const result = await verifyPresentation(presentation, aud, {
        verifierUrl: `${broker}/verify-access`,
        fetch: doFetch,
      });
      if (!result.ok) {
        json(res, 403, { error: "access_denied", error_description: `verification failed: ${result.reason}` });
        return true;
      }
      const issued = sessions.issue(result.email);
      // `next` must stay on THIS origin (open-redirect guard).
      let next = typeof body.next === "string" ? body.next : "/";
      try {
        const u = new URL(next, aud);
        next = u.origin === new URL(aud).origin ? u.pathname + u.search : "/";
      } catch {
        next = "/";
      }
      res.writeHead(200, {
        "content-type": "application/json",
        "set-cookie": issued.setCookies,
      });
      res.end(JSON.stringify({ ok: true, email: result.email, next }));
      return true;
    }
    if (rq.method === "POST" && path === "/connect/logout") {
      res.writeHead(200, {
        "content-type": "application/json",
        "set-cookie": sessions.clearCookies(),
      });
      res.end(JSON.stringify({ ok: true }));
      return true;
    }
    void url;
    return false;
  }

  return { userFor, handle };
}

function loginPage(broker) {
  const b = broker.replace(/\/+$/, "");
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Sign in — MCP gateway</title>
<style>body{font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:420px;margin:14vh auto;padding:0 24px;color:#1a1a1a;text-align:center}
button{font:600 15px system-ui;padding:11px 22px;border-radius:10px;border:0;background:#17171a;color:#fff;cursor:pointer}
.err{color:#b3261e;font-size:13.5px;min-height:1.4em;margin-top:12px}p{color:#6b6b74}</style>
<h1 style="font-size:20px">Sign in to connect</h1>
<p>This gateway checks who you are before asking anything on your behalf.
Sign in with your browserid — the next screen confirms exactly what this
connection may do.</p>
<button id="go">Sign in with browserid</button>
<div class="err" id="err"></div>
<script>
const next = new URLSearchParams(location.search).get("next") || "/";
const err = (m) => { document.getElementById("err").textContent = m; };
document.getElementById("go").onclick = () => {
  const s = document.createElement("script");
  s.src = ${JSON.stringify(b + "/include.js")};
  s.setAttribute("data-browserid-url", ${JSON.stringify(b)});
  s.onload = () => {
    navigator.id.watch({
      onlogin: async (presentation) => {
        try {
          const r = await fetch("/connect/login", {
            method: "POST", credentials: "same-origin",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ presentation, next }),
          });
          const j = await r.json();
          if (!r.ok || !j.ok) throw new Error(j.error_description || j.error || "sign-in failed");
          location.assign(j.next || "/");
        } catch (e) { err(e.message); }
      },
      onlogout: () => {},
    });
    navigator.id.request({ siteName: "MCP gateway" });
  };
  s.onerror = () => err("could not load the browserid dialog");
  document.head.appendChild(s);
};
</script>`;
}
