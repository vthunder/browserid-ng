// @browserid-ng/hono — "Sign in with BrowserID" for Hono (edge/serverless:
// Cloudflare Workers, Bun, Deno, Node). Verifies a BrowserID presentation
// server-side at the hosted /verify (via @browserid-ng/verify — no
// crypto in JS, fail-closed). The client gets the presentation from the login
// dialog (@browserid-ng/nextauth/client's signInWithBrowserID works
// standalone) and POSTs it; you verify it and set your own session/cookie.
//
//   import { browseridLogin, verifyBrowserID } from "@browserid-ng/hono";
//   app.post("/auth/browserid", browseridLogin({ audience: "https://app.example.com" }),
//     (c) => { const id = c.get("browserid"); /* set your session */ return c.json({ ok: true, email: id.email }); });

import { createVerifier } from "@browserid-ng/verify";

/**
 * Core verify: a BrowserID presentation → identity, or null (fail-closed).
 * @param {object} config
 * @param {string} config.audience  REQUIRED — your canonical origin (pin it).
 * @param {string} [config.broker]  default "https://browserid.me".
 * @param {string} [config.verifierUrl]  default `${broker}/verify`.
 * @param {string[]} [config.acceptedFallbacks]
 * @param {typeof fetch} [config.fetch]  injectable (tests / a bound fetch).
 */
export function verifyBrowserID(config = {}) {
  const audience = config.audience;
  if (!audience || typeof audience !== "string") {
    throw new Error("@browserid-ng/hono: 'audience' is required — pin it to your canonical origin");
  }
  if ("allowAgent" in config) {
    // Removed (was dead code — the protocol has no human/agent axis).
    // Delegation policy: compare `grantee` to `email` on the verified result.
    throw new Error(
      "@browserid-ng/hono: allowAgent was removed — check `grantee !== email` for delegated presentations instead"
    );
  }
  const broker = (config.broker || "https://browserid.me").replace(/\/+$/, "");
  const verifier = createVerifier({
    verifierUrl: config.verifierUrl || `${broker}/verify`,
    acceptedFallbacks: config.acceptedFallbacks,
    fetch: config.fetch,
  });
  return async function (presentation) {
    if (!presentation || typeof presentation !== "string") return null;
    const r = await verifier.verify(presentation, audience);
    if (!r.ok) return null;
    return {
      email: r.email,
      issuer: r.issuer,
      grantee: r.grantee,
      scopes: r.scopes,
      statusRefs: r.statusRefs,
    };
  };
}

/**
 * Hono middleware: read `presentation` from the JSON body, verify it, and on
 * success set `c.set("browserid", identity)` then `await next()`. On failure
 * respond 401. Mount on your login POST route; set your session in the next
 * handler from `c.get("browserid")`.
 */
export function browseridLogin(config = {}) {
  const verify = verifyBrowserID(config);
  return async function browseridLoginMiddleware(c, next) {
    let presentation;
    try {
      const body = await c.req.json();
      presentation = body && body.presentation;
    } catch {
      presentation = undefined;
    }
    const user = await verify(presentation);
    if (!user) {
      return c.json({ error: "invalid_token", error_description: "BrowserID verification failed" }, 401);
    }
    c.set("browserid", user);
    await next();
  };
}

/**
 * Re-check a session's BrowserID revocation status (spec §6.4) — call on
 * activity with the `statusRefs` you stored at login. `{ ok, revoked }`:
 * clear the session when `revoked` is true OR `ok` is false (fail-closed).
 */
export async function browseridSessionValid(statusRefs, opts = {}) {
  const broker = (opts.broker || "https://browserid.me").replace(/\/+$/, "");
  const verifier = createVerifier({
    verifierUrl: opts.verifierUrl || `${broker}/verify`,
    fetch: opts.fetch,
  });
  const r = await verifier.checkStatus(statusRefs || []);
  return { ok: r.ok === true && r.revoked !== true, revoked: r.revoked === true, reason: r.reason };
}
