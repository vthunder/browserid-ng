// @browserid-ng/fastify — "Sign in with BrowserID" for Fastify. A preHandler
// hook that verifies a BrowserID presentation server-side at the hosted
// /verify-access (via @browserid-ng/verify — no crypto in JS, fail-closed) and
// attaches `request.browserid`. The client gets the presentation from the login
// dialog (@browserid-ng/nextauth/client's signInWithBrowserID works standalone)
// and POSTs it; you verify it and set your own session.
//
//   import { browseridLogin } from "@browserid-ng/fastify";
//   fastify.post("/auth/browserid", { preHandler: browseridLogin({ audience: "https://app.example.com" }) },
//     async (req) => { /* req.browserid.email — set your session */ return { ok: true }; });

import { createVerifier } from "@browserid-ng/verify";

/**
 * Core verify: a BrowserID presentation → identity, or null (fail-closed).
 * @param {object} config
 * @param {string} config.audience  REQUIRED — your canonical origin (pin it).
 * @param {string} [config.broker]  default "https://browserid.me".
 * @param {string} [config.verifierUrl]  default `${broker}/verify-access`.
 * @param {string[]} [config.acceptedFallbacks]
 * @param {boolean} [config.allowAgent]  default false (humans only).
 * @param {typeof fetch} [config.fetch]  injectable (tests).
 */
export function verifyBrowserID(config = {}) {
  const audience = config.audience;
  if (!audience || typeof audience !== "string") {
    throw new Error("@browserid-ng/fastify: 'audience' is required — pin it to your canonical origin");
  }
  const broker = (config.broker || "https://browserid.me").replace(/\/+$/, "");
  const verifier = createVerifier({
    verifierUrl: config.verifierUrl || `${broker}/verify-access`,
    acceptedFallbacks: config.acceptedFallbacks,
    fetch: config.fetch,
  });
  const allowAgent = config.allowAgent === true;
  return async function (presentation) {
    if (!presentation || typeof presentation !== "string") return null;
    const r = await verifier.verify(presentation, audience, { allowAgent });
    if (!r.ok) return null;
    return {
      email: r.email,
      issuer: r.issuer,
      grantee: r.grantee,
      subject: r.subject,
      scopes: r.scopes,
      statusRefs: r.statusRefs,
    };
  };
}

/**
 * A Fastify `preHandler` hook: verify `request.body.presentation` and, on
 * success, attach `request.browserid` (your route handler then sets the
 * session). On failure it replies 401 and short-circuits the route.
 * Ensure a JSON body parser is active (Fastify's default handles
 * `application/json`).
 */
export function browseridLogin(config = {}) {
  const verify = verifyBrowserID(config);
  return async function browseridLoginPreHandler(request, reply) {
    const presentation = request.body && request.body.presentation;
    const user = await verify(presentation);
    if (!user) {
      reply.code(401).send({ error: "invalid_token", error_description: "BrowserID verification failed" });
      return reply; // short-circuit: skip the route handler
    }
    request.browserid = user;
  };
}

/**
 * Re-check a session's BrowserID revocation status (spec §6.4) — call on
 * activity with the `statusRefs` you stored at login. `{ ok, revoked }`: clear
 * the session when `revoked` is true OR `ok` is false (fail-closed).
 */
export async function browseridSessionValid(statusRefs, opts = {}) {
  const broker = (opts.broker || "https://browserid.me").replace(/\/+$/, "");
  const verifier = createVerifier({
    verifierUrl: opts.verifierUrl || `${broker}/verify-access`,
    fetch: opts.fetch,
  });
  const r = await verifier.checkStatus(statusRefs || []);
  return { ok: r.ok === true && r.revoked !== true, revoked: r.revoked === true, reason: r.reason };
}
