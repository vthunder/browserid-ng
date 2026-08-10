// @browserid-ng/express — "Sign in with BrowserID" for Express, as a Passport
// strategy and a plain middleware. Verifies a BrowserID presentation
// server-side at the hosted /verify-access (via @browserid-ng/verify — no
// crypto in JS, fail-closed). The client obtains the presentation from the
// login dialog (include.js / @browserid-ng/nextauth/client works standalone)
// and POSTs it; this verifies it and hands you the identity. Session
// management stays the app's job. See
// docs/plans/2026-08-10-nextauth-adapter-build-spec.md (same core, Express shape).

import { createVerifier } from "@browserid-ng/verify";

/**
 * Build a verify function: a BrowserID presentation → an identity, or null.
 * @param {object} config
 * @param {string} config.audience  REQUIRED — your canonical origin (pin it;
 *   never accept a client-supplied audience).
 * @param {string} [config.broker]  default "https://browserid.me".
 * @param {string} [config.verifierUrl]  default `${broker}/verify-access`.
 * @param {string[]} [config.acceptedFallbacks]
 * @param {boolean} [config.allowAgent]  default false (humans only).
 * @param {typeof fetch} [config.fetch]  injectable (tests).
 * @returns {(presentation: string) => Promise<object|null>}
 */
export function verifyBrowserID(config = {}) {
  const audience = config.audience;
  if (!audience || typeof audience !== "string") {
    throw new Error("@browserid-ng/express: 'audience' is required — pin it to your canonical origin");
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
    if (!r.ok) return null; // fail-closed
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
 * Express middleware: verify `req.body.presentation` and, on success, attach
 * the identity as `req.browserid` and call `next()`. On failure respond 401.
 * Mount on your login route with a JSON body parser ahead of it; set your own
 * session in the following handler from `req.browserid`.
 */
export function browseridLogin(config = {}) {
  const verify = verifyBrowserID(config);
  return async function browseridLoginMiddleware(req, res, next) {
    try {
      const presentation = req.body && req.body.presentation;
      const user = await verify(presentation);
      if (!user) {
        res.status(401).json({ error: "invalid_token", error_description: "BrowserID verification failed" });
        return;
      }
      req.browserid = user;
      next();
    } catch (e) {
      next(e);
    }
  };
}

/**
 * A Passport-compatible strategy (no `passport` dependency — it implements the
 * strategy interface Passport calls). Register it, then
 * `passport.authenticate("browserid")` on your login POST route.
 *
 *   passport.use(new Strategy({ audience }, (user, done) => {
 *     // map the verified BrowserID identity to your app user, then:
 *     done(null, appUser);
 *   }));
 *
 * If no `verify` callback is given, the verified BrowserID identity is used
 * as the authenticated user directly.
 */
export class Strategy {
  constructor(config = {}, verify) {
    this.name = "browserid";
    this._verifyPresentation = verifyBrowserID(config);
    this._verify = typeof config === "function" ? config : verify;
  }

  /** Called by Passport with the request. Reads `req.body.presentation`. */
  authenticate(req) {
    const presentation = req.body && req.body.presentation;
    this._verifyPresentation(presentation)
      .then((user) => {
        if (!user) return this.fail({ message: "BrowserID verification failed" }, 401);
        if (this._verify) {
          this._verify(user, (err, out, info) => {
            if (err) return this.error(err);
            if (!out) return this.fail(info || { message: "rejected" }, 401);
            this.success(out, info);
          });
        } else {
          this.success(user);
        }
      })
      .catch((e) => this.error(e));
  }
}

/**
 * Re-check a session's BrowserID revocation status (spec §6.4) — call on
 * activity with the `statusRefs` you stored at login. `{ ok, revoked }`:
 * destroy the session when `revoked` is true OR `ok` is false (fail-closed).
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
