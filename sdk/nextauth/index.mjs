// @browserid-ng/nextauth — drop-in "Sign in with BrowserID" for Auth.js
// (NextAuth). A Credentials provider whose authorize() verifies a BrowserID
// presentation server-side at the hosted /verify-access (via
// @browserid-ng/verify — no crypto in JS, fail-closed), plus small browser
// helpers that drive the login dialog. See
// docs/plans/2026-08-10-nextauth-adapter-build-spec.md (bean bla3).
//
// Server (auth config):
//   import Credentials from "next-auth/providers/credentials";
//   import { BrowserID } from "@browserid-ng/nextauth";
//   providers: [ Credentials(BrowserID({ audience: "https://app.example.com" })) ]
//
// Client (a sign-in button):
//   import { signInWithBrowserID } from "@browserid-ng/nextauth/client";
//   const presentation = await signInWithBrowserID();
//   await signIn("browserid", { presentation });   // next-auth signIn

import { createVerifier } from "@browserid-ng/verify";

/**
 * Build the server-side `authorize` function: verify a BrowserID presentation
 * and map it to an Auth.js user, or null (fail-closed).
 * @param {object} config
 * @param {string} config.audience  REQUIRED — your canonical origin (or
 *   `<origin>/<path>` for scoped access). The presentation MUST be bound to
 *   it; never accept a client-supplied audience.
 * @param {string} [config.broker]  BrowserID broker origin (default browserid.me).
 * @param {string} [config.verifierUrl]  hosted verifier (default `${broker}/verify-access`).
 * @param {string[]} [config.acceptedFallbacks]
 * @param {boolean} [config.allowAgent]  accept an agent presentation as a login (default false — humans only).
 * @param {typeof fetch} [config.fetch]  injectable (tests).
 */
export function browseridAuthorize(config = {}) {
  const audience = config.audience;
  if (!audience || typeof audience !== "string") {
    throw new Error(
      "@browserid-ng/nextauth: 'audience' is required — pin it to your canonical origin"
    );
  }
  const broker = (config.broker || "https://browserid.me").replace(/\/+$/, "");
  const verifier = createVerifier({
    verifierUrl: config.verifierUrl || `${broker}/verify-access`,
    acceptedFallbacks: config.acceptedFallbacks,
    fetch: config.fetch,
  });
  const allowAgent = config.allowAgent === true;

  return async function authorize(credentials) {
    const presentation = credentials && credentials.presentation;
    if (!presentation || typeof presentation !== "string") return null;
    const r = await verifier.verify(presentation, audience, { allowAgent });
    if (!r.ok) return null; // fail-closed
    return {
      id: r.email,
      email: r.email,
      name: r.email, // apps usually swap this for a public display name
      browserid: {
        issuer: r.issuer,
        grantee: r.grantee,
        subject: r.subject,
        scopes: r.scopes,
        statusRefs: r.statusRefs,
      },
    };
  };
}

/**
 * The Auth.js Credentials-provider options for BrowserID. Pass to your
 * `Credentials(...)` import (v5) or use as a provider (v4). Kept free of any
 * next-auth dependency so it works across versions.
 */
export function BrowserID(config = {}) {
  return {
    id: "browserid",
    name: "BrowserID",
    type: "credentials",
    credentials: {
      presentation: { label: "BrowserID presentation", type: "text" },
    },
    authorize: browseridAuthorize(config),
  };
}

/**
 * Re-check a session's BrowserID revocation status (spec §6.4) — call on
 * session activity with the `statusRefs` stashed at sign-in. Returns
 * `{ ok, revoked }`: sign the user out when `revoked` is true OR `ok` is
 * false (fail-closed: "cannot prove unrevoked" is a rejection).
 * @param {{uri:string, idx:number}[]} statusRefs
 * @param {{broker?:string, verifierUrl?:string, fetch?:typeof fetch}} [opts]
 */
export async function browseridSessionValid(statusRefs, opts = {}) {
  const broker = (opts.broker || "https://browserid.me").replace(/\/+$/, "");
  const verifier = createVerifier({
    verifierUrl: opts.verifierUrl || `${broker}/verify-access`,
    fetch: opts.fetch,
  });
  const r = await verifier.checkStatus(statusRefs || []);
  // valid iff the check succeeded AND nothing is revoked.
  return { ok: r.ok === true && r.revoked !== true, revoked: r.revoked === true, reason: r.reason };
}
