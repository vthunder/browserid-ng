// @browserid-ng/verify — verify BrowserID-NG access presentations
// (device-cert model).
//
// This is the zero-dependency path: it POSTs the presentation to a hosted
// /verify-access service (default https://browserid.me/verify-access) which
// performs the DNSSEC-rooted key resolution, the full cryptographic join
// (access cert + assertion + warrant + config cert), primary/fallback
// conformance, and revocation checks. You get back a small, typed result.
//
// It is FAIL-CLOSED by construction: any non-"okay" status, network error,
// malformed response, or exception resolves to { ok: false, reason }. Callers
// never have to remember to check a status string — a truthy `.ok` is the only
// success signal.
//
// Trust note: using a hosted verifier means you trust that service to perform
// verification honestly. That is the right tradeoff for many RPs (it is the same
// party you already discover keys through), but if you need to verify without
// trusting a third party, run your own /verify-access (the broker is open
// source) and point `verifierUrl` at it, or use the native verifier libraries.

const DEFAULT_VERIFIER = "https://browserid.me/verify-access";

/**
 * Create a verifier bound to a hosted /verify-access endpoint.
 * @param {object} [opts]
 * @param {string} [opts.verifierUrl] hosted /verify-access URL (default browserid.me)
 * @param {string[]} [opts.acceptedFallbacks] default fallback-IdP issuer domains
 *   accepted for emails with no primary IdP (spec §8.1). Primaries are always
 *   accepted. Omit for the verifier's default ({that broker}).
 * @param {number} [opts.timeoutMs] request timeout (default 10000)
 * @param {typeof fetch} [opts.fetch] fetch implementation (default global fetch)
 */
export function createVerifier(opts = {}) {
  const verifierUrl = opts.verifierUrl || DEFAULT_VERIFIER;
  const defaultFallbacks = opts.acceptedFallbacks;
  const timeoutMs = opts.timeoutMs ?? 10000;
  const doFetch = opts.fetch || globalThis.fetch;
  if (typeof doFetch !== "function") {
    throw new Error("no fetch available — pass opts.fetch or use Node >=18");
  }

  /**
   * Verify an access presentation against an expected audience.
   * @param {string} presentation the `access_cert~assertion~warrant~config_cert`
   *   string from the RP flow (navigator.id.watch()'s onlogin delivers it)
   * @param {string} audience the exact origin you expect (e.g. "https://app.example")
   * @param {object} [callOpts]
   * @param {string[]} [callOpts.acceptedFallbacks] override the default set
   * @returns {Promise<VerifyResult>}
   */
  async function verify(presentation, audience, callOpts = {}) {
    if ("allowAgent" in callOpts) {
      // Removed, loudly: the protocol has no human/agent axis (a user can mint
      // their agent an "as-you" credential, so no verifier can tell them
      // apart), and the old `allowAgent: false` default never rejected
      // anything. Silently ignoring the option would keep a security promise
      // we cannot honor. Delegation IS detectable: `grantee !== email` means
      // another identity acted on the user's behalf — apply policy on that,
      // and on `scopes`, after verify() succeeds.
      throw new Error(
        "allowAgent was removed: the protocol cannot distinguish humans from " +
          "agents. Check `result.grantee !== result.email` for delegated " +
          "presentations instead."
      );
    }
    if (!presentation || typeof presentation !== "string") {
      return fail("no presentation provided");
    }
    if (!audience || typeof audience !== "string") {
      return fail("no audience provided");
    }
    const acceptedFallbacks = callOpts.acceptedFallbacks ?? defaultFallbacks;

    const body = { presentation, audience };
    if (acceptedFallbacks) body.accepted_fallbacks = acceptedFallbacks;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res, json;
    try {
      res = await doFetch(verifierUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (e) {
      return fail(`verifier request failed: ${(e && e.message) || e}`);
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) return fail(`verifier returned HTTP ${res.status}`);
    try {
      json = await res.json();
    } catch {
      return fail("verifier returned a non-JSON response");
    }

    // Fail closed on anything that isn't an explicit success.
    if (!json || json.status !== "okay" || !json.email) {
      return fail((json && json.reason) || "verification failed");
    }

    return {
      ok: true,
      // The ATTRIBUTED identity (the warrant grantor): who this session/action
      // belongs to.
      email: json.email,
      // The ACTOR of record (the warrant grantee): equals `email` when the
      // identity acted for itself; differs when another identity — typically
      // a named agent — acted on `email`'s behalf under an audience-bound,
      // user-approved warrant. RPs that want delegation policy compare the
      // two; there is no human/agent flag (an "as-you" agent is
      // indistinguishable from its owner by design).
      grantee: json.grantee || json.email,
      issuer: json.issuer,
      scopes: json.scopes || [],
      // Revocation pointers ({uri, idx}) for later re-checks via
      // checkStatus() — retain these with the session; the presentation
      // itself expires in minutes.
      statusRefs: json.status_refs || [],
    };
  }

  /**
   * Re-check revocation for a previously verified session ("logged out
   * everywhere", spec §6.4). Call on session activity with the `statusRefs`
   * a successful verify() returned; when it resolves `{ok: true}` with
   * `revoked: true` — or `{ok: false}` at all (fail-closed: "cannot prove
   * unrevoked" is a rejection) — terminate the RP session.
   * @param {{uri: string, idx: number}[]} refs
   * @returns {Promise<{ok: true, revoked: boolean}
   *   | {ok: false, reason: string}>}
   */
  async function checkStatus(refs) {
    if (!Array.isArray(refs) || refs.length === 0) {
      // No refs means the credentials carried no revocation pointer; there
      // is nothing to re-check and TTL-only semantics apply.
      return { ok: true, revoked: false };
    }
    const statusUrl = new URL("/status/check", verifierUrl).toString();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res, json;
    try {
      res = await doFetch(statusUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refs }),
        signal: controller.signal,
      });
    } catch (e) {
      return fail(`status check failed: ${(e && e.message) || e}`);
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) return fail(`status check returned HTTP ${res.status}`);
    try {
      json = await res.json();
    } catch {
      return fail("status check returned a non-JSON response");
    }
    if (!json || json.ok !== true) {
      return fail((json && "status refs unavailable (fail-closed)") || "status check failed");
    }
    return { ok: true, revoked: json.revoked === true };
  }

  return { verify, checkStatus, verifierUrl };
}

function fail(reason) {
  return { ok: false, reason };
}

/**
 * One-shot convenience wrapper.
 * @param {string} presentation
 * @param {string} audience
 * @param {object} [opts] merges createVerifier + verify options
 * @returns {Promise<VerifyResult>}
 */
export function verifyPresentation(presentation, audience, opts = {}) {
  return createVerifier(opts).verify(presentation, audience, opts);
}

/**
 * @typedef {{ok: true, email: string, grantee: string, issuer?: string,
 *   scopes: string[],
 *   statusRefs: {uri: string, idx: number}[]}
 *   | {ok: false, reason: string}} VerifyResult
 */
