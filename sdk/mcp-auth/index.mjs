// @browserid-ng/mcp-auth — warrant-gated MCP tools over MCP's own OAuth 2.1.
//
// Turns any MCP server into a BrowserID resource server: an embedded
// authorization server (AS) redeems a warrant presentation for a short-lived
// scoped bearer via the RFC 7521 jwt-bearer assertion grant, and a per-call
// guard re-checks the warrant's revocation status FAIL-CLOSED on every tool
// call. Hosts run their stock MCP OAuth client unmodified and never learn
// BrowserID exists.
//
// No crypto in JS: verification is delegated to the broker's DNSSEC-rooted
// hosted verifier (`POST /verify-access`), and revocation to `POST
// /status/check` — the single Rust implementation of both. See
// docs/plans/2026-08-10-mcp-auth-flight-build-spec.md.

import { randomBytes } from "node:crypto";

const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

// ---------------------------------------------------------------------------
// Bearer store — an interface with an in-memory default. A grant record is
// { grantor, grantee, holder, scopes, statusRefs, exp, issuer }.
// ---------------------------------------------------------------------------

/** In-memory bearer store (single process). Swap for Redis/db in production. */
export function createMemoryStore() {
  const grants = new Map();
  return {
    async put(token, grant) {
      grants.set(token, grant);
    },
    async get(token) {
      const g = grants.get(token);
      if (!g) return null;
      if (g.exp <= nowS()) {
        grants.delete(token);
        return null;
      }
      return g;
    },
    async del(token) {
      grants.delete(token);
    },
    /** Best-effort sweep of expired grants (optional to call). */
    async sweep() {
      const t = nowS();
      for (const [k, g] of grants) if (g.exp <= t) grants.delete(k);
    },
  };
}

const nowS = () => Math.floor(Date.now() / 1000);
const bearerToken = () => `bat_${randomBytes(32).toString("base64url")}`;

// ---------------------------------------------------------------------------
// Errors — carry an OAuth error code + HTTP status so callers can render
// RFC 6749 §5.2 token errors and RFC 6750 bearer challenges uniformly.
// ---------------------------------------------------------------------------

export class McpAuthError extends Error {
  constructor(oauthError, message, httpStatus = 400) {
    super(message);
    this.name = "McpAuthError";
    this.oauthError = oauthError; // e.g. "invalid_grant", "invalid_token"
    this.httpStatus = httpStatus;
  }
  toTokenErrorResponse() {
    return { error: this.oauthError, error_description: this.message };
  }
}

// ---------------------------------------------------------------------------
// The middleware factory.
// ---------------------------------------------------------------------------

/**
 * @param {object} opts
 * @param {string} opts.resource   Canonical URL of THIS MCP server (the OAuth
 *                                  resource + the audience warrants must bind to).
 * @param {string} [opts.broker]   BrowserID broker origin (default https://browserid.me).
 * @param {Record<string,string[]>} [opts.scopesForTool]  toolName -> required scopes.
 * @param {number} [opts.tokenTtlS]  Bearer lifetime seconds (default 3600).
 * @param {number} [opts.statusCacheS]  Max seconds to trust a per-grant status
 *                                  result before a fresh re-check (default 60;
 *                                  never exceeds the list's own ttl semantics).
 * @param {string[]} [opts.acceptedFallbacks]  Fallback issuer domains this RP
 *                                  accepts (spec §8.1). Default [broker host].
 * @param {object} [opts.store]     Bearer store (default createMemoryStore()).
 * @param {typeof fetch} [opts.fetch]  Injectable fetch (tests).
 */
export function createMcpAuth(opts) {
  const resource = req(opts, "resource").replace(/\/+$/, "");
  const broker = (opts.broker || "https://browserid.me").replace(/\/+$/, "");
  const scopesForTool = opts.scopesForTool || {};
  const tokenTtlS = opts.tokenTtlS ?? 3600;
  const statusCacheS = opts.statusCacheS ?? 60;
  const store = opts.store || createMemoryStore();
  const doFetch = opts.fetch || globalThis.fetch;
  const acceptedFallbacks =
    opts.acceptedFallbacks || [new URL(broker).host];
  const verifyUrl = `${broker}/verify-access`;
  const statusUrl = `${broker}/status/check`;

  // --- OAuth discovery (RFC 9728 / RFC 8414) -------------------------------

  function protectedResourceMetadata() {
    return {
      resource,
      authorization_servers: [resource],
      scopes_supported: allScopes(scopesForTool),
      bearer_methods_supported: ["header"],
    };
  }

  function authorizationServerMetadata() {
    return {
      issuer: resource,
      token_endpoint: `${resource}/token`,
      grant_types_supported: [JWT_BEARER_GRANT],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: allScopes(scopesForTool),
      // The AS mints bearers only from a browserid warrant presentation; there
      // is no interactive authorize endpoint here (approval happens at the
      // registrar, out of band — an agent must never approve its own warrant).
      response_types_supported: [],
    };
  }

  // --- The token endpoint (the embedded AS) --------------------------------

  /**
   * Redeem a warrant presentation for a bearer. `params` is the parsed
   * form/JSON token-request body: { grant_type, assertion, scope? }.
   * `assertion` is the 4-object BrowserID access presentation. Returns the
   * RFC 6749 token response object; throws McpAuthError on failure.
   */
  async function handleToken(params) {
    const grantType = params.grant_type;
    if (grantType !== JWT_BEARER_GRANT) {
      throw new McpAuthError(
        "unsupported_grant_type",
        `only ${JWT_BEARER_GRANT} is supported`
      );
    }
    const presentation = params.assertion;
    if (!presentation || typeof presentation !== "string") {
      throw new McpAuthError("invalid_request", "missing 'assertion' (a browserid presentation)");
    }

    let verified;
    try {
      const res = await doFetch(verifyUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          presentation,
          audience: resource,
          accepted_fallbacks: acceptedFallbacks,
        }),
      });
      verified = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new McpAuthError("invalid_grant", `verifier HTTP ${res.status}`);
      }
    } catch (e) {
      if (e instanceof McpAuthError) throw e;
      // Fail-closed: an unreachable verifier is not an approval.
      throw new McpAuthError("temporarily_unavailable", `verifier unreachable: ${e.message}`, 503);
    }

    if (verified.status !== "okay") {
      throw new McpAuthError("invalid_grant", verified.reason || "presentation did not verify");
    }

    // The warrant's scopes are the ceiling. A requested `scope` may narrow but
    // never widen them (RFC 6749 §3.3).
    const granted = Array.isArray(verified.scopes) ? verified.scopes : [];
    const requested = parseScope(params.scope);
    const scopes = requested.length
      ? requested.filter((s) => granted.includes(s))
      : granted;
    if (requested.length && scopes.length !== requested.length) {
      throw new McpAuthError("invalid_scope", "requested scope exceeds the warrant's grant");
    }

    const token = bearerToken();
    const exp = nowS() + tokenTtlS;
    await store.put(token, {
      grantor: verified.email || null, // attributed identity (human)
      grantee: verified.grantee || verified.email || null, // acting identity (agent)
      holder: verified.holder || null,
      issuer: verified.issuer || null,
      scopes,
      statusRefs: verified.status_refs || [],
      exp,
      statusCheckedAt: nowS(), // verify-access already checked status fail-closed
      statusOk: true,
    });

    return {
      access_token: token,
      token_type: "Bearer",
      expires_in: tokenTtlS,
      scope: scopes.join(" "),
    };
  }

  // --- Per-call bearer validation (fail-closed status re-check) -------------

  /**
   * Validate a Bearer token and return its live authorization context.
   * Re-checks the warrant's status refs FAIL-CLOSED (revoked or unreachable
   * => rejected) unless a recent (< statusCacheS) successful check exists.
   * Throws McpAuthError (401) on any failure.
   * @returns {Promise<{grantor:string, grantee:string, holder:string, scopes:string[], issuer:string}>}
   */
  async function authenticate(authorizationHeader) {
    const m = /^Bearer\s+(.+)$/i.exec(authorizationHeader || "");
    if (!m) throw new McpAuthError("invalid_request", "missing Bearer token", 401);
    const token = m[1].trim();
    const grant = await store.get(token);
    if (!grant) throw new McpAuthError("invalid_token", "unknown or expired token", 401);

    await ensureUnrevoked(token, grant);

    return {
      grantor: grant.grantor,
      grantee: grant.grantee,
      holder: grant.holder,
      issuer: grant.issuer,
      scopes: grant.scopes.slice(),
    };
  }

  async function ensureUnrevoked(token, grant) {
    const refs = grant.statusRefs || [];
    if (refs.length === 0) return; // nothing to re-check
    // Trust a very recent successful check to bound status-list traffic; never
    // longer than statusCacheS, so revoke lands within that window at worst.
    if (grant.statusOk && nowS() - grant.statusCheckedAt < statusCacheS) return;

    let body;
    try {
      const res = await doFetch(statusUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refs }),
      });
      body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (e) {
      // Fail-closed: can't prove unrevoked => reject (spec §6.4).
      grant.statusOk = false;
      throw new McpAuthError("invalid_token", `status unavailable (fail-closed): ${e.message}`, 401);
    }
    // ok:false OR revoked:true => treat as revoked.
    if (body.ok !== true || body.revoked === true) {
      grant.statusOk = false;
      await store.del(token);
      throw new McpAuthError("invalid_token", "warrant revoked", 401);
    }
    grant.statusOk = true;
    grant.statusCheckedAt = nowS();
  }

  /** RFC 6750 challenge header value for a 401. */
  function challenge() {
    return `Bearer resource_metadata="${resource}/.well-known/oauth-protected-resource"`;
  }

  /**
   * Guard a tool call: authenticate the bearer, then enforce that the tool's
   * required scopes (from scopesForTool[toolName], or an explicit list) are a
   * subset of the grant. Returns the ctx on success; throws McpAuthError.
   */
  async function requireWarrant(authorizationHeader, toolNameOrScopes) {
    const ctx = await authenticate(authorizationHeader);
    const required = Array.isArray(toolNameOrScopes)
      ? toolNameOrScopes
      : scopesForTool[toolNameOrScopes] || [];
    const missing = required.filter((s) => !ctx.scopes.includes(s));
    if (missing.length) {
      throw new McpAuthError(
        "insufficient_scope",
        `this tool needs scope(s) [${missing.join(", ")}] not in the warrant`,
        403
      );
    }
    return ctx;
  }

  return {
    resource,
    broker,
    protectedResourceMetadata,
    authorizationServerMetadata,
    handleToken,
    authenticate,
    requireWarrant,
    challenge,
    store,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function req(o, k) {
  if (!o || o[k] == null || o[k] === "") throw new Error(`createMcpAuth: '${k}' is required`);
  return o[k];
}
function parseScope(s) {
  return typeof s === "string" ? s.split(/\s+/).filter(Boolean) : [];
}
function allScopes(map) {
  const set = new Set();
  for (const list of Object.values(map)) for (const s of list) set.add(s);
  return [...set];
}

export { JWT_BEARER_GRANT };
