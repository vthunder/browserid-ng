// @browserid-ng/mcp-auth — warrant-gated MCP tools over MCP's own OAuth 2.1.
//
// Turns any MCP server into a BrowserID resource server: an embedded
// authorization server (AS) redeems a warrant presentation for a short-lived
// scoped bearer via the RFC 7521 jwt-bearer assertion grant, and a per-call
// guard re-checks the warrant's revocation status FAIL-CLOSED on every tool
// call. Hosts run their stock MCP OAuth client unmodified and never learn
// BrowserID exists.
//
// An OPTIONAL second lane (`createAuthCodeLane`) serves generic OAuth hosts
// that have no wallet at all: RFC 7591 dynamic registration + a PKCE-S256
// authorization-code flow whose approval is the broker's consent page, with
// the gateway's own DeviceAgent obtaining the warrant. Both lanes mint the
// same bearer through the same verify path. See the M1 build spec
// (docs/plans/2026-08-12-M1-authcode-build-spec.md).
//
// No crypto in JS: verification is delegated to the broker's DNSSEC-rooted
// hosted verifier (`POST /verify-access`), and revocation to `POST
// /status/check` — the single Rust implementation of both. See
// docs/plans/2026-08-10-mcp-auth-flight-build-spec.md.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const AUTH_CODE_GRANT = "authorization_code";

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
    return redeemPresentation(presentation, params.scope);
  }

  /**
   * The shared bearer mint: verify a presentation against the broker's
   * hosted verifier (audience = this resource, fail-closed) and store a
   * scoped bearer. Both token-endpoint grants terminate here — Lane A
   * (jwt-bearer, `handleToken`) and the optional authorization-code lane
   * (`createAuthCodeLane`) — so every bearer flows through the SAME
   * `/verify-access` check and the same per-call status re-check.
   */
  async function redeemPresentation(presentation, scope) {
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
    const requested = parseScope(scope);
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
    redeemPresentation,
    authenticate,
    requireWarrant,
    challenge,
    store,
  };
}

// ---------------------------------------------------------------------------
// The OPTIONAL authorization-code lane (Lane B) — a generic OAuth host
// (claude.ai, Cursor) that knows nothing about BrowserID does the ordinary
// redirect dance: discover → register (RFC 7591 DCR) → /authorize (PKCE
// S256) → approve on the broker's consent page → code → /token. The lane
// itself obtains the warrant: it embeds a DeviceAgent (a gateway agent
// credential, the wallet's ~/.browserid shape) that raises the consent
// request server-side, picks up the approved `warrant~config_cert`, and at
// token time mints a presentation that is fed through the SAME
// `redeemPresentation` verify+mint path as Lane A — identical bearers,
// identical fail-closed per-call status re-checks downstream.
//
// `@browserid-ng/agent` is imported lazily, only when a lane is actually
// exercised — Lane-A-only users never load it.
// ---------------------------------------------------------------------------

/** Lazy module handle so require-less Lane-A users never pay for the agent. */
let agentModulePromise = null;
const loadAgentModule = () => (agentModulePromise ??= import("@browserid-ng/agent"));

/** PKCE S256 (RFC 7636): base64url(sha256(verifier)) must equal the
 *  challenge. Constant-time compare; verifier charset/length per §4.1. */
export function verifyPkceS256(verifier, challenge) {
  if (typeof verifier !== "string" || typeof challenge !== "string") return false;
  if (verifier.length < 43 || verifier.length > 128) return false;
  if (!/^[A-Za-z0-9\-._~]+$/.test(verifier)) return false;
  const digest = createHash("sha256").update(verifier, "ascii").digest();
  let expected;
  try {
    expected = Buffer.from(challenge, "base64url");
  } catch {
    return false;
  }
  return expected.length === digest.length && timingSafeEqual(digest, expected);
}

/**
 * The authorization-code lane. Optional: construct it only when this server
 * holds a gateway agent credential; everything Lane A does is untouched.
 *
 * @param {object} opts
 * @param {object} opts.mcpAuth     The `createMcpAuth` instance to extend.
 * @param {object} opts.credential  Gateway agent device credential (the
 *                                  wallet's shape: { device_key,
 *                                  agent_device_cert, idp, identity? }).
 * @param {string} [opts.broker]    Broker origin (default mcpAuth.broker).
 * @param {typeof fetch} [opts.fetch]  Injectable fetch (tests).
 * @param {string} [opts.label]     Display label on the consent card
 *                                  (default "mcp gateway").
 * @param {number} [opts.codeTtlS]  OAuth code lifetime (default 60s).
 * @param {number} [opts.pendingTtlS]  /authorize → /authorize/return window
 *                                  (default 900s, the consent request's TTL).
 * @param {number} [opts.returnPollTries]   Poll attempts on the return leg.
 * @param {number} [opts.returnPollDelayMs] Delay between those attempts.
 */
export function createAuthCodeLane(opts) {
  const mcpAuth = req(opts, "mcpAuth");
  const credential = req(opts, "credential");
  const resource = mcpAuth.resource;
  const broker = (opts.broker || mcpAuth.broker).replace(/\/+$/, "");
  const doFetch = opts.fetch || globalThis.fetch;
  const label = opts.label || "mcp gateway";
  const codeTtlS = opts.codeTtlS ?? 60;
  const pendingTtlS = opts.pendingTtlS ?? 900;
  const returnPollTries = opts.returnPollTries ?? 5;
  const returnPollDelayMs = opts.returnPollDelayMs ?? 500;

  // In-memory v1 stores (the design's locked default). A client row is
  // { redirectUris, clientName }; pending is keyed by our internal
  // auth_state; codes are single-use and short-lived.
  const clients = new Map(); // client_id -> { redirectUris, clientName }
  const pendingAuthz = new Map(); // auth_state -> { clientId, redirectUri, hostState, codeChallenge, scope, pollCode, exp }
  const codes = new Map(); // code -> { clientId, redirectUri, codeChallenge, grant, exp }

  const sweep = (map) => {
    const t = nowS();
    for (const [k, v] of map) if (v.exp <= t) map.delete(k);
  };

  // The embedded DeviceAgent, constructed on first use. All grant-map
  // mutations + presentation mints are serialized through `withAgent`: the
  // agent holds ONE grant slot per audience and every Lane-B user shares
  // this resource's audience, so an unserialized addGrant/assertionFor pair
  // could interleave and mint one user's presentation under another user's
  // warrant.
  let agentPromise = null;
  const getAgent = () =>
    (agentPromise ??= loadAgentModule().then(
      ({ DeviceAgent }) => new DeviceAgent(credential, { http: doFetch })
    ));
  let agentChain = Promise.resolve();
  function withAgent(fn) {
    const run = agentChain.then(async () => fn(await getAgent()));
    agentChain = run.then(
      () => {},
      () => {}
    );
    return run;
  }

  // --- discovery ------------------------------------------------------------

  /** Lane-A metadata plus the auth-code additions — serve THIS from
   *  `/.well-known/oauth-authorization-server` when the lane is on. */
  function authorizationServerMetadata() {
    const base = mcpAuth.authorizationServerMetadata();
    return {
      ...base,
      authorization_endpoint: `${resource}/authorize`,
      registration_endpoint: `${resource}/register`,
      grant_types_supported: [...base.grant_types_supported, AUTH_CODE_GRANT],
      response_types_supported: ["code"],
      code_challenge_methods_supported: ["S256"],
    };
  }

  // --- Dynamic Client Registration (RFC 7591) --------------------------------

  /** A registered redirect_uri must be absolute https — or http on the
   *  loopback for dev — and carry no fragment. Everything else is refused,
   *  which is what makes the /authorize exact-match meaningful. */
  function validRedirectUri(u) {
    let url;
    try {
      url = new URL(u);
    } catch {
      return false;
    }
    if (url.hash) return false;
    if (url.protocol === "https:") return true;
    return (
      url.protocol === "http:" &&
      (url.hostname === "localhost" || url.hostname.startsWith("127.") || url.hostname === "[::1]")
    );
  }

  /**
   * `POST /register` — mint a public (PKCE, no secret) client. `body` is the
   * parsed RFC 7591 registration request; returns the registration response.
   */
  function handleRegister(body) {
    const uris = body?.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === "string")) {
      throw new McpAuthError(
        "invalid_client_metadata",
        "redirect_uris (a non-empty array of strings) is required"
      );
    }
    for (const u of uris) {
      if (!validRedirectUri(u)) {
        throw new McpAuthError(
          "invalid_redirect_uri",
          `redirect_uri must be absolute https (or http://localhost for dev), got '${u}'`
        );
      }
    }
    if (clients.size >= 10_000) {
      throw new McpAuthError("temporarily_unavailable", "client registry full", 503);
    }
    const clientId = `mcp_${randomBytes(16).toString("base64url")}`;
    const clientName = typeof body.client_name === "string" ? body.client_name : undefined;
    clients.set(clientId, { redirectUris: uris.slice(), clientName });
    return {
      client_id: clientId,
      client_id_issued_at: nowS(),
      redirect_uris: uris.slice(),
      token_endpoint_auth_method: "none",
      grant_types: [AUTH_CODE_GRANT],
      response_types: ["code"],
      ...(clientName ? { client_name: clientName } : {}),
    };
  }

  // --- GET /authorize ---------------------------------------------------------

  const errorRedirect = (redirectUri, hostState, error, description) => ({
    redirect:
      `${redirectUri}${redirectUri.includes("?") ? "&" : "?"}` +
      new URLSearchParams({
        error,
        error_description: description,
        ...(hostState != null ? { state: hostState } : {}),
      }).toString(),
  });

  /**
   * `GET /authorize` — validate the host's request, raise the warrant
   * request as the gateway agent (audience = THIS resource, always), and
   * send the browser to the broker's consent page. Resolves to
   * `{ redirect: url }`; throws McpAuthError for errors that must NOT
   * redirect (unknown client / unregistered redirect_uri — the open-redirect
   * guard: render those, never bounce).
   */
  async function handleAuthorize(query) {
    sweep(pendingAuthz);
    sweep(codes);
    const q = query || {};
    const client = clients.get(q.client_id);
    if (!client) {
      throw new McpAuthError("invalid_request", "unknown client_id (register first)");
    }
    // Exact-match against the DCR-registered set. On failure DO NOT redirect.
    const redirectUri = q.redirect_uri;
    if (typeof redirectUri !== "string" || !client.redirectUris.includes(redirectUri)) {
      throw new McpAuthError("invalid_request", "redirect_uri is not registered for this client");
    }
    const hostState = q.state != null ? String(q.state) : null;
    // From here on the redirect_uri is validated: OAuth errors go back to it.
    if (q.response_type !== "code") {
      return errorRedirect(redirectUri, hostState, "unsupported_response_type", "only response_type=code is supported");
    }
    // PKCE S256 REQUIRED: no challenge, or any method but S256 ('plain'
    // included), is refused.
    if (typeof q.code_challenge !== "string" || !q.code_challenge) {
      return errorRedirect(redirectUri, hostState, "invalid_request", "code_challenge is required (PKCE S256)");
    }
    if (q.code_challenge_method !== "S256") {
      return errorRedirect(redirectUri, hostState, "invalid_request", "code_challenge_method must be S256");
    }

    const scopes = parseScope(q.scope);
    const authState = randomBytes(32).toString("base64url");
    const returnUrl = `${resource}/authorize/return?st=${authState}`;
    let pending;
    try {
      const { requestWarrants } = await loadAgentModule();
      const agent = await getAgent();
      // The audience is pinned to THIS resource — the same audience
      // /verify-access binds the bearer to. grantor "*": the approver picks
      // which of their identities delegates.
      pending = await requestWarrants(broker, {
        deviceCert: agent.deviceCert,
        identity: agent.email,
        grants: [{ audience: resource, scopes }],
        label,
        grantor: "*",
        returnUrl,
        http: doFetch,
      });
    } catch (e) {
      return errorRedirect(redirectUri, hostState, "temporarily_unavailable", `warrant request failed: ${e.message}`);
    }
    pendingAuthz.set(authState, {
      clientId: q.client_id,
      redirectUri,
      hostState,
      codeChallenge: q.code_challenge,
      scope: q.scope,
      pollCode: pending.code,
      exp: nowS() + pendingTtlS,
    });
    return { redirect: pending.verificationUriComplete };
  }

  // --- GET /authorize/return ---------------------------------------------------

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /**
   * `GET /authorize/return?st=…` — the post-approval leg the broker's
   * consent page bounces the browser to (via the origin-validated
   * return_url). Picks up the approved warrant, mints the single-use OAuth
   * code, and redirects to the host's redirect_uri. Single-use: the pending
   * record is consumed on entry. Throws McpAuthError (render an error page)
   * when the record is missing/expired — there is nowhere trustworthy to
   * redirect.
   */
  async function handleAuthorizeReturn(query) {
    const rec = pendingAuthz.get(query?.st);
    pendingAuthz.delete(query?.st);
    if (!rec || rec.exp <= nowS()) {
      throw new McpAuthError("invalid_request", "unknown or expired authorization — start over");
    }
    // The approval already happened before the browser got here; poll once,
    // with a few short retries to cover propagation.
    let grants = null;
    for (let i = 0; i < returnPollTries; i++) {
      let body;
      try {
        const res = await doFetch(`${broker}/warrant/poll`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ code: rec.pollCode }),
        });
        body = await res.json().catch(() => ({}));
        if (body.status === "approved") {
          grants = body.grants || [];
          break;
        }
        if (body.status === "denied" || res.status === 410) {
          return errorRedirect(rec.redirectUri, rec.hostState, "access_denied", body.reason || "the approval was denied");
        }
      } catch {
        // transient: retry
      }
      if (i < returnPollTries - 1) await sleep(returnPollDelayMs);
    }
    if (!grants) {
      return errorRedirect(rec.redirectUri, rec.hostState, "access_denied", "the approval could not be confirmed");
    }
    const grant = grants.find((g) => g?.audience === resource && g?.warrant);
    if (!grant) {
      return errorRedirect(rec.redirectUri, rec.hostState, "access_denied", "no warrant was granted for this resource");
    }
    // Hold the warrant now (validates grantee + holder against the gateway
    // credential — a mis-issued warrant fails here, not opaquely at /token)…
    try {
      await withAgent((agent) => agent.addGrant(grant.warrant));
    } catch (e) {
      return errorRedirect(rec.redirectUri, rec.hostState, "access_denied", `unusable warrant: ${e.message}`);
    }
    // …and ALSO bind it to the code: at token time it is re-held under the
    // agent lock, so concurrent users of this shared audience can't swap
    // each other's warrants.
    const code = `oac_${randomBytes(32).toString("base64url")}`;
    codes.set(code, {
      clientId: rec.clientId,
      redirectUri: rec.redirectUri,
      codeChallenge: rec.codeChallenge,
      grant: grant.warrant,
      exp: nowS() + codeTtlS,
    });
    return {
      redirect:
        `${rec.redirectUri}${rec.redirectUri.includes("?") ? "&" : "?"}` +
        new URLSearchParams({
          code,
          ...(rec.hostState != null ? { state: rec.hostState } : {}),
        }).toString(),
    };
  }

  // --- POST /token (authorization_code branch) ---------------------------------

  /**
   * `POST /token` for a lane-enabled server: handles
   * `grant_type=authorization_code`; everything else (the jwt-bearer branch
   * verbatim) is delegated to `mcpAuth.handleToken`. The minted bearer goes
   * through the SAME `redeemPresentation` verify path as Lane A.
   */
  async function handleToken(params) {
    const p = params || {};
    if (p.grant_type !== AUTH_CODE_GRANT) {
      if (p.grant_type === JWT_BEARER_GRANT) return mcpAuth.handleToken(p);
      throw new McpAuthError(
        "unsupported_grant_type",
        `only ${JWT_BEARER_GRANT} and ${AUTH_CODE_GRANT} are supported`
      );
    }
    if (typeof p.code !== "string" || !p.code) {
      throw new McpAuthError("invalid_request", "missing 'code'");
    }
    // Single use: delete on read — a replayed code finds nothing.
    const rec = codes.get(p.code);
    codes.delete(p.code);
    if (!rec || rec.exp <= nowS()) {
      throw new McpAuthError("invalid_grant", "unknown, used, or expired code");
    }
    // Bound to the client + redirect_uri the code was issued for.
    if (p.client_id !== rec.clientId) {
      throw new McpAuthError("invalid_grant", "code was not issued to this client");
    }
    if (p.redirect_uri !== rec.redirectUri) {
      throw new McpAuthError("invalid_grant", "redirect_uri does not match the authorization request");
    }
    // …and to the PKCE challenge. S256 only.
    if (!verifyPkceS256(p.code_verifier, rec.codeChallenge)) {
      throw new McpAuthError("invalid_grant", "PKCE verification failed");
    }
    // Mint the presentation under the agent lock, re-holding THIS code's
    // warrant so the presentation is provably the approving user's.
    let presentation;
    try {
      presentation = await withAgent((agent) => {
        agent.addGrant(rec.grant);
        return agent.assertionFor(resource);
      });
    } catch (e) {
      throw new McpAuthError("invalid_grant", `could not mint a presentation: ${e.message}`);
    }
    // The same verify+mint path as Lane A: /verify-access binds the
    // audience, fail-closed, and the bearer lands in the same store.
    return mcpAuth.redeemPresentation(presentation, p.scope);
  }

  return {
    resource,
    broker,
    authorizationServerMetadata,
    handleRegister,
    handleAuthorize,
    handleAuthorizeReturn,
    handleToken,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function req(o, k) {
  if (!o || o[k] == null || o[k] === "") throw new Error(`mcp-auth: '${k}' is required`);
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

export { JWT_BEARER_GRANT, AUTH_CODE_GRANT };
