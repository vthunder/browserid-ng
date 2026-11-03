// OAuth 2.1 AS + RS in one place (design doc §6). The wallet service is the
// MCP resource server; the embedded authorization server is one authorize
// page + token endpoint, and the authorize page's login step IS browserid
// sign-in (humans only — the verifier rejects agent presentations by default).
//
// Spec surface: RFC 9728 (protected-resource metadata), RFC 8414 (AS
// metadata), RFC 7591 (dynamic client registration — what claude.ai uses
// today), RFC 8707 (resource binding), RFC 9207 (iss in the authorization
// response), PKCE S256 only. Client ID Metadata Documents are deliberately
// NOT implemented yet: fetching arbitrary client_id URLs is an SSRF surface
// this service shouldn't grow in its MVP (see design doc §6).
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  WALLET_ORIGIN, ACCESS_TOKEN_TTL_S, REFRESH_TOKEN_TTL_S, AUTH_CODE_TTL_S,
  SESSION_TTL_S, SESSION_SECRET, WALLET_SCOPE, PRODUCTION,
} from "./config.mjs";
import { nowS } from "./db.mjs";

const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const b64uSha256 = (s) => createHash("sha256").update(s).digest("base64url");
const token = (prefix) => `${prefix}_${randomBytes(32).toString("base64url")}`;

// --- session cookie (authorize page only) ----------------------------------

/** The authorize-page session: the signed-in email plus the sign-in's
 *  status refs (spec §6.4 — "logged out everywhere"), re-checked fail-closed
 *  before the session approves a connection and at every refresh of the
 *  tokens it produced (audit 2026-11 D13). */
export function signSession(email, statusRefs = []) {
  const refs = Array.isArray(statusRefs) ? statusRefs : [];
  const p = Buffer.from(JSON.stringify({ email, refs, exp: nowS() + SESSION_TTL_S })).toString("base64url");
  const sig = createHmac("sha256", SESSION_SECRET).update(p).digest("base64url");
  return `${p}.${sig}`;
}

export function verifySession(cookieHeader) {
  const raw = Object.fromEntries(
    (cookieHeader || "").split(";").map((c) => c.trim().split("=").map(decodeURIComponent)).filter((x) => x[0])
  )["wsid"];
  if (!raw || !raw.includes(".")) return null;
  const [p, sig] = raw.split(".");
  const expect = createHmac("sha256", SESSION_SECRET).update(p).digest("base64url");
  if (sig.length !== expect.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  try {
    const obj = JSON.parse(Buffer.from(p, "base64url").toString());
    return obj.exp > nowS() ? obj : null;
  } catch {
    return null;
  }
}

export const sessionCookie = (value, maxAge = SESSION_TTL_S) =>
  `wsid=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${PRODUCTION ? "; Secure" : ""}`;

// --- discovery --------------------------------------------------------------

export function protectedResourceMetadata() {
  return {
    resource: WALLET_ORIGIN,
    authorization_servers: [WALLET_ORIGIN],
    scopes_supported: [WALLET_SCOPE],
    bearer_methods_supported: ["header"],
  };
}

export function authorizationServerMetadata() {
  return {
    issuer: WALLET_ORIGIN,
    authorization_endpoint: `${WALLET_ORIGIN}/authorize`,
    token_endpoint: `${WALLET_ORIGIN}/oauth/token`,
    registration_endpoint: `${WALLET_ORIGIN}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint: `${WALLET_ORIGIN}/oauth/revoke`,
    revocation_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [WALLET_SCOPE],
    authorization_response_iss_parameter_supported: true,
  };
}

// --- clients (RFC 7591) -----------------------------------------------------

function validRedirectUri(u) {
  try {
    const url = new URL(u);
    if (url.protocol === "https:") return true;
    // http is dev-only, loopback-only.
    return !PRODUCTION && url.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname === "::1" ? "[::1]" : url.hostname);
  } catch {
    return false;
  }
}

export function registerClient(db, body) {
  const uris = body?.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === "string" && validRedirectUri(u))) {
    return { error: "invalid_redirect_uri", error_description: "redirect_uris must be a non-empty array of https URLs" };
  }
  const clientId = token("cid");
  const name = typeof body.client_name === "string" ? body.client_name.slice(0, 120) : null;
  db.prepare("INSERT INTO oauth_clients (client_id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?)")
    .run(clientId, name, JSON.stringify(uris), nowS());
  return {
    client_id: clientId,
    client_id_issued_at: nowS(),
    client_name: name ?? undefined,
    redirect_uris: uris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
}

export function getClient(db, clientId) {
  const row = db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(clientId);
  return row ? { ...row, redirect_uris: JSON.parse(row.redirect_uris) } : null;
}

// --- authorize --------------------------------------------------------------

/**
 * Validate the query half of an authorization request. Returns
 * { ok, params } or { ok: false, status, error } — a bad client/redirect pair
 * must render an error page and NEVER redirect (open-redirect hygiene).
 */
export function checkAuthorizeRequest(db, q) {
  const client = q.client_id && getClient(db, q.client_id);
  if (!client) return { ok: false, status: 400, error: "unknown client_id" };
  if (!client.redirect_uris.includes(q.redirect_uri)) {
    return { ok: false, status: 400, error: "redirect_uri is not registered for this client" };
  }
  if (q.response_type !== "code") return { ok: false, status: 400, error: "response_type must be 'code'" };
  if (!q.code_challenge || q.code_challenge_method !== "S256") {
    return { ok: false, status: 400, error: "PKCE with code_challenge_method=S256 is required" };
  }
  if (q.resource && q.resource.replace(/\/$/, "") !== WALLET_ORIGIN) {
    return { ok: false, status: 400, error: `resource must be ${WALLET_ORIGIN}` };
  }
  const scope = q.scope || WALLET_SCOPE;
  if (scope !== WALLET_SCOPE) return { ok: false, status: 400, error: `scope must be '${WALLET_SCOPE}'` };
  return {
    ok: true,
    client,
    params: {
      client_id: q.client_id,
      redirect_uri: q.redirect_uri,
      state: q.state,
      code_challenge: q.code_challenge,
      scope,
      resource: q.resource || null,
    },
  };
}

/** The signed-in user approved: mint a code, return the redirect URL.
 *  `statusRefs` are the approving sign-in's revocation pointers; they ride
 *  into the tokens the code produces. */
export function approveAuthorization(db, email, params, statusRefs = []) {
  const check = checkAuthorizeRequest(db, { ...params, response_type: "code", code_challenge_method: "S256" });
  if (!check.ok) return check;
  const code = token("wac");
  db.prepare(
    `INSERT INTO oauth_codes (code, client_id, account_email, redirect_uri, code_challenge, scope, resource, expires_at, status_refs)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(sha256(code), params.client_id, email, params.redirect_uri, params.code_challenge,
    check.params.scope, params.resource ?? null, nowS() + AUTH_CODE_TTL_S, JSON.stringify(Array.isArray(statusRefs) ? statusRefs : []));
  const url = new URL(params.redirect_uri);
  url.searchParams.set("code", code);
  if (params.state) url.searchParams.set("state", params.state);
  url.searchParams.set("iss", WALLET_ORIGIN); // RFC 9207
  return { ok: true, redirect: url.href };
}

// --- token ------------------------------------------------------------------

function issueTokenPair(db, { clientId, email, scope, rotatedFrom = null, statusRefs = "[]" }) {
  const access = token("wat");
  const refresh = token("wrt");
  const t = nowS();
  const ins = db.prepare(
    `INSERT INTO oauth_tokens (token_hash, kind, client_id, account_email, scope, expires_at, revoked, rotated_from, created_at, status_refs)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`
  );
  ins.run(sha256(access), "access", clientId, email, scope, t + ACCESS_TOKEN_TTL_S, null, t, statusRefs);
  ins.run(sha256(refresh), "refresh", clientId, email, scope, t + REFRESH_TOKEN_TTL_S, rotatedFrom, t, statusRefs);
  return {
    access_token: access,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_S,
    refresh_token: refresh,
    scope,
  };
}

const tokenError = (error, description) => ({ error, error_description: description });

const burnFamily = (db, email, clientId) =>
  db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE account_email = ? AND client_id = ?").run(email, clientId);

/**
 * POST /oauth/token — form-encoded body, public client (auth method none).
 * `checkStatus(refs)` is the verifier's status re-check ({ok, revoked} |
 * {ok:false}); a refresh is granted only when the sign-in behind the
 * connection is provably unrevoked (audit 2026-11 D13, decision Q21 (a)).
 */
export async function tokenGrant(db, form, { checkStatus } = {}) {
  if (form.grant_type === "authorization_code") {
    const { code, code_verifier, client_id, redirect_uri, resource } = form;
    if (!code || !code_verifier || !client_id) return tokenError("invalid_request", "code, code_verifier and client_id are required");
    const row = db.prepare("SELECT * FROM oauth_codes WHERE code = ?").get(sha256(code));
    if (!row) return tokenError("invalid_grant", "unknown code");
    if (row.used) {
      // A replayed code means the code leaked — burn everything it produced.
      db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE account_email = ? AND client_id = ?")
        .run(row.account_email, row.client_id);
      return tokenError("invalid_grant", "code already redeemed");
    }
    db.prepare("UPDATE oauth_codes SET used = 1 WHERE code = ?").run(sha256(code));
    if (row.expires_at < nowS()) return tokenError("invalid_grant", "code expired");
    if (row.client_id !== client_id) return tokenError("invalid_grant", "client mismatch");
    if (row.redirect_uri !== redirect_uri) return tokenError("invalid_grant", "redirect_uri mismatch");
    if (b64uSha256(code_verifier) !== row.code_challenge) return tokenError("invalid_grant", "PKCE verification failed");
    if (resource && resource.replace(/\/$/, "") !== WALLET_ORIGIN) return tokenError("invalid_target", `resource must be ${WALLET_ORIGIN}`);
    return { ...issueTokenPair(db, { clientId: client_id, email: row.account_email, scope: row.scope, statusRefs: row.status_refs || "[]" }), account_email: row.account_email };
  }

  if (form.grant_type === "refresh_token") {
    const { refresh_token, client_id } = form;
    if (!refresh_token || !client_id) return tokenError("invalid_request", "refresh_token and client_id are required");
    const hash = sha256(refresh_token);
    const row = db.prepare("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'").get(hash);
    if (!row || row.client_id !== client_id) return tokenError("invalid_grant", "unknown refresh token");
    if (row.revoked) {
      // Reuse of a rotated refresh token — assume theft, burn the family.
      burnFamily(db, row.account_email, row.client_id);
      return tokenError("invalid_grant", "refresh token reuse detected; all tokens revoked");
    }
    if (row.expires_at < nowS()) return tokenError("invalid_grant", "refresh token expired");
    // The sign-in behind this connection must still be live. Fail closed:
    // no refs (a pre-D13 row), an unreachable verifier, or a revoked login
    // all refuse; a revoked login also ends the connection.
    let refs = null;
    try { refs = JSON.parse(row.status_refs || "null"); } catch { refs = null; }
    if (!Array.isArray(refs) || typeof checkStatus !== "function") {
      return tokenError("invalid_grant", "the sign-in behind this connection cannot be re-checked; connect again");
    }
    const st = await checkStatus(refs);
    if (!st || st.ok !== true) return tokenError("invalid_grant", "sign-in status unavailable (fail-closed); try again later");
    if (st.revoked === true) {
      burnFamily(db, row.account_email, row.client_id);
      return tokenError("invalid_grant", "the sign-in behind this connection was revoked; connect again");
    }
    db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE token_hash = ?").run(hash);
    return { ...issueTokenPair(db, { clientId: client_id, email: row.account_email, scope: row.scope, rotatedFrom: hash, statusRefs: row.status_refs }), account_email: row.account_email };
  }

  return tokenError("unsupported_grant_type", "use authorization_code or refresh_token");
}

/**
 * POST /oauth/revoke — RFC 7009. `token` (access or refresh) from the public
 * client it was issued to ends the whole connection: every token for that
 * (account, client) pair is revoked. Unknown or foreign tokens answer 200
 * without effect, as the RFC asks. Returns { ok, revoked: n, account_email? }.
 */
export function revokeToken(db, form) {
  const { token: t, client_id } = form;
  if (!t || !client_id) return tokenError("invalid_request", "token and client_id are required");
  const row = db.prepare("SELECT * FROM oauth_tokens WHERE token_hash = ?").get(sha256(t));
  if (!row || row.client_id !== client_id) return { ok: true, revoked: 0 };
  const r = burnFamily(db, row.account_email, row.client_id);
  return { ok: true, revoked: r.changes, account_email: row.account_email };
}

/** The tenant's lever: end every connection at once (the /account page). */
export function disconnectAll(db, email) {
  const r = db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE account_email = ? AND revoked = 0").run(email);
  return { revoked: r.changes };
}

/** Live connections for the /account page: client names with a usable refresh token. */
export function listConnections(db, email) {
  return db.prepare(
    `SELECT t.client_id, c.name, MAX(t.created_at) AS since
       FROM oauth_tokens t LEFT JOIN oauth_clients c ON c.client_id = t.client_id
      WHERE t.account_email = ? AND t.kind = 'refresh' AND t.revoked = 0 AND t.expires_at > ?
      GROUP BY t.client_id`
  ).all(email, nowS()).map((r) => ({ client_id: r.client_id, name: r.name, since: r.since }));
}

// --- resource-server auth ---------------------------------------------------

/**
 * Authenticate a bearer request to /mcp. Returns { email, clientId } or null.
 * 401s must carry WWW-Authenticate pointing at the RFC 9728 document — that
 * header is how an MCP client discovers where to go authorize.
 */
export function authenticateBearer(db, authorizationHeader) {
  const m = /^Bearer\s+(.+)$/i.exec(authorizationHeader || "");
  if (!m) return null;
  const row = db.prepare("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'access'").get(sha256(m[1]));
  if (!row || row.revoked || row.expires_at < nowS()) return null;
  return { email: row.account_email, clientId: row.client_id };
}

export const wwwAuthenticate = () =>
  `Bearer resource_metadata="${WALLET_ORIGIN}/.well-known/oauth-protected-resource"`;
