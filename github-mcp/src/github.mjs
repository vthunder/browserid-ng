// GitHub App client — server→GitHub auth for github-mcp.
//
// Mints an App JWT (RS256, hand-rolled on node:crypto — no octokit; the whole
// exchange is three fetch calls and keeping the dependency footprint at
// mcp-demo's three deps matters more than a client library), exchanges it for
// a short-lived INSTALLATION ACCESS TOKEN, caches that token until near
// expiry, and auto-refreshes — including a one-shot re-mint + retry if GitHub
// 401s a token we thought was still good.
//
// v1 is single-install: the server resolves ONE installation (the first from
// GET /app/installations, or GITHUB_INSTALLATION_ID) and uses it for every
// request. The per-agent scoping/attribution/revocation story lives in the
// warrant layer (see src/server.mjs), not here.

import { sign } from "node:crypto";
import { readFileSync } from "node:fs";

const b64uJson = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

/**
 * Resolve the App private key from the environment: GITHUB_APP_PRIVATE_KEY_FILE
 * (a path — wins when both are set) or GITHUB_APP_PRIVATE_KEY (the PEM itself).
 * Returns null when neither is set.
 */
export function loadPrivateKeyFromEnv(env = process.env) {
  if (env.GITHUB_APP_PRIVATE_KEY_FILE) {
    return readFileSync(env.GITHUB_APP_PRIVATE_KEY_FILE, "utf8");
  }
  return env.GITHUB_APP_PRIVATE_KEY || null;
}

/**
 * @param {object} opts
 * @param {string|number} opts.appId       GitHub App ID (JWT issuer).
 * @param {string} opts.privateKey         App private key, PEM (PKCS#1 or PKCS#8).
 * @param {string} [opts.apiUrl]           GitHub API base (default https://api.github.com;
 *                                         point at a local mock in tests).
 * @param {string|number} [opts.installationId]  Pin the installation; skips discovery.
 * @param {typeof fetch} [opts.fetch]      Injectable fetch (tests).
 * @param {() => number} [opts.nowMs]      Injectable clock (tests).
 * @param {number} [opts.tokenSkewS]       Refresh the installation token this many
 *                                         seconds before its expiry (default 300).
 */
export function createGitHubApp(opts) {
  const appId = opts.appId;
  const privateKey = opts.privateKey;
  if (!appId) throw new Error("createGitHubApp: 'appId' is required (GITHUB_APP_ID)");
  if (!privateKey) {
    throw new Error(
      "createGitHubApp: 'privateKey' is required (GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_FILE)"
    );
  }
  const base = (opts.apiUrl || "https://api.github.com").replace(/\/+$/, "");
  const doFetch = opts.fetch || globalThis.fetch;
  const nowMs = opts.nowMs || (() => Date.now());
  const tokenSkewS = opts.tokenSkewS ?? 300;

  // --- App JWT (authenticates as the App itself, for /app/* endpoints) ------

  function appJwt() {
    const t = Math.floor(nowMs() / 1000);
    // iat backdated 60s for clock drift; exp well under GitHub's 10-minute cap.
    const signingInput = `${b64uJson({ alg: "RS256", typ: "JWT" })}.${b64uJson({
      iat: t - 60,
      exp: t + 540,
      iss: String(appId),
    })}`;
    const sig = sign("RSA-SHA256", Buffer.from(signingInput), privateKey);
    return `${signingInput}.${sig.toString("base64url")}`;
  }

  // --- raw API call ---------------------------------------------------------

  async function gh(path, { method = "GET", token, body } = {}) {
    const headers = {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "browserid-github-mcp",
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await doFetch(`${base}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data && data.message ? `: ${data.message}` : "";
      throw new Error(`GitHub ${method} ${path} → HTTP ${res.status}${detail}`);
    }
    return data;
  }

  // --- installation resolution (v1: one installation for everything) --------

  let installationId = opts.installationId ? Number(opts.installationId) : null;

  async function resolveInstallationId() {
    if (installationId) return installationId;
    const installs = await gh("/app/installations", { token: appJwt() });
    if (!Array.isArray(installs) || installs.length === 0) {
      throw new Error(
        "the GitHub App has no installations — install it on a repo first (or set GITHUB_INSTALLATION_ID)"
      );
    }
    installationId = installs[0].id;
    return installationId;
  }

  // --- installation access token: mint, cache, refresh near expiry ----------

  let cached = null; // { token, expMs }

  async function installationToken() {
    if (cached && nowMs() < cached.expMs - tokenSkewS * 1000) return cached.token;
    const id = await resolveInstallationId();
    const out = await gh(`/app/installations/${id}/access_tokens`, {
      method: "POST",
      token: appJwt(),
    });
    const expMs = Date.parse(out.expires_at || "") || nowMs() + 3600_000;
    cached = { token: out.token, expMs };
    return cached.token;
  }

  /** Call GitHub as the installation; on a 401, re-mint once and retry. */
  async function call(path, callOpts = {}) {
    const token = await installationToken();
    try {
      return await gh(path, { ...callOpts, token });
    } catch (e) {
      if (!/HTTP 401/.test(e.message)) throw e;
      cached = null; // the token was revoked/expired out from under us
      return gh(path, { ...callOpts, token: await installationToken() });
    }
  }

  const encPath = (p) => p.split("/").map(encodeURIComponent).join("/");

  return {
    appJwt,
    resolveInstallationId,
    installationToken,
    /** {total_count, repositories: [{full_name, private, ...}]} */
    listRepos: () => call("/installation/repositories"),
    /** Contents API: a file object (base64) or an array for a directory. */
    readFile: (repo, path, ref) =>
      call(`/repos/${repo}/contents/${encPath(path)}${ref ? `?ref=${encodeURIComponent(ref)}` : ""}`),
    listIssues: (repo, state) =>
      call(`/repos/${repo}/issues${state ? `?state=${encodeURIComponent(state)}` : ""}`),
    createIssue: (repo, title, body) =>
      call(`/repos/${repo}/issues`, { method: "POST", body: { title, body: body || "" } }),
    commentIssue: (repo, issueNumber, body) =>
      call(`/repos/${repo}/issues/${issueNumber}/comments`, { method: "POST", body: { body } }),
  };
}
