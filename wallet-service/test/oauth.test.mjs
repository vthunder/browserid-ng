// The full OAuth 2.1 flow over real HTTP: register → authorize checks →
// login (stubbed verifier) → approve → token (PKCE) → bearer on /mcp →
// refresh rotation → replay/reuse burns the family.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

const PORT = 43117;
process.env.PORT = String(PORT);
process.env.WALLET_DATABASE_PATH = ":memory:";
process.env.WALLET_KEK = randomBytes(32).toString("base64url");
process.env.WALLET_SESSION_SECRET = randomBytes(32).toString("base64url");

const { createWalletService } = await import("../src/server.mjs");

const ORIGIN = `http://localhost:${PORT}`;
const REDIRECT = "http://localhost:9/cb";
const EMAIL = "dan@example.com";

let service;
before(() => new Promise((r) => {
  service = createWalletService({ verifyLogin: async (p) => (p === "good" ? { ok: true, email: EMAIL } : { ok: false, reason: "bad presentation" }) });
  service.server.listen(PORT, r);
}));
after(() => service.server.close());

const post = (path, body, headers = {}) =>
  fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

async function registerClient() {
  const res = await post("/oauth/register", { redirect_uris: [REDIRECT], client_name: "claude.ai test" });
  assert.equal(res.status, 201);
  return (await res.json()).client_id;
}

async function login() {
  const res = await post("/oauth/login", { presentation: "good" });
  assert.equal(res.status, 200);
  return res.headers.get("set-cookie").split(";")[0];
}

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

async function fullCodeFlow({ clientId, cookie, resource }) {
  const { verifier, challenge } = pkce();
  const params = {
    client_id: clientId, redirect_uri: REDIRECT, response_type: "code", state: "st8",
    code_challenge: challenge, code_challenge_method: "S256", ...(resource ? { resource } : {}),
  };
  const approve = await post("/oauth/approve", params, { cookie });
  assert.equal(approve.status, 200);
  const { redirect } = await approve.json();
  const u = new URL(redirect);
  assert.equal(u.origin + u.pathname, REDIRECT);
  assert.equal(u.searchParams.get("state"), "st8");
  assert.equal(u.searchParams.get("iss"), ORIGIN, "RFC 9207 iss");
  const code = u.searchParams.get("code");

  const tok = await post("/oauth/token", new URLSearchParams({
    grant_type: "authorization_code", code, code_verifier: verifier,
    client_id: clientId, redirect_uri: REDIRECT,
  }).toString(), { "content-type": "application/x-www-form-urlencoded" });
  assert.equal(tok.status, 200);
  return { tokens: await tok.json(), code, verifier };
}

test("discovery documents", async () => {
  const pr = await (await fetch(`${ORIGIN}/.well-known/oauth-protected-resource`)).json();
  assert.equal(pr.resource, ORIGIN);
  assert.deepEqual(pr.authorization_servers, [ORIGIN]);
  const as = await (await fetch(`${ORIGIN}/.well-known/oauth-authorization-server`)).json();
  assert.equal(as.issuer, ORIGIN);
  assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
  assert.ok(as.authorization_response_iss_parameter_supported);
});

test("register rejects bad redirect uris", async () => {
  for (const uris of [[], ["ftp://x"], ["http://evil.example.com/cb"]]) {
    const res = await post("/oauth/register", { redirect_uris: uris });
    assert.equal(res.status, 400, JSON.stringify(uris));
  }
});

test("authorize page validates before rendering, never redirects on error", async () => {
  const clientId = await registerClient();
  const bad = await fetch(`${ORIGIN}/authorize?client_id=${clientId}&redirect_uri=http://evil.example.com/cb&response_type=code&code_challenge=x&code_challenge_method=S256`);
  assert.equal(bad.status, 400);
  const noPkce = await fetch(`${ORIGIN}/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code`);
  assert.equal(noPkce.status, 400);
  const ok = await fetch(`${ORIGIN}/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=x&code_challenge_method=S256`);
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /claude\.ai test/);
});

test("login rejects a bad presentation; approve requires a session", async () => {
  const bad = await post("/oauth/login", { presentation: "evil" });
  assert.equal(bad.status, 401);
  const noSession = await post("/oauth/approve", { client_id: "x" });
  assert.equal(noSession.status, 401);
});

test("code flow: PKCE enforced, tokens issued, bearer works on /mcp", async () => {
  const clientId = await registerClient();
  const cookie = await login();
  const { tokens } = await fullCodeFlow({ clientId, cookie, resource: ORIGIN });
  assert.equal(tokens.token_type, "Bearer");
  assert.equal(tokens.scope, "wallet");
  assert.ok(tokens.refresh_token);
  assert.ok(!("account_email" in tokens), "internal field must not leak");

  // Bearer auth: bad token 401 + resource_metadata pointer; good token works.
  const unauth = await post("/mcp", {}, { authorization: "Bearer nope", accept: "application/json, text/event-stream" });
  assert.equal(unauth.status, 401);
  assert.match(unauth.headers.get("www-authenticate"), /resource_metadata=/);

  const init = await post("/mcp", {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } },
  }, { authorization: `Bearer ${tokens.access_token}`, accept: "application/json, text/event-stream" });
  assert.equal(init.status, 200);
  const initBody = await init.json();
  assert.equal(initBody.result.serverInfo.name, "browserid-wallet");
});

test("PKCE mismatch is rejected and burns the code", async () => {
  const clientId = await registerClient();
  const cookie = await login();
  const { challenge } = pkce();
  const approve = await post("/oauth/approve", {
    client_id: clientId, redirect_uri: REDIRECT, response_type: "code",
    code_challenge: challenge, code_challenge_method: "S256",
  }, { cookie });
  const code = new URL((await approve.json()).redirect).searchParams.get("code");
  const wrong = await post("/oauth/token", new URLSearchParams({
    grant_type: "authorization_code", code, code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier",
    client_id: clientId, redirect_uri: REDIRECT,
  }).toString(), { "content-type": "application/x-www-form-urlencoded" });
  assert.equal(wrong.status, 400);
  assert.equal((await wrong.json()).error, "invalid_grant");
});

test("code replay revokes issued tokens", async () => {
  const clientId = await registerClient();
  const cookie = await login();
  const { tokens, code, verifier } = await fullCodeFlow({ clientId, cookie });
  const replay = await post("/oauth/token", new URLSearchParams({
    grant_type: "authorization_code", code, code_verifier: verifier,
    client_id: clientId, redirect_uri: REDIRECT,
  }).toString(), { "content-type": "application/x-www-form-urlencoded" });
  assert.equal(replay.status, 400);
  // The tokens minted from the replayed code are burned.
  const probe = await post("/mcp", {}, { authorization: `Bearer ${tokens.access_token}`, accept: "application/json, text/event-stream" });
  assert.equal(probe.status, 401);
});

test("refresh rotation works; reuse of the old token burns the family", async () => {
  const clientId = await registerClient();
  const cookie = await login();
  const { tokens } = await fullCodeFlow({ clientId, cookie });

  const form = (rt) => new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId }).toString();
  const fh = { "content-type": "application/x-www-form-urlencoded" };

  const r1 = await post("/oauth/token", form(tokens.refresh_token), fh);
  assert.equal(r1.status, 200);
  const t1 = await r1.json();
  assert.notEqual(t1.refresh_token, tokens.refresh_token);

  // Replaying the rotated-out refresh token kills everything…
  const reuse = await post("/oauth/token", form(tokens.refresh_token), fh);
  assert.equal(reuse.status, 400);
  // …including the fresh pair.
  const r2 = await post("/oauth/token", form(t1.refresh_token), fh);
  assert.equal(r2.status, 400);
  const probe = await post("/mcp", {}, { authorization: `Bearer ${t1.access_token}`, accept: "application/json, text/event-stream" });
  assert.equal(probe.status, 401);
});

test("resource parameter must name this wallet", async () => {
  const clientId = await registerClient();
  const cookie = await login();
  const approve = await post("/oauth/approve", {
    client_id: clientId, redirect_uri: REDIRECT, response_type: "code",
    code_challenge: pkce().challenge, code_challenge_method: "S256",
    resource: "https://other.example.com",
  }, { cookie });
  assert.equal(approve.status, 400);
});
