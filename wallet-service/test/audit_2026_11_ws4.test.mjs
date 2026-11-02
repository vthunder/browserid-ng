// Security audit 2026-11, WS4 — the hosted wallet (wallet-service): sign-in
// admission, tenant keying, session/token lifetime vs login revocation, and
// the OAuth AS edges the existing suites do not pin.
//
// Tests that FAIL today are skipped with `AUDIT-2026-11 <id>: fails today`;
// un-skipping is the acceptance test for the fix. Everything else pins what
// the audit re-verified. No production code is changed.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

const PORT = 43119;
process.env.PORT = String(PORT);
process.env.WALLET_DATABASE_PATH = ":memory:";
process.env.WALLET_KEK = randomBytes(32).toString("base64url");
process.env.WALLET_SESSION_SECRET = randomBytes(32).toString("base64url");

const { createWalletService } = await import("../src/server.mjs");

const ORIGIN = `http://localhost:${PORT}`;
const REDIRECT = "http://localhost:9/cb";

// The stubbed verifier answers per presentation string, in the shape
// @browserid-ng/verify returns: { ok, email, grantee, scopes, statusRefs }.
const VERDICTS = {
  human: { ok: true, email: "dan@example.com", grantee: "dan@example.com", scopes: ["login"], statusRefs: [{ uri: "https://idp.example/status/1", idx: 7 }] },
  // A delegated presentation: an agent identity acting for dan under a warrant
  // whose audience is this wallet (grantee != email).
  agent: { ok: true, email: "dan@example.com", grantee: "dan+agent@example.com", scopes: ["login"], statusRefs: [] },
  // Same mailbox, different local-part case, as a verifier would relay it.
  upper: { ok: true, email: "Dan@example.com", grantee: "Dan@example.com", scopes: ["login"], statusRefs: [] },
  // A presentation whose warrant does not carry the login scope.
  noscope: { ok: true, email: "dan@example.com", grantee: "dan@example.com", scopes: ["guestbook-sign"], statusRefs: [] },
};

let service;
before(() => new Promise((r) => {
  service = createWalletService({
    verifyLogin: async (p) => VERDICTS[p] || { ok: false, reason: "bad presentation" },
  });
  service.server.listen(PORT, r);
}));
after(() => service.server.close());

const post = (path, body, headers = {}) =>
  fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
    redirect: "manual",
  });

async function registerClient() {
  const res = await post("/oauth/register", { redirect_uris: [REDIRECT], client_name: "audit" });
  return (await res.json()).client_id;
}
async function login(presentation = "human") {
  const res = await post("/oauth/login", { presentation });
  return { status: res.status, cookie: (res.headers.get("set-cookie") || "").split(";")[0], body: await res.json() };
}
function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}
async function tokens({ clientId, cookie }) {
  const { verifier, challenge } = pkce();
  const approve = await post("/oauth/approve", {
    client_id: clientId, redirect_uri: REDIRECT, response_type: "code",
    code_challenge: challenge, code_challenge_method: "S256",
  }, { cookie });
  assert.equal(approve.status, 200);
  const code = new URL((await approve.json()).redirect).searchParams.get("code");
  const tok = await post("/oauth/token", new URLSearchParams({
    grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: REDIRECT,
  }).toString(), { "content-type": "application/x-www-form-urlencoded" });
  assert.equal(tok.status, 200);
  return tok.json();
}
const mcpProbe = (access) =>
  post("/mcp", { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } },
    { authorization: `Bearer ${access}`, accept: "application/json, text/event-stream" });

// ---------------------------------------------------------------------------
// W4-22 — delegated (agent) presentations open a tenant as the human

// server.mjs:34 says "Human sign-in only: the default verifier rejects
// subject=agent" — but @browserid-ng/verify removed allowAgent (July M2) and
// now tells RPs to compare grantee with email themselves. /oauth/login
// never does, so an agent holding a login warrant for this wallet's origin
// becomes the human's tenant: full control of the custodied agent key.
test("W4-22: a delegated presentation (grantee != email) does not open the human's tenant", { skip: "AUDIT-2026-11 W4-22: fails today — /oauth/login keys the tenant on email and ignores grantee" }, async () => {
  const r = await login("agent");
  assert.equal(r.status, 401);
});

test("W4-22 (pinned): a presentation without the login scope is still admitted today — no scope policy at /oauth/login", async () => {
  // Pinned as observed behaviour, not as intended; see the report. The
  // hosted verifier returns `scopes` and leaves scope policy to the RP
  // (verify.rs:602), so neither layer requires `login` here: any warrant
  // whose audience is this wallet's origin opens the tenant.
  const r = await login("noscope");
  assert.equal(r.status, 200);
});

// ---------------------------------------------------------------------------
// D13 — status refs dropped; session and refresh tokens outlive the login

test("D13 (pinned): the verifier's status refs are not retained anywhere the service could re-check them", async () => {
  await login("human");
  const cols = service.db.prepare("PRAGMA table_info(accounts)").all().map((c) => c.name);
  assert.deepEqual(cols, ["email", "created_at"], "accounts carry no status refs");
  const tables = service.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((t) => t.name);
  assert.ok(!tables.some((t) => /status|ref/i.test(t)), "no status-ref table");
});

// RFC 7009 token revocation is the smallest tenant-side lever: with it the
// human (or the client) can end a connection before the 30-day refresh
// family dies. Today there is no revoke, no logout, and no status re-check.
test("D13: a tenant can revoke a connection (RFC 7009 /oauth/revoke)", { skip: "AUDIT-2026-11 D13: fails today — no revocation endpoint, no logout, no status re-check on refresh" }, async () => {
  const clientId = await registerClient();
  const { cookie } = await login("human");
  const t = await tokens({ clientId, cookie });
  const rev = await post("/oauth/revoke", new URLSearchParams({ token: t.refresh_token, client_id: clientId }).toString(),
    { "content-type": "application/x-www-form-urlencoded" });
  assert.equal(rev.status, 200);
  assert.equal((await mcpProbe(t.access_token)).status, 401);
});

test("D13 (pinned): refresh re-mints without any verifier contact", async () => {
  const clientId = await registerClient();
  const { cookie } = await login("human");
  const t = await tokens({ clientId, cookie });
  let verifierCalls = 0;
  const orig = service.store.ensureAccount.bind(service.store);
  service.store.ensureAccount = (...a) => { verifierCalls++; return orig(...a); };
  const r = await post("/oauth/token", new URLSearchParams({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: clientId }).toString(),
    { "content-type": "application/x-www-form-urlencoded" });
  service.store.ensureAccount = orig;
  assert.equal(r.status, 200);
  assert.equal(verifierCalls, 0);
});

// ---------------------------------------------------------------------------
// D17 — local-part case folding (wallet-service side)

test("D17 (refuted here): tenants are keyed byte-exact on the verifier's email; no folding", async () => {
  await login("human");
  await login("upper");
  const rows = service.db.prepare("SELECT email FROM accounts WHERE lower(email) = 'dan@example.com' ORDER BY email").all().map((r) => r.email);
  assert.deepEqual(rows, ["Dan@example.com", "dan@example.com"]);
  const me = await fetch(`${ORIGIN}/oauth/me`, { headers: { cookie: (await login("upper")).cookie } });
  assert.equal((await me.json()).email, "Dan@example.com");
});

// ---------------------------------------------------------------------------
// OAuth AS edges (pinned)

test("AS (pinned): /oauth/approve and /oauth/login refuse a cross-origin Origin", async () => {
  const { cookie } = await login("human");
  const a = await post("/oauth/approve", { client_id: "x" }, { cookie, origin: "https://evil.example" });
  assert.equal(a.status, 403);
  const l = await post("/oauth/login", { presentation: "human" }, { origin: "https://evil.example" });
  assert.equal(l.status, 403);
});

test("AS (pinned): a code is bound to client_id and redirect_uri; a second client cannot redeem it", async () => {
  const c1 = await registerClient();
  const c2 = await registerClient();
  const { cookie } = await login("human");
  const { verifier, challenge } = pkce();
  const approve = await post("/oauth/approve", {
    client_id: c1, redirect_uri: REDIRECT, response_type: "code", code_challenge: challenge, code_challenge_method: "S256",
  }, { cookie });
  const code = new URL((await approve.json()).redirect).searchParams.get("code");
  const form = (o) => new URLSearchParams(o).toString();
  const fh = { "content-type": "application/x-www-form-urlencoded" };
  const wrongClient = await post("/oauth/token", form({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: c2, redirect_uri: REDIRECT }), fh);
  assert.equal(wrongClient.status, 400);
  // The first redemption attempt marks the code used, whoever made it.
  const rightClient = await post("/oauth/token", form({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: c1, redirect_uri: REDIRECT }), fh);
  assert.equal(rightClient.status, 400);
});

test("AS (pinned): client_name is attacker-chosen and rendered as the consenting party", async () => {
  const res = await post("/oauth/register", { redirect_uris: [REDIRECT], client_name: "Claude (official)" });
  const { client_id } = await res.json();
  const page = await fetch(`${ORIGIN}/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=x&code_challenge_method=S256`);
  assert.match(await page.text(), /Claude \(official\)/);
});

// ---------------------------------------------------------------------------
// W4-23 — rate-limit and audit keys trust X-Forwarded-For

test("W4-23: a client cannot spend another address's login budget, nor reset its own, via X-Forwarded-For", { skip: "AUDIT-2026-11 W4-23: fails today — clientIp() takes the first XFF hop unconditionally (cf. W5-6)" }, async () => {
  for (let i = 0; i < 25; i++) {
    await post("/oauth/login", { presentation: "nope" }, { "x-forwarded-for": `10.0.0.${i}` });
  }
  // Twenty-five bad logins from one socket must be throttled regardless of
  // the header; today each distinct XFF value gets a fresh bucket.
  const r = await post("/oauth/login", { presentation: "nope" }, { "x-forwarded-for": "10.0.0.99" });
  assert.equal(r.status, 429);
});
