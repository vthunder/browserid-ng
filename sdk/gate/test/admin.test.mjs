// The admin console's security gate. Proves: presentation-verified login gated
// to the EXACT admin email (right identity in, wrong 403, none/bad 403/400),
// audience bound to the console origin, session enforcement (no session → 401),
// CSRF required on writes, and forged/expired/tampered cookies rejected. Config
// writes are STAGED (persist only; nothing spawns) — a POST just lands in the
// saved config as a pending mount.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHmac, randomBytes } from "node:crypto";
import { KeyPair } from "@browserid-ng/agent";
import { createGateway } from "../src/gateway.mjs";

const BROKER_PORT = 43370;
const PORT = 43371;
const BROKER = `http://localhost:${BROKER_PORT}`;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const ADMIN = "admin@example.com";
const OTHER = "someone@example.com";
const GATEWAY = "gate@example.com";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (c) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(c)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);
const gatewayKp = KeyPair.generate();
const credential = {
  device_key: Buffer.from(gatewayKp.seed).toString("base64url"),
  agent_device_cert: fakeJws({ typ: "browserid-device-cert-v1", "public-key": { algorithm: "Ed25519", publicKey: gatewayKp.publicKeyB64 }, holder: "svc.gate1", identities: [GATEWAY], iat: nowS(), exp: nowS() + 8.64e6 }),
  idp: BROKER, identity: GATEWAY,
};

// Mock verifier: presentation → email; audience MUST equal the console origin.
const broker = createServer(async (req, res) => {
  const reply = (c, o) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  let raw = ""; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  if (req.url === "/verify-access") {
    const email = { "pres-admin": ADMIN, "pres-other": OTHER }[body.presentation];
    if (!email) return reply(200, { status: "failure", reason: "verification failed" });
    assert.equal(body.audience, ORIGIN, "login audience is the exact console origin");
    return reply(200, { status: "okay", email, grantee: email, holder: "u.1", issuer: "example.com", scopes: [], status_refs: [] });
  }
  reply(404, {});
});

const SECRET = randomBytes(32);
let gw;
before(async () => {
  await new Promise((r) => broker.listen(BROKER_PORT, r));
  gw = createGateway({
    credential, adminEmail: ADMIN, broker: BROKER, origin: ORIGIN,
    persist: false, config: { mounts: [] }, sessionSecret: SECRET, log: () => {},
  });
  await gw.start({ port: PORT });
});
after(async () => { await gw.close(); broker.close(); });

// --- helpers ----------------------------------------------------------------
const post = (path, opts = {}) => fetch(`${ORIGIN}${path}`, { method: "POST", ...opts });
async function login(presentation) {
  const res = await post("/admin/login", {
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ presentation }),
  });
  const cookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const sessionCookie = cookies.map((c) => c.split(";")[0]).find((c) => c.startsWith("gate_session="));
  const data = await res.json().catch(() => ({}));
  return { res, cookie: sessionCookie, csrf: data.csrf, data };
}

// --- login gating -----------------------------------------------------------
test("the admin identity signs in and gets a session + csrf", async () => {
  const { res, cookie, csrf } = await login("pres-admin");
  assert.equal(res.status, 200);
  assert.ok(cookie, "a gate_session cookie is set");
  assert.ok(csrf, "a csrf token is returned");
  const setCookie = res.headers.getSetCookie().find((c) => c.startsWith("gate_session="));
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Lax/);
});

test("a DIFFERENT verified identity is refused (403) — no substring/domain widening", async () => {
  const { res } = await login("pres-other");
  assert.equal(res.status, 403);
});

test("an unverifiable presentation is refused (403)", async () => {
  const { res } = await login("garbage");
  assert.equal(res.status, 403);
});

test("a login with no presentation is a 400", async () => {
  const res = await post("/admin/login", { headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(res.status, 400);
});

// --- session enforcement ----------------------------------------------------
test("no session → 401 on the config API", async () => {
  const res = await fetch(`${ORIGIN}/admin/mounts`);
  assert.equal(res.status, 401);
});

test("a valid session can read the mount list", async () => {
  const { cookie } = await login("pres-admin");
  const res = await fetch(`${ORIGIN}/admin/mounts`, { headers: { cookie } });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(Array.isArray(body.mounts));
});

// --- CSRF -------------------------------------------------------------------
test("a write WITHOUT the CSRF token is refused (403), WITH it succeeds (staged)", async () => {
  const { cookie, csrf } = await login("pres-admin");
  const def = { name: "Notes", mount: "notes", command: ["echo", "hi"], allow: ["dan@example.com"] };

  const noCsrf = await post("/admin/mounts", {
    headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify(def),
  });
  assert.equal(noCsrf.status, 403, "missing CSRF is refused");

  const withCsrf = await post("/admin/mounts", {
    headers: { cookie, "content-type": "application/json", "x-csrf-token": csrf },
    body: JSON.stringify(def),
  });
  assert.equal(withCsrf.status, 201);
  const row = await withCsrf.json();
  // STAGED: persisted but NOT running until restart.
  assert.equal(row.running, false, "a web-added mount does not spawn live");
  assert.equal(row.pending, "new");
  assert.equal(row.needsRestart, true);
});

test("a bad CSRF token is refused even with a valid session", async () => {
  const { cookie } = await login("pres-admin");
  const res = await post("/admin/mounts", {
    headers: { cookie, "content-type": "application/json", "x-csrf-token": "not-the-token" },
    body: JSON.stringify({ name: "X", mount: "x", command: ["echo"], allow: [] }),
  });
  assert.equal(res.status, 403);
});

// --- forged / tampered / expired cookies ------------------------------------
const b64u = (b) => Buffer.from(b).toString("base64url");
function craftCookie(email, exp, secret) {
  const nonce = b64u(randomBytes(32));
  const payload = `v1.${b64u(email)}.${exp}.${nonce}`;
  const mac = b64u(createHmac("sha256", secret).update(payload).digest());
  return `gate_session=v1.${b64u(email)}.${exp}.${nonce}.${mac}`;
}

test("a cookie signed with the WRONG secret is rejected (401)", async () => {
  const forged = craftCookie(ADMIN, nowS() + 3600, randomBytes(32)); // wrong key
  const res = await fetch(`${ORIGIN}/admin/mounts`, { headers: { cookie: forged } });
  assert.equal(res.status, 401);
});

test("a tampered cookie (flipped MAC) is rejected (401)", async () => {
  const { cookie } = await login("pres-admin");
  const flipped = cookie.slice(0, -1) + (cookie.endsWith("A") ? "B" : "A");
  const res = await fetch(`${ORIGIN}/admin/mounts`, { headers: { cookie: flipped } });
  assert.equal(res.status, 401);
});

test("an EXPIRED but correctly-signed cookie is rejected (401)", async () => {
  const expired = craftCookie(ADMIN, nowS() - 10, SECRET); // valid sig, past exp
  const res = await fetch(`${ORIGIN}/admin/mounts`, { headers: { cookie: expired } });
  assert.equal(res.status, 401);
});

test("a validly-signed cookie for a NON-admin email is rejected (401)", async () => {
  const notAdmin = craftCookie(OTHER, nowS() + 3600, SECRET);
  const res = await fetch(`${ORIGIN}/admin/mounts`, { headers: { cookie: notAdmin } });
  assert.equal(res.status, 401);
});

// --- tunnel-less startup ------------------------------------------------------
test("no tunnel available → still starts, on a localhost origin, and says why", async () => {
  const gw2 = createGateway({
    credential, adminEmail: ADMIN, broker: BROKER, persist: false,
    config: { mounts: [] }, sessionSecret: SECRET, log: () => {},
    ensureFunnel: async () => { throw new Error("tailscale not available (is it installed and running?)"); },
  });
  try {
    const info = await gw2.start({ port: 0 });
    assert.match(info.origin, /^http:\/\/127\.0\.0\.1:\d+$/, "falls back to localhost");
    assert.equal(info.public, false);
    assert.match(info.funnelError, /tailscale not available/);
    // The console actually serves on that origin.
    const res = await fetch(`${info.origin}/admin/bootstrap`);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).signedIn, false);
  } finally {
    await gw2.close();
  }
});
