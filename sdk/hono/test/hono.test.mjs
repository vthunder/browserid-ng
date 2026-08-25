import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBrowserID, browseridLogin, browseridSessionValid } from "../index.mjs";

const AUDIENCE = "https://app.example.com";

function fakeBroker({ verify, status } = {}) {
  const f = async (url, init) => {
    const body = init && init.body ? JSON.parse(init.body) : {};
    if (String(url).endsWith("/verify")) {
      f.lastAudience = body.audience;
      return json(verify ?? { status: "failure" });
    }
    if (String(url).endsWith("/status/check")) return json(status ?? { ok: true, revoked: false });
    throw new Error("unexpected " + url);
  };
  return f;
}
const json = (o) => ({ ok: true, status: 200, json: async () => o });
const OK = { status: "okay", email: "dan@sandmill.org", grantee: "dan@sandmill.org", issuer: "sandmill.org", scopes: [], status_refs: [{ uri: "u", idx: 3 }] };

// Minimal Hono-like context stub.
function ctx(body) {
  const store = new Map();
  const out = { jsonBody: null, statusCode: null };
  return {
    _out: out,
    req: { json: async () => { if (body === "throw") throw new Error("no body"); return body; } },
    set: (k, v) => store.set(k, v),
    get: (k) => store.get(k),
    json: (obj, status) => { out.jsonBody = obj; out.statusCode = status || 200; return { _res: true }; },
  };
}

test("audience is required", () => {
  assert.throws(() => verifyBrowserID({}), /audience/);
});

test("verifyBrowserID returns identity + pins audience", async () => {
  const f = fakeBroker({ verify: OK });
  const id = await verifyBrowserID({ audience: AUDIENCE, fetch: f })("AC~AS~WR~CC");
  assert.equal(id.email, "dan@sandmill.org");
  assert.equal(f.lastAudience, AUDIENCE);
});

test("browseridLogin sets context on success", async () => {
  const mw = browseridLogin({ audience: AUDIENCE, fetch: fakeBroker({ verify: OK }) });
  const c = ctx({ presentation: "AC~AS~WR~CC" });
  let nexted = false;
  await mw(c, async () => { nexted = true; });
  assert.equal(nexted, true);
  assert.equal(c.get("browserid").email, "dan@sandmill.org");
});

test("browseridLogin 401s on failure and never calls next", async () => {
  const mw = browseridLogin({ audience: AUDIENCE, fetch: fakeBroker({ verify: { status: "failure" } }) });
  const c = ctx({ presentation: "bad" });
  await mw(c, async () => assert.fail("next should not run"));
  assert.equal(c._out.statusCode, 401);
});

test("browseridLogin 401s on a missing/unparseable body", async () => {
  const mw = browseridLogin({ audience: AUDIENCE, fetch: fakeBroker({ verify: OK }) });
  const c = ctx("throw");
  await mw(c, async () => assert.fail("next should not run"));
  assert.equal(c._out.statusCode, 401);
});

test("browseridSessionValid reflects revocation", async () => {
  const ok = await browseridSessionValid([{ uri: "u", idx: 3 }], { fetch: fakeBroker({ status: { ok: true, revoked: false } }) });
  assert.equal(ok.ok, true);
  const rev = await browseridSessionValid([{ uri: "u", idx: 3 }], { fetch: fakeBroker({ status: { ok: true, revoked: true } }) });
  assert.equal(rev.ok, false);
});
