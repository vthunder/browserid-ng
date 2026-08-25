import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBrowserID, browseridLogin, Strategy, browseridSessionValid } from "../index.mjs";

const AUDIENCE = "https://api.example.com";

function fakeBroker({ verify, status } = {}) {
  const fetch = async (url, init) => {
    const body = init && init.body ? JSON.parse(init.body) : {};
    if (String(url).endsWith("/verify")) {
      fetch.lastAudience = body.audience;
      return json(verify ?? { status: "failure", reason: "none" });
    }
    if (String(url).endsWith("/status/check")) return json(status ?? { ok: true, revoked: false });
    throw new Error("unexpected " + url);
  };
  return fetch;
}
const json = (o) => ({ ok: true, status: 200, json: async () => o });
const okVerify = {
  status: "okay", email: "dan@sandmill.org", grantee: "dan@sandmill.org",
  issuer: "sandmill.org", scopes: [], status_refs: [{ uri: "u", idx: 3 }],
};

test("audience is required", () => {
  assert.throws(() => verifyBrowserID({}), /audience/);
});

test("verifyBrowserID returns an identity and pins the audience", async () => {
  const fetch = fakeBroker({ verify: okVerify });
  const v = verifyBrowserID({ audience: AUDIENCE, fetch });
  const id = await v("AC~AS~WR~CC");
  assert.equal(id.email, "dan@sandmill.org");
  assert.equal(fetch.lastAudience, AUDIENCE);
});

test("verifyBrowserID fails closed", async () => {
  const v = verifyBrowserID({ audience: AUDIENCE, fetch: fakeBroker({ verify: { status: "failure" } }) });
  assert.equal(await v("x"), null);
  assert.equal(await v(""), null);
  assert.equal(await v(undefined), null);
});

test("browseridLogin middleware attaches req.browserid or 401s", async () => {
  const mw = browseridLogin({ audience: AUDIENCE, fetch: fakeBroker({ verify: okVerify }) });
  // success
  const req = { body: { presentation: "AC~AS~WR~CC" } };
  let nexted = false;
  await mw(req, mockRes(), () => { nexted = true; });
  assert.equal(nexted, true);
  assert.equal(req.browserid.email, "dan@sandmill.org");
  // failure
  const badMw = browseridLogin({ audience: AUDIENCE, fetch: fakeBroker({ verify: { status: "failure" } }) });
  const res = mockRes();
  await badMw({ body: {} }, res, () => assert.fail("should not call next"));
  assert.equal(res.statusCode, 401);
});

test("Passport Strategy: success and fail paths", async () => {
  // no verify callback -> the identity is the user
  const s = new Strategy({ audience: AUDIENCE, fetch: fakeBroker({ verify: okVerify }) });
  const user = await runStrategy(s, { body: { presentation: "AC~AS~WR~CC" } });
  assert.equal(user.kind, "success");
  assert.equal(user.value.email, "dan@sandmill.org");

  // fail on bad presentation
  const s2 = new Strategy({ audience: AUDIENCE, fetch: fakeBroker({ verify: { status: "failure" } }) });
  const out = await runStrategy(s2, { body: {} });
  assert.equal(out.kind, "fail");
});

test("Passport Strategy: verify callback maps to an app user", async () => {
  const s = new Strategy({ audience: AUDIENCE, fetch: fakeBroker({ verify: okVerify }) }, (id, done) => {
    done(null, { appId: 42, email: id.email });
  });
  const out = await runStrategy(s, { body: { presentation: "AC~AS~WR~CC" } });
  assert.equal(out.kind, "success");
  assert.equal(out.value.appId, 42);
});

test("browseridSessionValid reflects revocation", async () => {
  const ok = await browseridSessionValid([{ uri: "u", idx: 3 }], { fetch: fakeBroker({ status: { ok: true, revoked: false } }) });
  assert.equal(ok.ok, true);
  const rev = await browseridSessionValid([{ uri: "u", idx: 3 }], { fetch: fakeBroker({ status: { ok: true, revoked: true } }) });
  assert.equal(rev.ok, false);
});

// --- helpers ---
function mockRes() {
  return {
    statusCode: 200,
    body: null,
    status(c) { this.statusCode = c; return this; },
    json(o) { this.body = o; return this; },
  };
}
function runStrategy(strategy, req) {
  return new Promise((resolve) => {
    strategy.success = (value, info) => resolve({ kind: "success", value, info });
    strategy.fail = (info, status) => resolve({ kind: "fail", info, status });
    strategy.error = (err) => resolve({ kind: "error", err });
    strategy.authenticate(req);
  });
}
