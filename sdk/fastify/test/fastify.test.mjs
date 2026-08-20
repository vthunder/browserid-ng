import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBrowserID, browseridLogin, browseridSessionValid } from "../index.mjs";

const AUDIENCE = "https://api.example.com";

function fakeBroker({ verify, status } = {}) {
  const f = async (url, init) => {
    const body = init && init.body ? JSON.parse(init.body) : {};
    if (String(url).endsWith("/verify-access")) {
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

// Minimal Fastify request/reply stubs.
function reqReply(body) {
  const reply = {
    statusCode: 200, sent: null,
    code(c) { this.statusCode = c; return this; },
    send(o) { this.sent = o; return this; },
  };
  return { request: { body }, reply };
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

test("browseridLogin preHandler attaches request.browserid on success", async () => {
  const pre = browseridLogin({ audience: AUDIENCE, fetch: fakeBroker({ verify: OK }) });
  const { request, reply } = reqReply({ presentation: "AC~AS~WR~CC" });
  const ret = await pre(request, reply);
  assert.equal(ret, undefined); // does not short-circuit
  assert.equal(request.browserid.email, "dan@sandmill.org");
});

test("browseridLogin preHandler 401s + short-circuits on failure", async () => {
  const pre = browseridLogin({ audience: AUDIENCE, fetch: fakeBroker({ verify: { status: "failure" } }) });
  const { request, reply } = reqReply({});
  const ret = await pre(request, reply);
  assert.equal(reply.statusCode, 401);
  assert.equal(ret, reply); // returning reply short-circuits the route
});

test("browseridSessionValid reflects revocation", async () => {
  const ok = await browseridSessionValid([{ uri: "u", idx: 3 }], { fetch: fakeBroker({ status: { ok: true, revoked: false } }) });
  assert.equal(ok.ok, true);
  const rev = await browseridSessionValid([{ uri: "u", idx: 3 }], { fetch: fakeBroker({ status: { ok: true, revoked: true } }) });
  assert.equal(rev.ok, false);
});
