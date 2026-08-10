import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BrowserID,
  browseridAuthorize,
  browseridSessionValid,
} from "../index.mjs";

const AUDIENCE = "https://app.example.com";

// Fake broker: /verify-access -> configurable verify JSON; /status/check ->
// configurable status JSON. Records the last verify body so we can assert the
// audience binding.
function fakeBroker({ verify, status } = {}) {
  const seen = {};
  const fetch = async (url, init) => {
    const body = init && init.body ? JSON.parse(init.body) : {};
    if (String(url).endsWith("/verify-access")) {
      seen.verify = body;
      if (verify === "throw") throw new Error("ECONNREFUSED");
      return json(verify ?? { status: "failure", reason: "no verify configured" });
    }
    if (String(url).endsWith("/status/check")) {
      seen.status = body;
      if (status === "throw") throw new Error("ECONNREFUSED");
      return json(status ?? { ok: true, revoked: false, results: [] });
    }
    throw new Error("unexpected url " + url);
  };
  return { fetch, seen };
}
const json = (obj) => ({ ok: true, status: 200, json: async () => obj });

const okVerify = {
  status: "okay",
  email: "dan@sandmill.org",
  grantee: "dan@sandmill.org",
  issuer: "sandmill.org",
  subject: "user",
  scopes: [],
  status_refs: [{ uri: "https://browserid.me/.well-known/browserid-status", idx: 7 }],
};

test("BrowserID() returns a Credentials-provider options object", () => {
  const p = BrowserID({ audience: AUDIENCE, fetch: fakeBroker().fetch });
  assert.equal(p.id, "browserid");
  assert.equal(p.type, "credentials");
  assert.ok(p.credentials.presentation);
  assert.equal(typeof p.authorize, "function");
});

test("audience is required", () => {
  assert.throws(() => browseridAuthorize({}), /audience/);
  assert.throws(() => BrowserID({}), /audience/);
});

test("authorize returns a user for a verified human presentation", async () => {
  const broker = fakeBroker({ verify: okVerify });
  const authorize = browseridAuthorize({ audience: AUDIENCE, fetch: broker.fetch });
  const user = await authorize({ presentation: "AC~AS~WR~CC" });
  assert.equal(user.email, "dan@sandmill.org");
  assert.equal(user.id, "dan@sandmill.org");
  assert.equal(user.browserid.issuer, "sandmill.org");
  assert.deepEqual(user.browserid.statusRefs, okVerify.status_refs);
  // The presentation is verified against the pinned audience.
  assert.equal(broker.seen.verify.audience, AUDIENCE);
});

test("authorize returns null on a missing/blank presentation", async () => {
  const authorize = browseridAuthorize({ audience: AUDIENCE, fetch: fakeBroker().fetch });
  assert.equal(await authorize(undefined), null);
  assert.equal(await authorize({}), null);
  assert.equal(await authorize({ presentation: "" }), null);
});

test("authorize fails closed when verification fails", async () => {
  const broker = fakeBroker({ verify: { status: "failure", reason: "expired" } });
  const authorize = browseridAuthorize({ audience: AUDIENCE, fetch: broker.fetch });
  assert.equal(await authorize({ presentation: "AC~AS~WR~CC" }), null);
});

test("authorize fails closed when the verifier is unreachable", async () => {
  const broker = fakeBroker({ verify: "throw" });
  const authorize = browseridAuthorize({ audience: AUDIENCE, fetch: broker.fetch });
  assert.equal(await authorize({ presentation: "AC~AS~WR~CC" }), null);
});

test("an agent presentation is rejected by default, accepted with allowAgent", async () => {
  const agentVerify = { ...okVerify, subject: "agent", grantee: "dan+bot@sandmill.org", scopes: ["post"] };
  const reject = browseridAuthorize({ audience: AUDIENCE, fetch: fakeBroker({ verify: agentVerify }).fetch });
  assert.equal(await reject({ presentation: "AC~AS~WR~CC" }), null);
  const accept = browseridAuthorize({ audience: AUDIENCE, allowAgent: true, fetch: fakeBroker({ verify: agentVerify }).fetch });
  const user = await accept({ presentation: "AC~AS~WR~CC" });
  assert.equal(user.browserid.subject, "agent");
  assert.equal(user.browserid.grantee, "dan+bot@sandmill.org");
});

test("browseridSessionValid reflects the status check", async () => {
  const refs = okVerify.status_refs;
  const valid = await browseridSessionValid(refs, { fetch: fakeBroker({ status: { ok: true, revoked: false } }).fetch });
  assert.deepEqual(valid, { ok: true, revoked: false, reason: undefined });

  const revoked = await browseridSessionValid(refs, { fetch: fakeBroker({ status: { ok: true, revoked: true } }).fetch });
  assert.equal(revoked.ok, false);
  assert.equal(revoked.revoked, true);

  const unreachable = await browseridSessionValid(refs, { fetch: fakeBroker({ status: "throw" }).fetch });
  assert.equal(unreachable.ok, false); // fail-closed
});
