import { test } from "node:test";
import assert from "node:assert/strict";
import { createVerifier, verifyAssertion } from "./index.mjs";

// A fetch stub that returns a canned /verify JSON body.
function stubFetch(jsonBody, { httpStatus = 200, throwErr = null } = {}) {
  return async () => {
    if (throwErr) throw throwErr;
    return {
      ok: httpStatus >= 200 && httpStatus < 300,
      status: httpStatus,
      json: async () => jsonBody,
    };
  };
}

test("okay → ok:true with email/issuer/expires", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "a@b.com", issuer: "b.com", expires: 123 }),
  });
  const r = await v.verify("cert~assertion", "https://app.example");
  assert.equal(r.ok, true);
  assert.equal(r.email, "a@b.com");
  assert.equal(r.issuer, "b.com");
  assert.equal(r.expires, 123);
  assert.equal(r.agent, null);
});

test("failure status → ok:false with reason (fail closed)", async () => {
  const v = createVerifier({ fetch: stubFetch({ status: "failure", reason: "Assertion expired" }) });
  const r = await v.verify("cert~assertion", "https://app.example");
  assert.equal(r.ok, false);
  assert.equal(r.reason, "Assertion expired");
});

test("okay but missing email → fail closed", async () => {
  const v = createVerifier({ fetch: stubFetch({ status: "okay" }) });
  const r = await v.verify("x~y", "https://app.example");
  assert.equal(r.ok, false);
});

test("HTTP 500 → fail closed", async () => {
  const v = createVerifier({ fetch: stubFetch({}, { httpStatus: 500 }) });
  const r = await v.verify("x~y", "https://app.example");
  assert.equal(r.ok, false);
  assert.match(r.reason, /HTTP 500/);
});

test("network error → fail closed", async () => {
  const v = createVerifier({ fetch: stubFetch(null, { throwErr: new Error("ECONNREFUSED") }) });
  const r = await v.verify("x~y", "https://app.example");
  assert.equal(r.ok, false);
  assert.match(r.reason, /ECONNREFUSED/);
});

test("agent presentation rejected by default", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "agent@b.com", issuer: "b.com",
      agent: { parent: "human@b.com", scopes: ["read"] } }),
  });
  const r = await v.verify("x~y", "https://app.example");
  assert.equal(r.ok, false);
  assert.match(r.reason, /agent presentation/);
});

test("agent presentation accepted with allowAgent → surfaces attribution", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "agent@b.com", issuer: "b.com",
      agent: { parent: "human@b.com", scopes: ["read", "write"] } }),
  });
  const r = await v.verify("x~y", "https://app.example", { allowAgent: true });
  assert.equal(r.ok, true);
  assert.deepEqual(r.agent, { parent: "human@b.com", scopes: ["read", "write"] });
});

test("empty inputs fail closed without a request", async () => {
  let called = false;
  const v = createVerifier({ fetch: async () => { called = true; return { ok: true, json: async () => ({}) }; } });
  assert.equal((await v.verify("", "https://a")).ok, false);
  assert.equal((await v.verify("x", "")).ok, false);
  assert.equal(called, false);
});

test("accepted_fallbacks passed through to the request body", async () => {
  let sentBody = null;
  const v = createVerifier({
    acceptedFallbacks: ["fallback.example"],
    fetch: async (_url, init) => {
      sentBody = JSON.parse(init.body);
      return { ok: true, status: 200, json: async () => ({ status: "okay", email: "a@b.com" }) };
    },
  });
  await v.verify("x~y", "https://app.example");
  assert.deepEqual(sentBody.accepted_fallbacks, ["fallback.example"]);
});

test("verifyAssertion one-shot wrapper works", async () => {
  const r = await verifyAssertion("x~y", "https://app.example", {
    fetch: stubFetch({ status: "okay", email: "a@b.com" }),
  });
  assert.equal(r.ok, true);
});
