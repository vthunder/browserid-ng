import { test } from "node:test";
import assert from "node:assert/strict";
import { createVerifier, verifyPresentation } from "./index.mjs";

// A fetch stub that returns a canned /verify-access JSON body.
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

const P = "ac~a~w~cc"; // shape of an access presentation

test("okay → ok:true with email/issuer/subject/scopes", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "a@b.com", issuer: "b.com", subject: "user", scopes: ["login"] }),
  });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, true);
  assert.equal(r.email, "a@b.com");
  assert.equal(r.issuer, "b.com");
  assert.equal(r.subject, "user");
  assert.deepEqual(r.scopes, ["login"]);
});

test("failure status → ok:false with reason (fail closed)", async () => {
  const v = createVerifier({ fetch: stubFetch({ status: "failure", reason: "assertion expired" }) });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, false);
  assert.equal(r.reason, "assertion expired");
});

test("okay but missing email → fail closed", async () => {
  const v = createVerifier({ fetch: stubFetch({ status: "okay" }) });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, false);
});

test("HTTP 500 → fail closed", async () => {
  const v = createVerifier({ fetch: stubFetch({}, { httpStatus: 500 }) });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, false);
  assert.match(r.reason, /HTTP 500/);
});

test("network error → fail closed", async () => {
  const v = createVerifier({ fetch: stubFetch(null, { throwErr: new Error("ECONNREFUSED") }) });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, false);
  assert.match(r.reason, /ECONNREFUSED/);
});

test("agent presentation rejected by default", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "agent@b.com", issuer: "b.com",
      subject: "agent", scopes: ["read"] }),
  });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, false);
  assert.match(r.reason, /agent/);
});

test("agent presentation accepted with allowAgent → surfaces subject+scopes", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "agent@b.com", issuer: "b.com",
      subject: "agent", scopes: ["read", "write"] }),
  });
  const r = await v.verify(P, "https://app.example", { allowAgent: true });
  assert.equal(r.ok, true);
  assert.equal(r.subject, "agent");
  assert.deepEqual(r.scopes, ["read", "write"]);
});

test("empty inputs fail closed without a request", async () => {
  let called = false;
  const v = createVerifier({ fetch: async () => { called = true; return { ok: true, json: async () => ({}) }; } });
  assert.equal((await v.verify("", "https://a")).ok, false);
  assert.equal((await v.verify(P, "")).ok, false);
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
  await v.verify(P, "https://app.example");
  assert.deepEqual(sentBody.accepted_fallbacks, ["fallback.example"]);
  assert.equal(sentBody.presentation, P);
});

test("verifyPresentation one-shot wrapper works", async () => {
  const r = await verifyPresentation(P, "https://app.example", {
    fetch: stubFetch({ status: "okay", email: "a@b.com" }),
  });
  assert.equal(r.ok, true);
});
