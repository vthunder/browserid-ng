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

test("okay → ok:true with email/issuer/grantee/scopes", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "a@b.com", issuer: "b.com", scopes: ["login"] }),
  });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, true);
  assert.equal(r.email, "a@b.com");
  assert.equal(r.issuer, "b.com");
  assert.equal(r.grantee, "a@b.com"); // defaults to email (as-you)
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

test("delegated presentation verifies; grantee is the actor of record", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "a@b.com", grantee: "a+bot@b.com",
      issuer: "b.com", scopes: ["read", "write"] }),
  });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, true);
  assert.equal(r.email, "a@b.com");
  assert.equal(r.grantee, "a+bot@b.com"); // RP delegation policy: grantee !== email
  assert.deepEqual(r.scopes, ["read", "write"]);
});

test("removed allowAgent option throws loudly instead of being ignored", async () => {
  const v = createVerifier({
    fetch: stubFetch({ status: "okay", email: "a@b.com", issuer: "b.com" }),
  });
  for (const val of [true, false]) {
    await assert.rejects(
      v.verify(P, "https://app.example", { allowAgent: val }),
      /allowAgent was removed/
    );
  }
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

// --- checkStatus (revocation re-checks, bean 6u70) -------------------------

const REFS = [{ uri: "https://idp.example/.well-known/browserid-status", idx: 7 }];

test("verify surfaces status_refs as statusRefs", async () => {
  const v = createVerifier({
    fetch: stubFetch({
      status: "okay", email: "a@b.com", issuer: "b.com",
      scopes: ["login"], status_refs: REFS,
    }),
  });
  const r = await v.verify(P, "https://app.example");
  assert.equal(r.ok, true);
  assert.deepEqual(r.statusRefs, REFS);
});

test("checkStatus: valid refs → ok:true revoked:false", async () => {
  const v = createVerifier({ fetch: stubFetch({ ok: true, revoked: false, results: [] }) });
  const r = await v.checkStatus(REFS);
  assert.deepEqual(r, { ok: true, revoked: false });
});

test("checkStatus: revoked ref surfaces revoked:true", async () => {
  const v = createVerifier({ fetch: stubFetch({ ok: true, revoked: true, results: [] }) });
  const r = await v.checkStatus(REFS);
  assert.deepEqual(r, { ok: true, revoked: true });
});

test("checkStatus: unavailable refs → fail closed (ok:false)", async () => {
  const v = createVerifier({ fetch: stubFetch({ ok: false, revoked: false, results: [] }) });
  const r = await v.checkStatus(REFS);
  assert.equal(r.ok, false);
});

test("checkStatus: HTTP error → fail closed", async () => {
  const v = createVerifier({ fetch: stubFetch({}, { httpStatus: 502 }) });
  const r = await v.checkStatus(REFS);
  assert.equal(r.ok, false);
  assert.match(r.reason, /HTTP 502/);
});

test("checkStatus: no refs → nothing to check, not revoked", async () => {
  const v = createVerifier({ fetch: stubFetch(null, { throwErr: new Error("must not fetch") }) });
  const r = await v.checkStatus([]);
  assert.deepEqual(r, { ok: true, revoked: false });
});

test("checkStatus posts to /status/check on the verifier origin", async () => {
  let calledUrl = null;
  const v = createVerifier({
    verifierUrl: "https://broker.example/verify-access",
    fetch: async (url) => {
      calledUrl = url;
      return { ok: true, status: 200, json: async () => ({ ok: true, revoked: false, results: [] }) };
    },
  });
  await v.checkStatus(REFS);
  assert.equal(calledUrl, "https://broker.example/status/check");
});
